package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/danielewood/spffy/pkg/cache"
	"github.com/danielewood/spffy/pkg/config"
	"github.com/danielewood/spffy/pkg/logging"
	"github.com/danielewood/spffy/pkg/resolver"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// Handler holds dependencies for processing DNS queries.
type Handler struct {
	Logger            logging.LoggerInterface // Use interface
	Cache             cache.CacheInterface    // Use interface
	ResolverPool      *resolver.ResolverPool
	Config            *config.Flags
	SPFSemaphore      chan struct{}
	QueryTotal        *prometheus.CounterVec
	LookupDuration    prometheus.Histogram
	DNSLookups        prometheus.Histogram
	QueryResponseTime prometheus.Histogram
	RequestsPerSecond prometheus.Counter
	ConcurrentQueries prometheus.Gauge
}

// NewHandler creates a new DNS Handler with necessary dependencies.
func NewHandler(
	logger logging.LoggerInterface,
	cache cache.CacheInterface,
	resolverPool *resolver.ResolverPool,
	cfg *config.Flags,
	spfSemaphore chan struct{},
	queryTotal *prometheus.CounterVec,
	lookupDuration prometheus.Histogram,
	dnsLookups prometheus.Histogram,
	queryResponseTime prometheus.Histogram,
	requestsPerSecond prometheus.Counter,
	concurrentQueries prometheus.Gauge,
) *Handler {
	return &Handler{
		Logger:            logger,
		Cache:             cache,
		ResolverPool:      resolverPool,
		Config:            cfg,
		SPFSemaphore:      spfSemaphore,
		QueryTotal:        queryTotal,
		LookupDuration:    lookupDuration,
		DNSLookups:        dnsLookups,
		QueryResponseTime: queryResponseTime,
		RequestsPerSecond: requestsPerSecond,
		ConcurrentQueries: concurrentQueries,
	}
}

func extractSPFComponents(queryName string, baseDomainFromConfig string) (ip, version, domainToQuery string, valid bool) {
	queryName = strings.TrimSuffix(queryName, ".")
	baseDomainSuffix := "." + baseDomainFromConfig
	if !strings.HasSuffix(queryName, baseDomainSuffix) {
		return "", "", "", false
	}

	withoutSuffix := strings.TrimSuffix(queryName, baseDomainSuffix)
	parts := strings.Split(withoutSuffix, ".")

	if len(parts) < 1 {
		return "", "", "", false
	}

	var ipParts []string
	var versionType string
	var domainStart int

	foundMarker := false
	for i, part := range parts {
		if part == "in-addr" {
			versionType = "in-addr"
			ipParts = parts[:i]
			domainStart = i + 1
			foundMarker = true
			break
		} else if part == "ip6" {
			versionType = "ip6"
			ipParts = parts[:i]
			domainStart = i + 1
			foundMarker = true
			break
		}
	}

	if !foundMarker {
		return "", "", "", false
	}

	if domainStart > len(parts) {
		return "", versionType, "", false
	} else if domainStart == len(parts) {
		domainToQuery = baseDomainFromConfig
	} else {
		domainToQuery = strings.Join(parts[domainStart:], ".")
	}

	var reconstructedIP string
	if versionType == "in-addr" {
		if len(ipParts) != 4 {
			return "", versionType, domainToQuery, false
		}
		reconstructedIP = strings.Join(ipParts, ".")
		if net.ParseIP(reconstructedIP) == nil {
			return "", versionType, domainToQuery, false
		}
	} else if versionType == "ip6" {
		if len(ipParts) != 32 {
			return "", versionType, domainToQuery, false
		}
		nibbles := make([]string, len(ipParts))
		for i := 0; i < len(ipParts); i++ {
			nibbles[i] = ipParts[len(ipParts)-1-i]
		}

		var hexGroups []string
		for i := 0; i < 32; i += 4 {
			hexGroups = append(hexGroups, strings.Join(nibbles[i:i+4], ""))
		}
		reconstructedIP = strings.Join(hexGroups, ":")
		parsedIP := net.ParseIP(reconstructedIP)
		if parsedIP == nil {
			return "", versionType, domainToQuery, false
		}
		reconstructedIP = parsedIP.String()
	} else {
		return "", versionType, domainToQuery, false // Should not be reached if foundMarker is true
	}

	return reconstructedIP, versionType, domainToQuery, true
}

func (h *Handler) logQueryResponse(r *dns.Msg, m *dns.Msg, clientAddr string, extraData map[string]interface{}) {
	logEntry := map[string]interface{}{
		"client_addr": clientAddr,
		"query": map[string]interface{}{
			"name": strings.ToLower(r.Question[0].Name),
			"type": dns.TypeToString[r.Question[0].Qtype],
		},
		"response": map[string]interface{}{
			"status": dns.RcodeToString[m.Rcode],
		},
	}

	if len(m.Answer) > 0 {
		var answers []string
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.TXT:
				answers = append(answers, strings.Join(v.Txt, ""))
			default:
				answers = append(answers, rr.String())
			}
		}
		logEntry["response"].(map[string]interface{})["answer"] = answers
	}

	if h.Logger.GetLevel() >= logging.LevelDebug && len(extraData) > 0 {
		logEntry["debug"] = extraData
	}

	if h.Logger.GetLevel() >= logging.LevelTrace {
		h.Logger.Trace(logEntry)
	} else if h.Logger.GetLevel() >= logging.LevelDebug {
		h.Logger.Debug(logEntry)
	} else {
		h.Logger.Info(logEntry)
	}
}

func (h *Handler) ProcessDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	if h.ConcurrentQueries != nil {
		h.ConcurrentQueries.Inc()
		defer h.ConcurrentQueries.Dec()
	}
	if h.RequestsPerSecond != nil {
		h.RequestsPerSecond.Inc()
	}
	if h.QueryResponseTime != nil {
		defer func() {
			h.QueryResponseTime.Observe(time.Since(startTime).Seconds())
		}()
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *h.Config.Compress

	clientAddr := w.RemoteAddr().String()
	queryName := r.Question[0].Name
	extraData := make(map[string]interface{})

	if h.Logger.GetLevel() >= logging.LevelDebug {
		extraData["raw_query"] = queryName
	}

	if r.Question[0].Qtype != dns.TypeTXT {
		extraData["reject"] = "non_txt"
		extraData["type"] = dns.TypeToString[r.Question[0].Qtype]
		m.SetRcode(r, dns.RcodeNameError)
		if h.QueryTotal != nil {
			h.QueryTotal.WithLabelValues("non_txt", "miss").Inc()
		}
		h.logQueryResponse(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	queryName = strings.ToLower(queryName)
	queryNameTrimmed := strings.TrimSuffix(queryName, ".")
	baseDomainSuffixLocal := "." + *h.Config.BaseDomain

	if !strings.HasSuffix(queryNameTrimmed, baseDomainSuffixLocal) {
		extraData["reject"] = "wrong_domain"
		extraData["expected"] = baseDomainSuffixLocal
		m.SetRcode(r, dns.RcodeNameError)
		if h.QueryTotal != nil {
			h.QueryTotal.WithLabelValues("wrong_domain", "miss").Inc()
		}
		h.logQueryResponse(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	ip, _, domainToQueryStr, valid := extractSPFComponents(queryName, *h.Config.BaseDomain) // version ignored

	if valid {
		extraData["ip"] = ip
		extraData["domain"] = domainToQueryStr
		extraData["spf_domain"] = fmt.Sprintf("_spffy.%s", domainToQueryStr)
		cacheKey := fmt.Sprintf("%s|%s", ip, domainToQueryStr)

		if cachedEntry, found := h.Cache.Get(cacheKey); found {
			extraData["cache"] = "hit"
			if h.QueryTotal != nil {
				h.QueryTotal.WithLabelValues("success", "hit").Inc()
			}
			if cachedEntry.Found {
				extraData["result"] = "pass"
				t := &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 15}, Txt: []string{cachedEntry.SPFRecord}}
				m.Answer = append(m.Answer, t)
			} else {
				extraData["result"] = "fail"
				m.SetRcode(r, dns.RcodeNameError)
			}
		} else {
			extraData["cache"] = "miss"
			select {
			case h.SPFSemaphore <- struct{}{}:
				defer func() { <-h.SPFSemaphore }()
			case <-time.After(1 * time.Second):
				extraData["error"] = "too_many_concurrent_lookups"
				extraData["result"] = "temperror"
				m.SetRcode(r, dns.RcodeServerFailure)
				if h.QueryTotal != nil {
					h.QueryTotal.WithLabelValues("temperror", "miss").Inc()
				}
				h.logQueryResponse(r, m, clientAddr, extraData)
				w.WriteMsg(m)
				return
			}

			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				extraData["error"] = "invalid_ip"
				extraData["result"] = "error"
				m.SetRcode(r, dns.RcodeServerFailure)
				if h.QueryTotal != nil {
					h.QueryTotal.WithLabelValues("invalid_ip", "miss").Inc()
				}
				// Log here as well, before returning
				h.logQueryResponse(r, m, clientAddr, extraData)
				w.WriteMsg(m)
				return
			}
			// SPF lookup logic
			spfDomainToCheck := fmt.Sprintf("_spffy.%s", domainToQueryStr)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			baseRes := h.ResolverPool.GetResolver()
			lookupCount := 0
			trackingRes := resolver.NewTrackingResolver(baseRes, &lookupCount)

			opts := []spf.Option{
				spf.WithResolver(trackingRes),
				spf.WithContext(ctx),
				spf.OverrideVoidLookupLimit(*h.Config.VoidLookupLimit),
			}

			lookupStart := time.Now()
			result, spfErr := spf.CheckHostWithSender(ipAddr, spfDomainToCheck, fmt.Sprintf("test@%s", spfDomainToCheck), opts...)
			spfDuration := time.Since(lookupStart)
			if h.LookupDuration != nil {
				h.LookupDuration.Observe(spfDuration.Seconds())
			}
			if h.DNSLookups != nil {
				h.DNSLookups.Observe(float64(lookupCount))
			}

			extraData["duration_ms"] = spfDuration.Milliseconds()
			extraData["dns_lookups"] = lookupCount
			if spfErr != nil {
				extraData["error"] = spfErr.Error()
			}

			originalFailType := "~all"
			spfMsgClient := new(dns.Client)
			spfMsgClient.Timeout = 3 * time.Second
			msgForOriginalSPF := new(dns.Msg)
			msgForOriginalSPF.SetQuestion(dns.Fqdn(spfDomainToCheck), dns.TypeTXT)

			var exchangeResolverAddr string
			if *h.Config.DNSServers != "" {
				servers := strings.Split(*h.Config.DNSServers, ",")
				if len(servers) > 0 && strings.TrimSpace(servers[0]) != "" {
					exchangeResolverAddr = strings.TrimSpace(servers[0])
					if !strings.Contains(exchangeResolverAddr, ":") {
						exchangeResolverAddr = net.JoinHostPort(exchangeResolverAddr, "53")
					}
				}
			}
			if exchangeResolverAddr == "" {
				exchangeResolverAddr = "8.8.8.8:53"
			}

			if respSPF, _, errEx := spfMsgClient.Exchange(msgForOriginalSPF, exchangeResolverAddr); errEx == nil && respSPF.Rcode == dns.RcodeSuccess {
				for _, rrAnswer := range respSPF.Answer {
					if txtRR, ok := rrAnswer.(*dns.TXT); ok {
						s := strings.Join(txtRR.Txt, "")
						if strings.HasPrefix(strings.ToLower(s), "v=spf1") {
							if strings.Contains(s, "-all") {
								originalFailType = "-all"
							}
							break
						}
					}
				}
			}
			extraData["fail_type"] = originalFailType

			var spfRecordText string
			var resultFoundForCache bool

			switch result {
			case spf.Pass:
				recordFormat := "v=spf1 ip4:%s %s"
				if ipAddr.To4() == nil {
					recordFormat = "v=spf1 ip6:%s %s"
				}
				spfRecordText = fmt.Sprintf(recordFormat, ip, originalFailType)
				extraData["result"] = "pass"
				resultFoundForCache = true
			case spf.Fail:
				spfRecordText = fmt.Sprintf("v=spf1 %s", originalFailType)
				extraData["result"] = "fail"
				resultFoundForCache = false
			case spf.SoftFail:
				spfRecordText = "v=spf1 ~all"
				extraData["result"] = "softfail"
				resultFoundForCache = false
			case spf.Neutral:
				spfRecordText = "v=spf1 ?all"
				extraData["result"] = "neutral"
				resultFoundForCache = false
			case spf.None:
				spfRecordText = fmt.Sprintf("v=spf1 %s", originalFailType)
				extraData["result"] = "none"
				resultFoundForCache = false
			case spf.TempError:
				extraData["result"] = "temperror"
				m.SetRcode(r, dns.RcodeServerFailure)
				if h.QueryTotal != nil {
					h.QueryTotal.WithLabelValues("temperror", "miss").Inc()
				}
				h.logQueryResponse(r, m, clientAddr, extraData)
				w.WriteMsg(m)
				return
			case spf.PermError:
				spfRecordText = fmt.Sprintf("v=spf1 %s", originalFailType)
				extraData["result"] = "permerror"
				resultFoundForCache = false
			default:
				spfRecordText = fmt.Sprintf("v=spf1 %s", originalFailType)
				extraData["result"] = "unknown"
				resultFoundForCache = false
			}
			h.Cache.Set(cacheKey, spfRecordText, resultFoundForCache)

			if resultFoundForCache {
				t := &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{spfRecordText}}
				m.Answer = append(m.Answer, t)
				if h.QueryTotal != nil {
					h.QueryTotal.WithLabelValues("success", "miss").Inc()
				}
			} else {
				m.SetRcode(r, dns.RcodeNameError)
				if h.QueryTotal != nil {
					label := "fail"
					if resStr, ok := extraData["result"].(string); ok {
						label = resStr
					}
					h.QueryTotal.WithLabelValues(label, "miss").Inc()
				}
			}
		}
	} else {
		extraData["reject"] = "invalid_format"
		m.SetRcode(r, dns.RcodeNameError)
		if h.QueryTotal != nil {
			h.QueryTotal.WithLabelValues("invalid_format", "miss").Inc()
		}
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
		} else {
			extraData["tsig_error"] = w.TsigStatus().Error()
		}
	}

	h.logQueryResponse(r, m, clientAddr, extraData)
	w.WriteMsg(m)
}

func (h *Handler) StartServerInstances(tsigName, tsigSecret string, soReusePort int) {
	handlerFunc := h.ProcessDNSQuery
	start := func(netType string, name, secret string, reuseport bool) {
		var tsigSecrets map[string]string
		if name != "" && secret != "" {
			tsigSecrets = map[string]string{name: secret}
		}
		server := &dns.Server{
			Addr:       ":8053",
			Net:        netType,
			TsigSecret: tsigSecrets,
			ReusePort:  reuseport,
			Handler:    dns.HandlerFunc(handlerFunc),
		}

		tcpAddr := ":8053"
		if h.Config != nil && h.Config.TCPAddr != nil && *h.Config.TCPAddr != "" {
			tcpAddr = *h.Config.TCPAddr
		} else if netType == "tcp" {
			tcpAddr = "[::]:8053"
		}
		udpAddr := ":8053"
		if h.Config != nil && h.Config.UDPAddr != nil && *h.Config.UDPAddr != "" {
			udpAddr = *h.Config.UDPAddr
		}

		if netType == "tcp" {
			server.Addr = tcpAddr
		} else if netType == "udp" {
			server.Addr = udpAddr
		}

		if err := server.ListenAndServe(); err != nil {
			h.Logger.Info(map[string]interface{}{
				"error":   fmt.Sprintf("Failed to setup the %s server on %s: %s", netType, server.Addr, err.Error()),
				"address": server.Addr,
			})
		}
	}
	if soReusePort > 0 {
		for i := 0; i < soReusePort; i++ {
			go start("tcp", tsigName, tsigSecret, true)
			go start("udp", tsigName, tsigSecret, true)
		}
	} else {
		go start("tcp", tsigName, tsigSecret, false)
		go start("udp", tsigName, tsigSecret, false)
	}
}
