package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	cpuprofile      = flag.String("cpuprofile", "", "write cpu profile to file")
	debugEnabled    = flag.Bool("debug", false, "enable debug information in JSON logging")
	logFile         = flag.String("logfile", "", "write JSON logs to file (default: stdout)")
	compress        = flag.Bool("compress", false, "compress replies")
	tsig            = flag.String("tsig", "", "use SHA256 hmac tsig: keyname:base64")
	soreuseport     = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu             = flag.Int("cpu", 0, "number of cpu to use")
	baseDomain      = flag.String("basedomain", "_spf-stage.spffy.dev", "base domain for SPF macro queries")
	cacheLimit      = flag.Int64("cachelimit", 1024*1024*1024, "cache memory limit in bytes (default: 1GB)")
	dnsServers      = flag.String("dnsservers", "", "comma-separated list of DNS servers to use for lookups (default: system resolver)")
	voidLookupLimit = flag.Uint("voidlookuplimit", 20, "maximum number of void DNS lookups allowed during SPF evaluation")
	cacheTTL        = flag.Duration("cachettl", 15*time.Second, "cache TTL for SPF results")
	maxConcurrent   = flag.Int("maxconcurrent", 1000, "maximum concurrent SPF lookups")
	metricsPort     = flag.Int("metricsport", 8080, "port for metrics server")
	logger          *log.Logger
)

type resolverPool struct {
	resolvers []*net.Resolver
	counter   uint64
}

func (rp *resolverPool) getResolver() *net.Resolver {
	if len(rp.resolvers) == 0 {
		return net.DefaultResolver
	}
	index := atomic.AddUint64(&rp.counter, 1) % uint64(len(rp.resolvers))
	return rp.resolvers[index]
}

var resolvers *resolverPool

type cacheEntry struct {
	spfRecord string
	expiry    time.Time
	found     bool
	size      int64
}

type dnsCache struct {
	mu        sync.RWMutex
	cache     map[string]*cacheEntry
	totalSize int64
	limit     int64
}

var cache = &dnsCache{
	cache: make(map[string]*cacheEntry),
	limit: 1024 * 1024 * 1024,
}

var spfSemaphore chan struct{}

// Prometheus metrics
var (
	cacheEntries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_entries",
		Help: "Number of entries in the SPF cache",
	})
	cacheSizeBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_size_bytes",
		Help: "Total size of cache entries in bytes",
	})
	cacheLimitBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_limit_bytes",
		Help: "Cache size limit in bytes",
	})
	queryTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "spffy_queries_total",
		Help: "Total number of DNS queries processed",
	}, []string{"result", "cache"})
	lookupDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "spffy_spf_lookup_duration_seconds",
		Help:    "SPF lookup duration in seconds",
		Buckets: prometheus.DefBuckets,
	})
	dnsLookups = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "spffy_dns_lookups_per_query",
		Help:    "Number of DNS lookups per SPF query",
		Buckets: []float64{0, 1, 2, 3, 4, 5, 10, 20, 30, 40, 50},
	})
	queryResponseTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "spffy_query_response_time_seconds",
		Help:    "DNS query response time in seconds",
		Buckets: prometheus.DefBuckets,
	})
	requestsPerSecond = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "spffy_requests_total",
		Help: "Total number of DNS requests received",
	})
	concurrentQueries = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_concurrent_queries",
		Help: "Number of concurrent DNS queries being processed",
	})
)

type trackingResolver struct {
	resolver *net.Resolver
	count    *int
}

func (tr *trackingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	*tr.count++
	return tr.resolver.LookupTXT(ctx, name)
}

func (tr *trackingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	*tr.count++
	return tr.resolver.LookupMX(ctx, name)
}

func (tr *trackingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	*tr.count++
	return tr.resolver.LookupAddr(ctx, addr)
}

func (tr *trackingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	*tr.count++
	return tr.resolver.LookupIPAddr(ctx, host)
}

func envString(envKey, defaultValue string) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return defaultValue
}

func envBool(envKey string, defaultValue bool) bool {
	if value := os.Getenv(envKey); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func envInt(envKey string, defaultValue int) int {
	if value := os.Getenv(envKey); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func envInt64(envKey string, defaultValue int64) int64 {
	if value := os.Getenv(envKey); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

func envUint(envKey string, defaultValue uint) uint {
	if value := os.Getenv(envKey); value != "" {
		if i, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint(i)
		}
	}
	return defaultValue
}

func envDuration(envKey string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(envKey); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func loadEnvConfig() {
	if !isFlagSet("cpuprofile") {
		*cpuprofile = envString("SPFFY_CPUPROFILE", *cpuprofile)
	}
	if !isFlagSet("debug") {
		*debugEnabled = envBool("SPFFY_DEBUG", *debugEnabled)
	}
	if !isFlagSet("logfile") {
		*logFile = envString("SPFFY_LOGFILE", *logFile)
	}
	if !isFlagSet("compress") {
		*compress = envBool("SPFFY_COMPRESS", *compress)
	}
	if !isFlagSet("tsig") {
		*tsig = envString("SPFFY_TSIG", *tsig)
	}
	if !isFlagSet("soreuseport") {
		*soreuseport = envInt("SPFFY_SOREUSEPORT", *soreuseport)
	}
	if !isFlagSet("cpu") {
		*cpu = envInt("SPFFY_CPU", *cpu)
	}
	if !isFlagSet("basedomain") {
		*baseDomain = envString("SPFFY_BASEDOMAIN", *baseDomain)
	}
	if !isFlagSet("cachelimit") {
		*cacheLimit = envInt64("SPFFY_CACHELIMIT", *cacheLimit)
	}
	if !isFlagSet("dnsservers") {
		*dnsServers = envString("SPFFY_DNSSERVERS", *dnsServers)
	}
	if !isFlagSet("voidlookuplimit") {
		*voidLookupLimit = envUint("SPFFY_VOIDLOOKUPLIMIT", *voidLookupLimit)
	}
	if !isFlagSet("cachettl") {
		*cacheTTL = envDuration("SPFFY_CACHETTL", *cacheTTL)
	}
	if !isFlagSet("maxconcurrent") {
		*maxConcurrent = envInt("SPFFY_MAXCONCURRENT", *maxConcurrent)
	}
	if !isFlagSet("metricsport") {
		*metricsPort = envInt("SPFFY_METRICSPORT", *metricsPort)
	}
}

func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func setupResolverPool() {
	resolvers = &resolverPool{}

	if *dnsServers == "" {
		resolvers.resolvers = []*net.Resolver{net.DefaultResolver}
		return
	}

	servers := strings.Split(*dnsServers, ",")
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}

		if !strings.Contains(server, ":") {
			server = server + ":53"
		}

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, server)
			},
		}

		resolvers.resolvers = append(resolvers.resolvers, resolver)
	}

	if len(resolvers.resolvers) == 0 {
		resolvers.resolvers = []*net.Resolver{net.DefaultResolver}
	}
}

func calcEntrySize(key string, spfRecord string) int64 {
	size := int64(len(key))
	size += int64(len(spfRecord))
	size += 24
	size += 1
	size += 8
	return size
}

func (c *dnsCache) evictOldest() {
	if c.totalSize <= c.limit {
		return
	}

	type entryWithKey struct {
		key    string
		entry  *cacheEntry
		expiry time.Time
	}

	var entries []entryWithKey
	for key, entry := range c.cache {
		entries = append(entries, entryWithKey{
			key:    key,
			entry:  entry,
			expiry: entry.expiry,
		})
	}

	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].expiry.After(entries[j].expiry) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	for _, entry := range entries {
		if c.totalSize <= c.limit {
			break
		}
		c.totalSize -= entry.entry.size
		delete(c.cache, entry.key)
	}
}

func (c *dnsCache) get(key string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiry) {
		return nil, false
	}

	return entry, true
}

func (c *dnsCache) set(key string, spfRecord string, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := calcEntrySize(key, spfRecord)

	if size > c.limit {
		return
	}

	if existing, exists := c.cache[key]; exists {
		c.totalSize -= existing.size
	}

	entry := &cacheEntry{
		spfRecord: spfRecord,
		expiry:    time.Now().Add(*cacheTTL),
		found:     found,
		size:      size,
	}

	c.cache[key] = entry
	c.totalSize += size

	c.evictOldest()

	// Update Prometheus metrics
	cacheEntries.Set(float64(len(c.cache)))
	cacheSizeBytes.Set(float64(c.totalSize))
	cacheLimitBytes.Set(float64(c.limit))
}

func (c *dnsCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiry) {
			c.totalSize -= entry.size
			delete(c.cache, key)
		}
	}

	// Update Prometheus metrics
	cacheEntries.Set(float64(len(c.cache)))
	cacheSizeBytes.Set(float64(c.totalSize))
	cacheLimitBytes.Set(float64(c.limit))
}

func (c *dnsCache) getStats() (entries int, totalSize int64, limit int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache), c.totalSize, c.limit
}

func runCacheCleanup() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cache.cleanup()
			}
		}
	}()
}

func configureLogger() {
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", *logFile, err)
		}
		logger = log.New(f, "", 0)
	} else {
		logger = log.New(os.Stdout, "", 0)
	}
}

func logQueryResponse(r *dns.Msg, m *dns.Msg, clientAddr string, extraData map[string]interface{}) {
	type queryInfo struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}

	type responseInfo struct {
		Status string   `json:"status"`
		Answer []string `json:"answer,omitempty"`
	}

	type logEntry struct {
		Timestamp  string                 `json:"timestamp"`
		ClientAddr string                 `json:"client_addr"`
		Query      queryInfo              `json:"query"`
		Response   responseInfo           `json:"response"`
		Debug      map[string]interface{} `json:"debug,omitempty"`
	}

	query := queryInfo{
		Name: strings.ToLower(r.Question[0].Name),
		Type: dns.TypeToString[r.Question[0].Qtype],
	}

	response := responseInfo{
		Status: dns.RcodeToString[m.Rcode],
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.TXT:
			response.Answer = append(response.Answer, strings.Join(v.Txt, ""))
		default:
			response.Answer = append(response.Answer, rr.String())
		}
	}

	entry := logEntry{
		Timestamp:  time.Now().Format(time.RFC3339),
		ClientAddr: clientAddr,
		Query:      query,
		Response:   response,
	}

	if *debugEnabled {
		entry.Debug = extraData
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return
	}

	logger.Println(string(jsonData))
}

func extractSPFComponents(queryName string) (ip, version, domain string, valid bool) {
	queryName = strings.TrimSuffix(queryName, ".")
	baseDomainSuffix := "." + *baseDomain
	if !strings.HasSuffix(queryName, baseDomainSuffix) {
		return "", "", "", false
	}

	withoutSuffix := strings.TrimSuffix(queryName, baseDomainSuffix)
	parts := strings.Split(withoutSuffix, ".")

	if len(parts) < 3 {
		return "", "", "", false
	}

	var ipParts []string
	var versionType string
	var domainStart int

	for i, part := range parts {
		if part == "in-addr" {
			versionType = "in-addr"
			ipParts = parts[:i]
			domainStart = i + 1
			break
		} else if part == "ip6" {
			versionType = "ip6"
			ipParts = parts[:i]
			domainStart = i + 1
			break
		}
	}

	if versionType == "" || domainStart >= len(parts) {
		return "", "", "", false
	}

	domain = strings.Join(parts[domainStart:], ".")

	var reconstructedIP string
	if versionType == "in-addr" {
		if len(ipParts) != 4 {
			return "", "", "", false
		}
		reversedParts := make([]string, len(ipParts))
		for i, part := range ipParts {
			reversedParts[len(ipParts)-1-i] = part
		}
		reconstructedIP = strings.Join(reversedParts, ".")

		if net.ParseIP(reconstructedIP) == nil {
			return "", "", "", false
		}
	} else if versionType == "ip6" {
		if len(ipParts) != 32 {
			return "", "", "", false
		}
		var hexGroups []string
		for i := len(ipParts) - 4; i >= 0; i -= 4 {
			group := ipParts[i+3] + ipParts[i+2] + ipParts[i+1] + ipParts[i]
			hexGroups = append(hexGroups, group)
		}
		reconstructedIP = strings.Join(hexGroups, ":")

		parsedIP := net.ParseIP(reconstructedIP)
		if parsedIP == nil {
			return "", "", "", false
		}
		reconstructedIP = parsedIP.String()
	}

	return reconstructedIP, versionType, domain, true
}

func processDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	concurrentQueries.Inc()
	defer concurrentQueries.Dec()
	defer func() {
		queryResponseTime.Observe(time.Since(startTime).Seconds())
	}()

	requestsPerSecond.Inc()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress

	clientAddr := w.RemoteAddr().String()
	queryName := r.Question[0].Name
	extraData := make(map[string]interface{})

	if *debugEnabled {
		extraData["raw_query"] = queryName
	}

	if r.Question[0].Qtype != dns.TypeTXT {
		extraData["reject"] = "non_txt"
		extraData["type"] = dns.TypeToString[r.Question[0].Qtype]
		m.SetRcode(r, dns.RcodeNameError)
		queryTotal.WithLabelValues("non_txt", "miss").Inc()
		logQueryResponse(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	queryName = strings.ToLower(queryName)

	queryNameTrimmed := strings.TrimSuffix(queryName, ".")
	baseDomainSuffix := "." + *baseDomain
	if !strings.HasSuffix(queryNameTrimmed, baseDomainSuffix) {
		extraData["reject"] = "wrong_domain"
		extraData["expected"] = baseDomainSuffix
		m.SetRcode(r, dns.RcodeNameError)
		queryTotal.WithLabelValues("wrong_domain", "miss").Inc()
		logQueryResponse(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	ip, _, domain, valid := extractSPFComponents(queryName)

	if valid {
		extraData["ip"] = ip
		extraData["domain"] = domain
		extraData["spf_domain"] = fmt.Sprintf("_spffy.%s", domain)

		cacheKey := fmt.Sprintf("%s|%s", ip, domain)

		if cachedEntry, found := cache.get(cacheKey); found {
			extraData["cache"] = "hit"
			queryTotal.WithLabelValues("success", "hit").Inc()
			if cachedEntry.found {
				extraData["result"] = "pass"
				t := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    15,
					},
					Txt: []string{cachedEntry.spfRecord},
				}
				m.Answer = append(m.Answer, t)
			} else {
				extraData["result"] = "fail"
				m.SetRcode(r, dns.RcodeNameError)
			}
		} else {
			extraData["cache"] = "miss"

			select {
			case spfSemaphore <- struct{}{}:
				defer func() { <-spfSemaphore }()
			case <-time.After(1 * time.Second):
				extraData["error"] = "too_many_concurrent_lookups"
				extraData["result"] = "temperror"
				m.SetRcode(r, dns.RcodeServerFailure)
				queryTotal.WithLabelValues("temperror", "miss").Inc()
				logQueryResponse(r, m, clientAddr, extraData)
				w.WriteMsg(m)
				return
			}

			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				extraData["error"] = "invalid_ip"
				extraData["result"] = "error"
				m.SetRcode(r, dns.RcodeServerFailure)
				queryTotal.WithLabelValues("invalid_ip", "miss").Inc()
			} else {
				spfDomain := fmt.Sprintf("_spffy.%s", domain)

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				baseResolver := resolvers.getResolver()

				lookupCount := 0
				trackingRes := &trackingResolver{
					resolver: baseResolver,
					count:    &lookupCount,
				}

				opts := []spf.Option{
					spf.WithResolver(trackingRes),
					spf.WithContext(ctx),
					spf.OverrideVoidLookupLimit(*voidLookupLimit),
				}

				lookupStart := time.Now()
				result, spfErr := spf.CheckHostWithSender(ipAddr, spfDomain, fmt.Sprintf("test@%s", spfDomain), opts...)
				spfDuration := time.Since(lookupStart)
				lookupDuration.Observe(spfDuration.Seconds())
				dnsLookups.Observe(float64(lookupCount))

				extraData["duration_ms"] = spfDuration.Milliseconds()
				extraData["dns_lookups"] = lookupCount

				if spfErr != nil {
					extraData["error"] = spfErr.Error()
				}

				var originalFailType string = "~all"

				spfMsg := new(dns.Msg)
				spfMsg.SetQuestion(dns.Fqdn(spfDomain), dns.TypeTXT)
				spfClient := new(dns.Client)
				spfClient.Timeout = 3 * time.Second

				selectedResolver := resolvers.getResolver()
				var resolverAddr string
				if len(resolvers.resolvers) > 0 && selectedResolver != net.DefaultResolver {
					if *dnsServers != "" {
						servers := strings.Split(*dnsServers, ",")
						if len(servers) > 0 {
							resolverAddr = strings.TrimSpace(servers[0])
							if !strings.Contains(resolverAddr, ":") {
								resolverAddr = resolverAddr + ":53"
							}
						}
					}
				}

				if resolverAddr == "" {
					resolverAddr = "8.8.8.8:53"
				}

				if spfResp, _, spfLookupErr := spfClient.Exchange(spfMsg, resolverAddr); spfLookupErr == nil && spfResp.Rcode == dns.RcodeSuccess {
					for _, rr := range spfResp.Answer {
						if txtRR, ok := rr.(*dns.TXT); ok {
							spfRecord := strings.Join(txtRR.Txt, "")
							if strings.HasPrefix(strings.ToLower(spfRecord), "v=spf1") {
								if strings.Contains(spfRecord, "-all") {
									originalFailType = "-all"
								} else {
									originalFailType = "~all"
								}
								extraData["fail_type"] = originalFailType
								break
							}
						}
					}
				}

				var spfRecord string
				var resultFound bool

				switch result {
				case spf.Pass:
					if ipAddr.To4() != nil {
						spfRecord = fmt.Sprintf("v=spf1 ip4:%s %s", ip, originalFailType)
					} else {
						spfRecord = fmt.Sprintf("v=spf1 ip6:%s %s", ip, originalFailType)
					}
					extraData["result"] = "pass"
					resultFound = true
				case spf.Fail:
					spfRecord = fmt.Sprintf("v=spf1 %s", originalFailType)
					extraData["result"] = "fail"
					resultFound = false
				case spf.SoftFail:
					spfRecord = "v=spf1 ~all"
					extraData["result"] = "softfail"
					resultFound = false
				case spf.Neutral:
					spfRecord = "v=spf1 ?all"
					extraData["result"] = "neutral"
					resultFound = false
				case spf.None:
					spfRecord = fmt.Sprintf("v=spf1 %s", originalFailType)
					extraData["result"] = "none"
					resultFound = false
				case spf.TempError:
					extraData["result"] = "temperror"
					m.SetRcode(r, dns.RcodeServerFailure)
					queryTotal.WithLabelValues("temperror", "miss").Inc()
					logQueryResponse(r, m, clientAddr, extraData)
					w.WriteMsg(m)
					return
				case spf.PermError:
					spfRecord = fmt.Sprintf("v=spf1 %s", originalFailType)
					extraData["result"] = "permerror"
					resultFound = false
				default:
					spfRecord = fmt.Sprintf("v=spf1 %s", originalFailType)
					extraData["result"] = "unknown"
					resultFound = false
				}

				cache.set(cacheKey, spfRecord, resultFound)

				if resultFound {
					t := &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   r.Question[0].Name,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Txt: []string{spfRecord},
					}
					m.Answer = append(m.Answer, t)
					queryTotal.WithLabelValues("success", "miss").Inc()
				} else {
					m.SetRcode(r, dns.RcodeNameError)
					queryTotal.WithLabelValues(extraData["result"].(string), "miss").Inc()
				}
			}
		}
	} else {
		extraData["reject"] = "invalid_format"
		m.SetRcode(r, dns.RcodeNameError)
		queryTotal.WithLabelValues("invalid_format", "miss").Inc()
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
		} else {
			extraData["tsig_error"] = w.TsigStatus().Error()
		}
	}

	logQueryResponse(r, m, clientAddr, extraData)

	w.WriteMsg(m)
}

func startDNSServer(net, name, secret string, soreuseport bool) {
	switch name {
	case "":
		server := &dns.Server{Addr: "[::]:8053", Net: net, TsigSecret: nil, ReusePort: soreuseport}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	default:
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: map[string]string{name: secret}, ReusePort: soreuseport}
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
		}
	}
}

func startMetricsServer() {
	// Register Prometheus metrics
	prometheus.MustRegister(cacheEntries)
	prometheus.MustRegister(cacheSizeBytes)
	prometheus.MustRegister(cacheLimitBytes)
	prometheus.MustRegister(queryTotal)
	prometheus.MustRegister(lookupDuration)
	prometheus.MustRegister(dnsLookups)
	prometheus.MustRegister(queryResponseTime)
	prometheus.MustRegister(requestsPerSecond)
	prometheus.MustRegister(concurrentQueries)

	// Set initial cache limit metric
	cacheLimitBytes.Set(float64(*cacheLimit))

	// Start HTTP server for Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf(":%d", *metricsPort)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Printf("Failed to start metrics server: %s\n", err.Error())
		}
	}()
	fmt.Printf("Metrics server started on port %d\n", *metricsPort)
}

func main() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
		fmt.Println("\nEnvironment Variables:")
		fmt.Println("  All flags can also be set via environment variables with SPFFY_ prefix:")
		fmt.Println("  SPFFY_CPUPROFILE, SPFFY_DEBUG, SPFFY_LOGFILE, SPFFY_COMPRESS,")
		fmt.Println("  SPFFY_TSIG, SPFFY_SOREUSEPORT, SPFFY_CPU, SPFFY_BASEDOMAIN,")
		fmt.Println("  SPFFY_CACHELIMIT, SPFFY_DNSSERVERS, SPFFY_VOIDLOOKUPLIMIT,")
		fmt.Println("  SPFFY_CACHETTL, SPFFY_MAXCONCURRENT, SPFFY_METRICSPORT")
		fmt.Println("\nDNS Servers:")
		fmt.Println("  Use comma-separated list for multiple servers (load balanced).")
		fmt.Println("  Example: SPFFY_DNSSERVERS=8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")
		fmt.Println("  If not specified, system resolver is used.")
	}
	flag.Parse()

	loadEnvConfig()

	if *tsig != "" {
		a := strings.SplitN(*tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1]
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	configureLogger()

	cache.limit = *cacheLimit

	setupResolverPool()

	if *debugEnabled {
		if *dnsServers == "" {
			fmt.Println("Using system resolver")
		} else {
			fmt.Printf("Using DNS servers: %s (load balanced)\n", *dnsServers)
		}
	}

	spfSemaphore = make(chan struct{}, *maxConcurrent)

	runCacheCleanup()

	startMetricsServer()

	if *cpu != 0 {
		runtime.GOMAXPROCS(*cpu)
	}
	dns.HandleFunc(".", processDNSQuery)
	if *soreuseport > 0 {
		for i := 0; i < *soreuseport; i++ {
			go startDNSServer("tcp", name, secret, true)
			go startDNSServer("udp", name, secret, true)
		}
	} else {
		go startDNSServer("tcp", name, secret, false)
		go startDNSServer("udp", name, secret, false)
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
