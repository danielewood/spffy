package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/danielewood/spffy/pkg/cache"
	"github.com/danielewood/spffy/pkg/config"
	"github.com/danielewood/spffy/pkg/logging"
	"github.com/danielewood/spffy/pkg/resolver"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
)

// --- Mocks & Test Helpers ---

// MockResponseWriter is a mock dns.ResponseWriter.
type MockResponseWriter struct {
	RemoteAddrVal net.Addr
	WrittenMsg    *dns.Msg
	TsigStatusVal error
}

func (m *MockResponseWriter) LocalAddr() net.Addr         { return nil }
func (m *MockResponseWriter) RemoteAddr() net.Addr        { return m.RemoteAddrVal }
func (m *MockResponseWriter) WriteMsg(msg *dns.Msg) error { m.WrittenMsg = msg; return nil }
func (m *MockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *MockResponseWriter) Close() error                { return nil }
func (m *MockResponseWriter) TsigStatus() error           { return m.TsigStatusVal }
func (m *MockResponseWriter) TsigTimersOnly(b bool)       {}
func (m *MockResponseWriter) Hijack()                     {}

// MockLogger for capturing log output or suppressing it.
type MockLogger struct {
	logging.Logger // Embed actual logger to use its methods if needed, or override
	Level          logging.LogLevel
	InfoMessages   []map[string]interface{}
	DebugMessages  []map[string]interface{}
	TraceMessages  []map[string]interface{}
}

func NewMockLogger(level logging.LogLevel) *MockLogger {
	// Initialize a real logger with a null writer if needed, or use simplified mock
	buf := logging.NewLogBuffer(10)
	baseLogger := logging.NewLogger(level.String(), "", buf)
	return &MockLogger{Logger: *baseLogger, Level: level}
}
func (m *MockLogger) GetLevel() logging.LogLevel      { return m.Level }
func (m *MockLogger) Info(msg map[string]interface{}) { m.InfoMessages = append(m.InfoMessages, msg) }
func (m *MockLogger) Debug(msg map[string]interface{}) {
	m.DebugMessages = append(m.DebugMessages, msg)
}
func (m *MockLogger) Trace(msg map[string]interface{}) {
	m.TraceMessages = append(m.TraceMessages, msg)
}
func (m *MockLogger) Error(msg map[string]interface{}) {}
func (m *MockLogger) Warn(msg map[string]interface{})  {}
func (m *MockLogger) Reconfigure(levelStr string, output string, buffer *logging.LogBuffer) {
	switch strings.ToUpper(levelStr) {
	case "NONE":
		m.Level = logging.LevelNone
	case "INFO":
		m.Level = logging.LevelInfo
	case "DEBUG":
		m.Level = logging.LevelDebug
	case "TRACE":
		m.Level = logging.LevelTrace
	default:
		m.Level = logging.LevelInfo
	}
}

// MockCache is a mock cache.DNSCache that implements cache.CacheInterface.
type MockCache struct {
	GetFunc      func(key string) (*cache.CacheEntry, bool)
	SetFunc      func(key string, spfRecord string, found bool)
	SetLimitFunc func(limit int64)
	SetTTLFunc   func(ttlSeconds int)
	mu           sync.Mutex
}

func (m *MockCache) Get(key string) (*cache.CacheEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.GetFunc != nil {
		return m.GetFunc(key)
	}
	return nil, false
}
func (m *MockCache) Set(key string, spfRecord string, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SetFunc != nil {
		m.SetFunc(key, spfRecord, found)
	}
}
func (m *MockCache) SetLimit(limit int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SetLimitFunc != nil {
		m.SetLimitFunc(limit)
	}
}
func (m *MockCache) SetTTL(ttlSeconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.SetTTLFunc != nil {
		m.SetTTLFunc(ttlSeconds)
	}
}

// Ensure MockCache implements CacheInterface
var _ cache.CacheInterface = &MockCache{}

// MockSPFResolver for resolver.SPFResolver interface
type MockSPFResolver struct {
	LookupTXTErr     error
	LookupTXTVals    []string
	LookupMXErr      error
	LookupMXVals     []*net.MX
	LookupAddrErr    error
	LookupAddrVals   []string
	LookupIPAddrErr  error
	LookupIPAddrVals []net.IPAddr
}

func (m *MockSPFResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return m.LookupTXTVals, m.LookupTXTErr
}
func (m *MockSPFResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return m.LookupMXVals, m.LookupMXErr
}
func (m *MockSPFResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return m.LookupAddrVals, m.LookupAddrErr
}
func (m *MockSPFResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return m.LookupIPAddrVals, m.LookupIPAddrErr
}

// Helper to get Prometheus counter value
func getCounterValue(cv *prometheus.CounterVec, labels ...string) float64 {
	if cv == nil {
		return 0
	}
	var m io_prometheus_client.Metric
	c, err := cv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	c.Write(&m)
	return m.GetCounter().GetValue()
}

// Helper to get Prometheus histogram observation count
func getHistogramObservationCount(h prometheus.Histogram) uint64 {
	if h == nil {
		return 0
	}
	var m io_prometheus_client.Metric
	h.Write(&m)
	return m.GetHistogram().GetSampleCount()
}

// --- Test Cases ---

func TestExtractSPFComponents(t *testing.T) {
	// baseDomainConfig is the domain suffix this SPFFY server is authoritative for.
	// wantDomainToQuery is the domain whose SPF policy is actually being resolved.
	tests := []struct {
		name              string
		queryName         string
		baseDomainConfig  string // The base domain suffix configured for the server
		wantIP            string
		wantVersion       string
		wantDomainToQuery string // The domain whose SPF record is actually being queried
		wantValid         bool
	}{
		{"ipv4_query_for_base_domain", "4.3.2.1.in-addr.spf.example.com.", "spf.example.com", "1.2.3.4", "in-addr", "spf.example.com", true},
		{"ipv6_query_for_base_domain", "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.d.c.b.ip6.spf.example.com.", "spf.example.com", "bcd0:1::567:89ab", "ip6", "spf.example.com", true},
		{"ipv4_query_for_sub_domain", "4.3.2.1.in-addr.target.com.spf.example.com.", "spf.example.com", "1.2.3.4", "in-addr", "target.com", true},
		{"ipv6_query_for_sub_domain", "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.ip6.target.com.spf.example.com.", "spf.example.com", "bcd0::10", "ip6", "target.com", true},
		{"invalid_chars_in_ip_part", "1.2.x.4.in-addr.spf.example.com.", "spf.example.com", "", "", "", false},
		{"not_matching_base_domain_suffix", "4.3.2.1.in-addr.target.com.anotherbase.com.", "spf.example.com", "", "", "", false},
		{"too_few_parts_for_ip_ipv4", "1.2.3.in-addr.spf.example.com.", "spf.example.com", "", "", "", false},
		{"too_few_parts_overall_no_ip", "in-addr.spf.example.com.", "spf.example.com", "", "", "spf.example.com", false},
		{"no_ip_type_marker", "1.2.3.4.spf.example.com.", "spf.example.com", "", "", "", false},
		{"invalid_ipv6_too_short_for_ip", "b.a.9.8.ip6.spf.example.com.", "spf.example.com", "", "", "", false},
		{"empty_query", "", "spf.example.com", "", "", "", false},
		{"base_domain_only", "spf.example.com.", "spf.example.com", "", "", "", false},
		{"ip_marker_no_ip_parts", "ip6.spf.example.com.", "spf.example.com", "", "", "spf.example.com", false},
		{"ip_marker_no_ip_parts_in-addr", "in-addr.spf.example.com.", "spf.example.com", "", "", "spf.example.com", false},
		{"malformed_ipv6", "x.y.z.ip6.spf.example.com.", "spf.example.com", "", "", "", false},
		{"extra_dots", "1.2.3.4..in-addr.spf.example.com.", "spf.example.com", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotVersion, gotDomainToQuery, gotValid := extractSPFComponents(tt.queryName, tt.baseDomainConfig)

			if gotValid != tt.wantValid {
				t.Errorf("extractSPFComponents() gotValid = %v, want %v for query '%s' with base '%s'", gotValid, tt.wantValid, tt.queryName, tt.baseDomainConfig)
				return
			}

			if tt.wantValid {
				if gotIP != tt.wantIP {
					t.Errorf("extractSPFComponents() gotIP = %q, want %q for query '%s'", gotIP, tt.wantIP, tt.queryName)
				}
				if gotVersion != tt.wantVersion {
					t.Errorf("extractSPFComponents() gotVersion = %q, want %q for query '%s'", gotVersion, tt.wantVersion, tt.queryName)
				}
				if gotDomainToQuery != tt.wantDomainToQuery {
					t.Errorf("extractSPFComponents() gotDomainToQuery = %q, want %q for query '%s'", gotDomainToQuery, tt.wantDomainToQuery, tt.queryName)
				}
			} else {
				if (tt.name == "ip_marker_no_ip_parts" || tt.name == "ip_marker_no_ip_parts_in-addr" || tt.name == "too_few_parts_overall_no_ip") && gotDomainToQuery != tt.wantDomainToQuery {
					t.Errorf("extractSPFComponents() for an invalid case, gotDomainToQuery = %q, want %q for query '%s'", gotDomainToQuery, tt.wantDomainToQuery, tt.queryName)
				}
			}
		})
	}
}

func TestProcessDNSQuery(t *testing.T) {
	// Helper to create a default handler with mocks
	// Helper to create a default handler with mocks
	createHandler := func(t *testing.T, cache *MockCache, logLevel logging.LogLevel, spfSemaphoreSize int) (*Handler, *MockLogger, *prometheus.CounterVec) {
		cfg := &config.Flags{
			BaseDomain:      new(string),
			Compress:        new(bool),
			DNSServers:      new(string),
			VoidLookupLimit: new(uint),
		}
		*cfg.BaseDomain = "spf.example.com"
		*cfg.Compress = true
		*cfg.DNSServers = "8.8.8.8:53"
		*cfg.VoidLookupLimit = 20
		logger := NewMockLogger(logLevel)
		queryTotal := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_q_total"}, []string{"result", "cache"})
		lookupDuration := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "test_lookup_duration"})
		dnsLookups := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "test_dns_lookups"})
		queryResponseTime := prometheus.NewHistogram(prometheus.HistogramOpts{Name: "test_query_response_time"})
		requestsPerSecond := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_requests_total"})
		concurrentQueries := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_concurrent_queries"})
		resolverPool := &resolver.ResolverPool{
			Resolvers: []*net.Resolver{{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, errors.New("mocked resolver")
				},
			}},
		}
		semaphore := make(chan struct{}, spfSemaphoreSize)
		return NewHandler(logger, cache, resolverPool, cfg, semaphore, queryTotal, lookupDuration, dnsLookups, queryResponseTime, requestsPerSecond, concurrentQueries), logger, queryTotal
	}

	t.Run("NonTXT", func(t *testing.T) {
		cache := &MockCache{}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelInfo, 1)
		req := new(dns.Msg)
		req.SetQuestion("test.com.", dns.TypeA) // Non-TXT query
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeNameError {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeNameError])
		}
		if val := getCounterValue(queryTotal, "non_txt", "miss"); val != 1 {
			t.Errorf("queryTotal for non_txt/miss = %f; want 1", val)
		}
		if len(logger.InfoMessages) == 0 && len(logger.DebugMessages) == 0 {
			t.Error("Expected some log output for rejected query")
		}
	})

	t.Run("WrongBaseDomain", func(t *testing.T) {
		cache := &MockCache{}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelInfo, 1)
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.spf.wrong.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeNameError {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeNameError])
		}
		if val := getCounterValue(queryTotal, "wrong_domain", "miss"); val != 1 {
			t.Errorf("queryTotal for wrong_domain/miss = %f; want 1", val)
		}
		if len(logger.InfoMessages) == 0 {
			t.Error("Expected log output")
		}
		if len(logger.InfoMessages) > 0 && logger.InfoMessages[0]["response"].(map[string]interface{})["status"] != "NXDOMAIN" {
			t.Errorf("Log response status = %v; want NXDOMAIN", logger.InfoMessages[0]["response"])
		}
	})

	t.Run("InvalidSPFComponents", func(t *testing.T) {
		cache := &MockCache{}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelInfo, 1)
		req := new(dns.Msg)
		req.SetQuestion("invalid.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeNameError {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeNameError])
		}
		if val := getCounterValue(queryTotal, "invalid_format", "miss"); val != 1 {
			t.Errorf("queryTotal for invalid_format/miss = %f; want 1", val)
		}
		if len(logger.InfoMessages) == 0 {
			t.Error("Expected log output")
		}
	})

	t.Run("CacheHit_FoundTrue", func(t *testing.T) {
		cache := &MockCache{
			GetFunc: func(key string) (*cache.CacheEntry, bool) {
				if key == "1.2.3.4|example.com" {
					return &cache.CacheEntry{
						SPFRecord: "v=spf1 ip4:1.2.3.4 -all",
						Expiry:    time.Now().Add(time.Hour),
						Found:     true,
						Hits:      1,
					}, true
				}
				return nil, false
			},
		}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelDebug, 1)
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if len(rw.WrittenMsg.Answer) != 1 {
			t.Fatalf("Expected 1 answer, got %d", len(rw.WrittenMsg.Answer))
		}
		if txt, ok := rw.WrittenMsg.Answer[0].(*dns.TXT); !ok || txt.Txt[0] != "v=spf1 ip4:1.2.3.4 -all" {
			t.Errorf("Answer TXT = %v; want 'v=spf1 ip4:1.2.3.4 -all'", rw.WrittenMsg.Answer)
		}
		if val := getCounterValue(queryTotal, "success", "hit"); val != 1 {
			t.Errorf("queryTotal for success/hit = %f; want 1", val)
		}
		if len(logger.DebugMessages) == 0 {
			t.Error("Expected debug log output")
		}
	})

	t.Run("CacheHit_FoundFalse", func(t *testing.T) {
		cache := &MockCache{
			GetFunc: func(key string) (*cache.CacheEntry, bool) {
				if key == "1.2.3.4|example.com" {
					return &cache.CacheEntry{
						SPFRecord: "v=spf1 -all",
						Expiry:    time.Now().Add(time.Hour),
						Found:     false,
						Hits:      1,
					}, true
				}
				return nil, false
			},
		}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelDebug, 1)
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeNameError {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeNameError])
		}
		if val := getCounterValue(queryTotal, "fail", "hit"); val != 1 {
			t.Errorf("queryTotal for fail/hit = %f; want 1", val)
		}
		if len(logger.DebugMessages) == 0 {
			t.Error("Expected debug log output")
		}
	})

	t.Run("CacheMiss_SPFPass", func(t *testing.T) {
		var setCacheKey string
		var setSPFRecord string
		var setFound bool
		cache := &MockCache{
			GetFunc: func(key string) (*cache.CacheEntry, bool) { return nil, false },
			SetFunc: func(key string, spfRecord string, found bool) {
				setCacheKey = key
				setSPFRecord = spfRecord
				setFound = found
				t.Logf("Cache Set: key=%s, spfRecord=%s, found=%v", key, spfRecord, found)
			},
		}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelTrace, 1)
		resolverPool := &resolver.ResolverPool{
			Resolvers: []*net.Resolver{{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return &mockConn{}, nil
				},
			}},
		}
		handler.ResolverPool = resolverPool
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		originalExchange := dnsClientExchange
		defer func() { dnsClientExchange = originalExchange }()
		dnsClientExchange = func(client *dns.Client, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Rcode = dns.RcodeSuccess
			resp.Answer = []dns.RR{
				&dns.TXT{
					Hdr: dns.RR_Header{Name: "_spffy.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{"v=spf1 ip4:1.2.3.4 -all"}, // Ensure -all is returned
				},
			}
			return resp, time.Millisecond, nil
		}

		originalSPFCheck := SPFCheckHost
		defer func() { SPFCheckHost = originalSPFCheck }()
		SPFCheckHost = func(ip net.IP, domain, sender string, opts ...spf.Option) (spf.Result, error) {
			return spf.Pass, nil
		}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if len(rw.WrittenMsg.Answer) != 1 {
			t.Fatalf("Expected 1 answer, got %d", len(rw.WrittenMsg.Answer))
		}
		if txt, ok := rw.WrittenMsg.Answer[0].(*dns.TXT); !ok || txt.Txt[0] != "v=spf1 ip4:1.2.3.4 -all" {
			t.Errorf("Answer TXT = %v; want 'v=spf1 ip4:1.2.3.4 -all'", rw.WrittenMsg.Answer)
		}
		if val := getCounterValue(queryTotal, "success", "miss"); val != 1 {
			t.Errorf("queryTotal for success/miss = %f; want 1", val)
		}
		if setCacheKey != "1.2.3.4|example.com" {
			t.Errorf("Cache Set key = %s; want 1.2.3.4|example.com", setCacheKey)
		}
		if setSPFRecord != "v=spf1 ip4:1.2.3.4 -all" {
			t.Errorf("Cache Set SPFRecord = %s; want v=spf1 ip4:1.2.3.4 -all", setSPFRecord)
		}
		if !setFound {
			t.Error("Cache Set Found = false; want true")
		}
		if len(logger.TraceMessages) == 0 {
			t.Error("Expected trace log output")
		}
	})

	t.Run("CacheMiss_SPFSoftFail", func(t *testing.T) {
		cache := &MockCache{
			GetFunc: func(key string) (*cache.CacheEntry, bool) { return nil, false },
			SetFunc: func(key string, spfRecord string, found bool) {
				if key != "1.2.3.4|example.com" || spfRecord != "v=spf1 ~all" || found {
					t.Errorf("Cache Set key=%s, spfRecord=%s, found=%v; want key=1.2.3.4|example.com, spfRecord=v=spf1 ~all, found=false", key, spfRecord, found)
				}
			},
		}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelInfo, 1)
		resolverPool := &resolver.ResolverPool{
			Resolvers: []*net.Resolver{{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return &mockConn{}, nil
				},
			}},
		}
		handler.ResolverPool = resolverPool
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		originalExchange := dnsClientExchange
		defer func() { dnsClientExchange = originalExchange }()
		dnsClientExchange = func(client *dns.Client, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Rcode = dns.RcodeSuccess
			resp.Answer = []dns.RR{
				&dns.TXT{
					Hdr: dns.RR_Header{Name: "_spffy.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{"v=spf1 ~all"},
				},
			}
			return resp, time.Millisecond, nil
		}

		originalSPFCheck := SPFCheckHost
		defer func() { SPFCheckHost = originalSPFCheck }()
		SPFCheckHost = func(ip net.IP, domain, sender string, opts ...spf.Option) (spf.Result, error) {
			return spf.SoftFail, nil
		}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeNameError {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeNameError])
		}
		if val := getCounterValue(queryTotal, "softfail", "miss"); val != 1 {
			t.Errorf("queryTotal for softfail/miss = %f; want 1", val)
		}
		if len(logger.InfoMessages) == 0 {
			t.Error("Expected info log output")
		}
	})

	t.Run("TooManyConcurrent", func(t *testing.T) {
		cache := &MockCache{}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelInfo, 0) // Zero-size semaphore
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeServerFailure {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeServerFailure])
		}
		if val := getCounterValue(queryTotal, "temperror", "miss"); val != 1 {
			t.Errorf("queryTotal for temperror/miss = %f; want 1", val)
		}
		if len(logger.InfoMessages) == 0 {
			t.Error("Expected log output")
		}
	})

	t.Run("InvalidIP", func(t *testing.T) {
		cache := &MockCache{}
		handler, logger, queryTotal := createHandler(t, cache, logging.LevelInfo, 1)
		req := new(dns.Msg)
		req.SetQuestion("invalid.ip.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.Rcode != dns.RcodeServerFailure {
			t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeServerFailure])
		}
		if val := getCounterValue(queryTotal, "invalid_ip", "miss"); val != 1 {
			t.Errorf("queryTotal for invalid_ip/miss = %f; want 1", val)
		}
		if len(logger.InfoMessages) == 0 {
			t.Error("Expected log output")
		}
	})

	t.Run("TSIGValid", func(t *testing.T) {
		cache := &MockCache{}
		handler, _, _ := createHandler(t, cache, logging.LevelInfo, 1)
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		req.SetTsig("keyname.", dns.HmacSHA256, 300, time.Now().Unix())
		rw := &MockResponseWriter{
			RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			TsigStatusVal: nil,
		}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if rw.WrittenMsg.IsTsig() == nil {
			t.Error("Expected TSIG in response")
		}
	})

	t.Run("TSIGInvalid", func(t *testing.T) {
		cache := &MockCache{}
		handler, logger, _ := createHandler(t, cache, logging.LevelDebug, 1)
		req := new(dns.Msg)
		req.SetQuestion("4.3.2.1.in-addr.example.com.spf.example.com.", dns.TypeTXT)
		req.SetTsig("keyname.", dns.HmacSHA256, 300, time.Now().Unix())
		rw := &MockResponseWriter{
			RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			TsigStatusVal: errors.New("invalid TSIG"),
		}

		handler.ProcessDNSQuery(rw, req)

		if rw.WrittenMsg == nil {
			t.Fatal("No response written")
		}
		if len(logger.DebugMessages) == 0 {
			t.Error("Expected debug log output")
		}
		if len(logger.DebugMessages) > 0 {
			if _, ok := logger.DebugMessages[0]["tsig_error"]; !ok {
				t.Error("Expected tsig_error in debug log")
			}
		}
	})
}

// mockConn for mocking DNS client connections
type mockConn struct{}

func (m *mockConn) Read(b []byte) (int, error)         { return 0, nil }
func (m *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Mock dnsClientExchange for testing
var dnsClientExchange = func(client *dns.Client, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	return nil, 0, errors.New("not implemented")
}

func TestLogQueryResponse(t *testing.T) {
	tests := []struct {
		name      string
		logLevel  logging.LogLevel
		hasAnswer bool
		extraData map[string]interface{}
		wantLog   bool
		wantDebug bool
	}{
		{"InfoNoAnswer", logging.LevelInfo, false, nil, true, false},
		{"DebugWithAnswer", logging.LevelDebug, true, map[string]interface{}{"key": "value"}, true, true},
		{"TraceWithExtra", logging.LevelTrace, false, map[string]interface{}{"key": "value"}, true, true},
		{"NoneNoLog", logging.LevelNone, false, nil, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewMockLogger(tt.logLevel)
			handler := &Handler{Logger: logger}
			req := new(dns.Msg)
			req.SetQuestion("test.spf.example.com.", dns.TypeTXT)
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Rcode = dns.RcodeSuccess
			if tt.hasAnswer {
				resp.Answer = []dns.RR{
					&dns.TXT{
						Hdr: dns.RR_Header{Name: "test.spf.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
						Txt: []string{"v=spf1 -all"},
					},
				}
			}
			clientAddr := "127.0.0.1:12345"

			handler.logQueryResponse(req, resp, clientAddr, tt.extraData)

			hasInfoLog := len(logger.InfoMessages) > 0
			hasDebugLog := len(logger.DebugMessages) > 0
			hasTraceLog := len(logger.TraceMessages) > 0

			if tt.wantLog && !hasInfoLog && !hasDebugLog && !hasTraceLog {
				t.Error("Expected log output, got none")
			}
			if !tt.wantLog && (hasInfoLog || hasDebugLog || hasTraceLog) {
				t.Error("Expected no log output, got some")
			}
			if tt.wantDebug && len(logger.DebugMessages) == 0 && len(logger.TraceMessages) == 0 {
				t.Error("Expected debug or trace log with extra data")
			}
			if tt.hasAnswer && (hasInfoLog || hasDebugLog || hasTraceLog) {
				var logMsg map[string]interface{}
				if hasTraceLog {
					logMsg = logger.TraceMessages[0]
				} else if hasDebugLog {
					logMsg = logger.DebugMessages[0]
				} else if hasInfoLog {
					logMsg = logger.InfoMessages[0]
				}
				if answers, ok := logMsg["response"].(map[string]interface{})["answer"].([]interface{}); !ok || len(answers) == 0 || answers[0] != "v=spf1 -all" {
					t.Errorf("Expected answer in log: %v", logMsg["response"])
				}
			}
		})
	}
}

func TestStartServerInstances(t *testing.T) {
	type serverStart struct {
		netType   string
		addr      string
		reusePort bool
		tsigName  string
	}
	var serversStarted []serverStart
	var mu sync.Mutex

	// Mock dns.Server creation and ListenAndServe
	originalStart := func(server *dns.Server) error {
		mu.Lock()
		serversStarted = append(serversStarted, serverStart{
			netType:   server.Net,
			addr:      server.Addr,
			reusePort: server.ReusePort,
			tsigName:  server.TsigSecret["keyname."],
		})
		mu.Unlock()
		return nil
	}

	logger := NewMockLogger(logging.LevelInfo)
	cfg := &config.Flags{
		TCPAddr: new(string),
		UDPAddr: new(string),
	}
	*cfg.TCPAddr = "[::]:8054"
	*cfg.UDPAddr = ":8055"
	handler := &Handler{Logger: logger, Config: cfg}

	t.Run("NoReusePort", func(t *testing.T) {
		serversStarted = nil
		startServerInstances(handler, "keyname.", "secret", 0, originalStart)
		time.Sleep(10 * time.Millisecond) // Allow goroutines to run
		if len(serversStarted) != 2 {
			t.Fatalf("Expected 2 servers, got %d: %v", len(serversStarted), serversStarted)
		}
		if serversStarted[0].netType != "tcp" || serversStarted[0].addr != "[::]:8054" || serversStarted[0].reusePort || serversStarted[0].tsigName != "secret" {
			t.Errorf("TCP server: %v", serversStarted[0])
		}
		if serversStarted[1].netType != "udp" || serversStarted[1].addr != ":8055" || serversStarted[1].reusePort || serversStarted[1].tsigName != "secret" {
			t.Errorf("UDP server: %v", serversStarted[1])
		}
	})

	t.Run("WithReusePort", func(t *testing.T) {
		serversStarted = nil
		startServerInstances(handler, "", "", 2, originalStart)
		time.Sleep(10 * time.Millisecond) // Allow goroutines to run
		if len(serversStarted) != 4 {
			t.Fatalf("Expected 4 servers, got %d: %v", len(serversStarted), serversStarted)
		}
		for i, s := range serversStarted {
			if i%2 == 0 && (s.netType != "tcp" || s.addr != "[::]:8054" || !s.reusePort || s.tsigName != "") {
				t.Errorf("TCP server %d: %v", i, s)
			}
			if i%2 == 1 && (s.netType != "udp" || s.addr != ":8055" || !s.reusePort || s.tsigName != "") {
				t.Errorf("UDP server %d: %v", i, s)
			}
		}
	})
}

// Helper to inject mock server start
func startServerInstances(h *Handler, tsigName, tsigSecret string, soReusePort int, startFunc func(*dns.Server) error) {
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
		if netType == "tcp" {
			if h.Config.TCPAddr != nil && *h.Config.TCPAddr != "" {
				server.Addr = *h.Config.TCPAddr // [::]:8054 for TCP
			} else {
				server.Addr = "[::]:8053"
			}
		} else if netType == "udp" {
			if h.Config.UDPAddr != nil && *h.Config.UDPAddr != "" {
				server.Addr = *h.Config.UDPAddr // :8055 for UDP
			} else {
				server.Addr = ":8053"
			}
		}
		startFunc(server)
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
