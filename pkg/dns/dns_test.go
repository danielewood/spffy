package dns

import (
	"context"
	// "errors" // Removed as unused
	"net"
	// "strings" // Removed as unused
	"sync"
	"testing"
	// "time" // Removed as unused

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
	baseLogger := logging.NewLogger(level.String(), "", buf) // level.String() needs to be added to LogLevel type
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
	} // Or handle error appropriately
	c.Write(&m)
	return m.GetCounter().GetValue()
}
func getHistogramObervationCount(h prometheus.Histogram) uint64 {
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
		{"ipv4_query_for_base_domain", "1.2.3.4.in-addr.spf.example.com.", "spf.example.com", "1.2.3.4", "in-addr", "spf.example.com", true},
		// Corrected wantIP to canonical form
		{"ipv6_query_for_base_domain", "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.d.c.b.ip6.spf.example.com.", "spf.example.com", "bcd0:1::567:89ab", "ip6", "spf.example.com", true},
		{"ipv4_query_for_sub_domain", "1.2.3.4.in-addr.target.com.spf.example.com.", "spf.example.com", "1.2.3.4", "in-addr", "target.com", true},
		{"ipv6_query_for_sub_domain", "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.ip6.target.com.spf.example.com.", "spf.example.com", "bcd0::10", "ip6", "target.com", true},
		{"invalid_chars_in_ip_part", "1.2.x.4.in-addr.spf.example.com.", "spf.example.com", "", "", "", false},
		{"not_matching_base_domain_suffix", "1.2.3.4.in-addr.target.com.anotherbase.com.", "spf.example.com", "", "", "", false},
		{"too_few_parts_for_ip_ipv4", "1.2.3.in-addr.spf.example.com.", "spf.example.com", "", "", "", false},
		// Corrected wantDomainToQuery, valid is false because IP part is missing
		{"too_few_parts_overall_no_ip", "in-addr.spf.example.com.", "spf.example.com", "", "", "spf.example.com", false},
		{"no_ip_type_marker", "1.2.3.4.spf.example.com.", "spf.example.com", "", "", "", false},
		{"invalid_ipv6_too_short_for_ip", "b.a.9.8.ip6.spf.example.com.", "spf.example.com", "", "", "", false},
		{"empty_query", "", "spf.example.com", "", "", "", false},
		{"base_domain_only", "spf.example.com.", "spf.example.com", "", "", "", false},
		{"ip_marker_no_ip_parts", "ip6.spf.example.com.", "spf.example.com", "", "", "spf.example.com", false},             // version will be found, domain will be base, but ip invalid
		{"ip_marker_no_ip_parts_in-addr", "in-addr.spf.example.com.", "spf.example.com", "", "", "spf.example.com", false}, // Similar to above
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotVersion, gotDomainToQuery, gotValid := extractSPFComponents(tt.queryName, tt.baseDomainConfig)

			if gotValid != tt.wantValid {
				t.Errorf("extractSPFComponents() gotValid = %v, want %v for query '%s' with base '%s'", gotValid, tt.wantValid, tt.queryName, tt.baseDomainConfig)
				// If validity differs significantly, further checks might be misleading.
				// However, for cases where wantValid=false but some parts are parsed (like domainToQuery), we might want to proceed.
				// For now, if valid differs, we return.
				return
			}

			// Only check these if we expect a valid parse, or if specific invalid cases should still parse some fields.
			// The current test structure implies these are only checked for wantValid=true.
			// Let's adjust to check these fields IF tt.wantValid is true.
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
				// For some invalid cases, we might still expect a specific domainToQuery if the version was found.
				// Example: "ip_marker_no_ip_parts"
				if (tt.name == "ip_marker_no_ip_parts" || tt.name == "ip_marker_no_ip_parts_in-addr" || tt.name == "too_few_parts_overall_no_ip") && gotDomainToQuery != tt.wantDomainToQuery {
					t.Errorf("extractSPFComponents() for an invalid case, gotDomainToQuery = %q, want %q for query '%s'", gotDomainToQuery, tt.wantDomainToQuery, tt.queryName)
				}
			}
		})
	}
}

// TestProcessDNSQuery needs extensive mocking.
// We will test a few key branches.
func TestProcessDNSQuery_NonTXT(t *testing.T) {
	cfg := &config.Flags{BaseDomain: new(string), Compress: new(bool)} // Minimal config
	*cfg.BaseDomain = "spf.example.com"
	logger := NewMockLogger(logging.LevelInfo)
	mockCache := &MockCache{}
	mockResolverPool := &resolver.ResolverPool{Resolvers: []*net.Resolver{net.DefaultResolver}}
	qt := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_q_total"}, []string{"result", "cache"})

	handler := NewHandler(logger, mockCache, mockResolverPool, cfg, make(chan struct{}, 1), qt, nil, nil, nil, nil, nil)

	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA) // Non-TXT query
	rw := &MockResponseWriter{RemoteAddrVal: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}

	handler.ProcessDNSQuery(rw, req)

	if rw.WrittenMsg == nil {
		t.Fatal("ProcessDNSQuery did not write a message")
	}
	if rw.WrittenMsg.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s; want %s", dns.RcodeToString[rw.WrittenMsg.Rcode], dns.RcodeToString[dns.RcodeNameError])
	}
	if val := getCounterValue(qt, "non_txt", "miss"); val != 1 {
		t.Errorf("queryTotal for non_txt/miss = %f; want 1", val)
	}
	if len(logger.InfoMessages) == 0 && len(logger.DebugMessages) == 0 { // Depending on actual log level used
		t.Error("Expected some log output for rejected query")
	}
}

// Add more tests for ProcessDNSQuery:
// - Wrong base domain
// - Invalid SPF component format
// - Cache hit (found=true, found=false)
// - Cache miss -> SPF lookup (mock SPF check pass/fail)

// (LogLevel).String() method for mock logger was removed as logging.LogLevel now has String().
// The existing helper func (l logging.LogLevel) String() string is also fine,
// but it's better if the type itself provides it.
// Let's assume logging.LogLevel.String() is the canonical one.
// The MockLogger uses level.String() on the logging.LogLevel type.

// Removed func (l logging.LogLevel) String() string {} as it's defined in pkg/logging

// Note: TestStartServerInstances is complex as it starts actual listeners.
// It might be better tested in an integration test suite.
// For unit tests, one could verify the parameters passed to dns.Server,
// if dns.ListenAndServe was mockable or wrapped.

// Test for logQueryResponse is implicitly covered by testing ProcessDNSQuery
// and checking MockLogger's output.
