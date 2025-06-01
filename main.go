package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	logger *Logger
)

// Settings holds all configurable settings
type Settings struct {
	CPUProfile      string `json:"cpuprofile"`
	LogLevel        string `json:"loglevel"`
	LogFile         string `json:"logfile"`
	Compress        bool   `json:"compress"`
	TSIG            string `json:"tsig"`
	SOReusePort     int    `json:"soreuseport"`
	CPU             int    `json:"cpu"`
	BaseDomain      string `json:"basedomain"`
	CacheLimit      int64  `json:"cachelimit"`
	DNSServers      string `json:"dnsservers"`
	VoidLookupLimit uint   `json:"voidlookuplimit"`
	CacheTTL        int    `json:"cachettl"`
	MaxConcurrent   int    `json:"maxconcurrent"`
	MetricsPort     int    `json:"metricsport"`
}

// flags holds the command-line flags
type flags struct {
	cpuprofile      *string
	logLevel        *string
	logFile         *string
	compress        *bool
	tsig            *string
	soreuseport     *int
	cpu             *int
	baseDomain      *string
	cacheLimit      *int64
	dnsServers      *string
	voidLookupLimit *uint
	cacheTTL        *int
	maxConcurrent   *int
	metricsPort     *int
}

// LogLevel defines the possible logging levels
type LogLevel int

const (
	LevelNone LogLevel = iota
	LevelInfo
	LevelDebug
	LevelTrace
)

// LogBuffer stores recent logs and broadcasts to clients
type LogBuffer struct {
	mu      sync.Mutex
	logs    []string
	maxSize int
	broad   chan string
	clients map[chan string]struct{}
}

func NewLogBuffer(maxSize int) *LogBuffer {
	return &LogBuffer{
		logs:    make([]string, 0, maxSize),
		maxSize: maxSize,
		broad:   make(chan string, 100),
		clients: make(map[chan string]struct{}),
	}
}

func (lb *LogBuffer) Add(log string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.logs = append(lb.logs, log)
	if len(lb.logs) > lb.maxSize {
		lb.logs = lb.logs[1:]
	}

	select {
	case lb.broad <- log:
	default:
	}
}

func (lb *LogBuffer) GetAll() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return append([]string{}, lb.logs...)
}

func (lb *LogBuffer) RegisterClient() chan string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	ch := make(chan string, 100)
	lb.clients[ch] = struct{}{}
	return ch
}

func (lb *LogBuffer) UnregisterClient(ch chan string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	delete(lb.clients, ch)
	close(ch)
}

func (lb *LogBuffer) Broadcast() {
	for log := range lb.broad {
		lb.mu.Lock()
		for ch := range lb.clients {
			select {
			case ch <- log:
			default:
			}
		}
		lb.mu.Unlock()
	}
}

// Logger is a custom logger with leveled logging
type Logger struct {
	level  LogLevel
	writer *log.Logger
	buffer *LogBuffer
}

// NewLogger creates a new logger with the specified level and output
func NewLogger(levelStr string, output string, buffer *LogBuffer) *Logger {
	var level LogLevel
	switch strings.ToUpper(levelStr) {
	case "NONE":
		level = LevelNone
	case "INFO":
		level = LevelInfo
	case "DEBUG":
		level = LevelDebug
	case "TRACE":
		level = LevelTrace
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level %s, defaulting to INFO\n", levelStr)
		level = LevelInfo
	}

	var writer *log.Logger
	if output != "" {
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file %s: %v\n", output, err)
			writer = log.New(os.Stdout, "", 0)
		} else {
			writer = log.New(f, "", 0)
		}
	} else {
		writer = log.New(os.Stdout, "", 0)
	}

	return &Logger{
		level:  level,
		writer: writer,
		buffer: buffer,
	}
}

// logMessage logs a message at the specified level with JSON formatting
func (l *Logger) logMessage(level LogLevel, msg map[string]interface{}) {
	if level > l.level {
		return
	}

	msg["level"] = levelToString(level)
	msg["timestamp"] = time.Now().Format(time.RFC3339)

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return
	}

	logStr := string(jsonData)
	l.writer.Println(logStr)
	l.buffer.Add(logStr)
}

func levelToString(level LogLevel) string {
	switch level {
	case LevelNone:
		return "NONE"
	case LevelInfo:
		return "INFO"
	case LevelDebug:
		return "DEBUG"
	case LevelTrace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

// Info logs at INFO level
func (l *Logger) Info(msg map[string]interface{}) {
	l.logMessage(LevelInfo, msg)
}

// Debug logs at DEBUG level
func (l *Logger) Debug(msg map[string]interface{}) {
	l.logMessage(LevelDebug, msg)
}

// Trace logs at TRACE level
func (l *Logger) Trace(msg map[string]interface{}) {
	l.logMessage(LevelTrace, msg)
}

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
	hits      uint64
}

type dnsCache struct {
	mu          sync.RWMutex
	cache       map[string]*cacheEntry
	totalSize   int64
	limit       int64
	totalHits   uint64
	totalMisses uint64
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
	cacheHitRatio = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_hit_ratio",
		Help: "Ratio of cache hits to total queries",
	})
	cacheOldestEntryAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_oldest_entry_age_seconds",
		Help: "Age of the oldest cache entry in seconds",
	})
	cacheYoungestEntryAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_youngest_entry_age_seconds",
		Help: "Age of the youngest cache entry in seconds",
	})
	cacheMostUsedEntry = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spffy_cache_most_used_entry",
		Help: "Number of hits for the most used cache entry",
	}, []string{"key"})
	cacheHitsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "spffy_cache_hits_total",
		Help: "Total number of cache hits",
	})
	cacheMissesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "spffy_cache_misses_total",
		Help: "Total number of cache misses",
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

func loadEnvConfig(f *flags) {
	if !isFlagSet("cpuprofile") {
		*f.cpuprofile = envString("SPFFY_CPUPROFILE", *f.cpuprofile)
	}
	if !isFlagSet("loglevel") {
		*f.logLevel = envString("SPFFY_LOGLEVEL", *f.logLevel)
	}
	if !isFlagSet("logfile") {
		*f.logFile = envString("SPFFY_LOGFILE", *f.logFile)
	}
	if !isFlagSet("compress") {
		*f.compress = envBool("SPFFY_COMPRESS", *f.compress)
	}
	if !isFlagSet("tsig") {
		*f.tsig = envString("SPFFY_TSIG", *f.tsig)
	}
	if !isFlagSet("soreuseport") {
		*f.soreuseport = envInt("SPFFY_SOREUSEPORT", *f.soreuseport)
	}
	if !isFlagSet("cpu") {
		*f.cpu = envInt("SPFFY_CPU", *f.cpu)
	}
	if !isFlagSet("basedomain") {
		*f.baseDomain = envString("SPFFY_BASEDOMAIN", *f.baseDomain)
	}
	if !isFlagSet("cachelimit") {
		*f.cacheLimit = envInt64("SPFFY_CACHELIMIT", *f.cacheLimit)
	}
	if !isFlagSet("dnsservers") {
		*f.dnsServers = envString("SPFFY_DNSSERVERS", *f.dnsServers)
	}
	if !isFlagSet("voidlookuplimit") {
		*f.voidLookupLimit = envUint("SPFFY_VOIDLOOKUPLIMIT", *f.voidLookupLimit)
	}
	if !isFlagSet("cachettl") {
		*f.cacheTTL = envInt("SPFFY_CACHETTL", *f.cacheTTL)
	}
	if !isFlagSet("maxconcurrent") {
		*f.maxConcurrent = envInt("SPFFY_MAXCONCURRENT", *f.maxConcurrent)
	}
	if !isFlagSet("metricsport") {
		*f.metricsPort = envInt("SPFFY_METRICSPORT", *f.metricsPort)
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

func setupResolverPool(dnsServers string) {
	resolvers = &resolverPool{}

	if dnsServers == "" {
		resolvers.resolvers = []*net.Resolver{net.DefaultResolver}
		return
	}

	servers := strings.Split(dnsServers, ",")
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

func (c *dnsCache) get(key string, f *flags) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.cache[key]
	if !exists {
		c.totalMisses++
		cacheMissesTotal.Inc()
		c.updateCacheMetrics(f)
		return nil, false
	}

	if time.Now().After(entry.expiry) {
		c.totalSize -= entry.size
		delete(c.cache, key)
		c.totalMisses++
		cacheMissesTotal.Inc()
		c.updateCacheMetrics(f)
		return nil, false
	}

	entry.hits++
	c.totalHits++
	cacheHitsTotal.Inc()
	c.updateCacheMetrics(f)

	return entry, true
}

func (c *dnsCache) set(key string, spfRecord string, found bool, f *flags) {
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
		expiry:    time.Now().Add(time.Duration(*f.cacheTTL) * time.Second),
		found:     found,
		size:      size,
		hits:      0,
	}

	c.cache[key] = entry
	c.totalSize += size
	c.evictOldest()
	c.updateCacheMetrics(f)

	cacheEntries.Set(float64(len(c.cache)))
	cacheSizeBytes.Set(float64(c.totalSize))
	cacheLimitBytes.Set(float64(c.limit))
}

func (c *dnsCache) cleanup(f *flags) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiry) {
			c.totalSize -= entry.size
			delete(c.cache, key)
		}
	}

	cacheEntries.Set(float64(len(c.cache)))
	cacheSizeBytes.Set(float64(c.totalSize))
	cacheLimitBytes.Set(float64(c.limit))
	c.updateCacheMetrics(f)
}

func (c *dnsCache) updateCacheMetrics(f *flags) {
	if c.totalHits+c.totalMisses > 0 {
		cacheHitRatio.Set(float64(c.totalHits) / float64(c.totalHits+c.totalMisses))
	} else {
		cacheHitRatio.Set(0)
	}

	now := time.Now()
	var oldestAge, youngestAge time.Duration
	var maxHits uint64
	var mostUsedKey string

	for key, entry := range c.cache {
		age := now.Sub(entry.expiry.Add(-time.Duration(*f.cacheTTL) * time.Second))
		if oldestAge == 0 || age > oldestAge {
			oldestAge = age
		}
		if youngestAge == 0 || age < youngestAge {
			youngestAge = age
		}
		if entry.hits > maxHits {
			maxHits = entry.hits
			mostUsedKey = key
		}
	}

	cacheOldestEntryAge.Set(oldestAge.Seconds())
	cacheYoungestEntryAge.Set(youngestAge.Seconds())
	cacheMostUsedEntry.WithLabelValues(mostUsedKey).Set(float64(maxHits))
}

func (c *dnsCache) getStats() (entries int, totalSize int64, limit int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache), c.totalSize, c.limit
}

func runCacheCleanup(f *flags) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cache.cleanup(f)
			}
		}
	}()
}

func configureLogger(logBuffer *LogBuffer, logLevel, logFile string) {
	logger = NewLogger(logLevel, logFile, logBuffer)
}

func logQueryResponse(r *dns.Msg, m *dns.Msg, clientAddr string, extraData map[string]interface{}) {
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

	if logger.level >= LevelDebug && len(extraData) > 0 {
		logEntry["debug"] = extraData
	}

	if logger.level >= LevelTrace {
		logger.Trace(logEntry)
	} else if logger.level >= LevelDebug {
		logger.Debug(logEntry)
	} else {
		logger.Info(logEntry)
	}
}

func extractSPFComponents(queryName string, f *flags) (ip, version, domain string, valid bool) {
	queryName = strings.TrimSuffix(queryName, ".")
	baseDomainSuffix := "." + *f.baseDomain
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

func processDNSQuery(w dns.ResponseWriter, r *dns.Msg, f *flags) {
	startTime := time.Now()
	concurrentQueries.Inc()
	defer concurrentQueries.Dec()
	defer func() {
		queryResponseTime.Observe(time.Since(startTime).Seconds())
	}()

	requestsPerSecond.Inc()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *f.compress

	clientAddr := w.RemoteAddr().String()
	queryName := r.Question[0].Name
	extraData := make(map[string]interface{})

	if logger.level >= LevelDebug {
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
	baseDomainSuffix := "." + *f.baseDomain
	if !strings.HasSuffix(queryNameTrimmed, baseDomainSuffix) {
		extraData["reject"] = "wrong_domain"
		extraData["expected"] = baseDomainSuffix
		m.SetRcode(r, dns.RcodeNameError)
		queryTotal.WithLabelValues("wrong_domain", "miss").Inc()
		logQueryResponse(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	ip, _, domain, valid := extractSPFComponents(queryName, f)

	if valid {
		extraData["ip"] = ip
		extraData["domain"] = domain
		extraData["spf_domain"] = fmt.Sprintf("_spffy.%s", domain)

		cacheKey := fmt.Sprintf("%s|%s", ip, domain)

		if cachedEntry, found := cache.get(cacheKey, f); found {
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
					spf.OverrideVoidLookupLimit(*f.voidLookupLimit),
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
					if *f.dnsServers != "" {
						servers := strings.Split(*f.dnsServers, ",")
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

				cache.set(cacheKey, spfRecord, resultFound, f)

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
			logger.Info(map[string]interface{}{
				"error": fmt.Sprintf("Failed to setup the %s server: %s", net, err.Error()),
			})
		}
	default:
		server := &dns.Server{Addr: ":8053", Net: net, TsigSecret: map[string]string{name: secret}, ReusePort: soreuseport}
		if err := server.ListenAndServe(); err != nil {
			logger.Info(map[string]interface{}{
				"error": fmt.Sprintf("Failed to setup the %s server: %s", net, err.Error()),
			})
		}
	}
}

func startMetricsServer(logBuffer *LogBuffer, f *flags) {
	prometheus.MustRegister(cacheEntries)
	prometheus.MustRegister(cacheSizeBytes)
	prometheus.MustRegister(cacheLimitBytes)
	prometheus.MustRegister(queryTotal)
	prometheus.MustRegister(lookupDuration)
	prometheus.MustRegister(dnsLookups)
	prometheus.MustRegister(queryResponseTime)
	prometheus.MustRegister(requestsPerSecond)
	prometheus.MustRegister(concurrentQueries)
	prometheus.MustRegister(cacheHitRatio)
	prometheus.MustRegister(cacheOldestEntryAge)
	prometheus.MustRegister(cacheYoungestEntryAge)
	prometheus.MustRegister(cacheMostUsedEntry)
	prometheus.MustRegister(cacheHitsTotal)
	prometheus.MustRegister(cacheMissesTotal)

	cacheLimitBytes.Set(float64(*f.cacheLimit))

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stream") == "true" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")

			clientChan := logBuffer.RegisterClient()
			defer logBuffer.UnregisterClient(clientChan)

			for _, log := range logBuffer.GetAll() {
				fmt.Fprintf(w, "data: %s\n\n", log)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}

			for log := range clientChan {
				fmt.Fprintf(w, "data: %s\n\n", log)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		} else {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
    <title>SPFFY Logs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/monokai-sublime.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script>hljs.highlightAll();</script>
    <style>
        body { background-color: #1a202c; color: #e2e8f0; }
        #logs { max-height: calc(100vh - 80px); overflow-y: auto; }
        .log-entry { border-bottom: 1px solid #4a5568; }
        pre { margin: 0; white-space: pre-wrap; word-break: break-all; }
        .toggle-button { position: fixed; top: 10px; right: 10px; }
    </style>
</head>
<body class="p-4">
    <button id="toggleFormat" class="toggle-button bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded">Toggle Format</button>
    <div id="logs" class="bg-gray-800 rounded-lg p-4"></div>
    <script>
        const logs = document.getElementById('logs');
        const toggleButton = document.getElementById('toggleFormat');
        let isFormatted = false;
        let source = null;

        function connectSource() {
            if (source) {
                source.close();
            }
            source = new EventSource('/logs?stream=true');
            source.onmessage = function(event) {
                if (!event.data.trim()) return;
                addLog(event.data);
            };
            source.onerror = function() {
                source.close();
                const div = document.createElement('div');
                div.className = 'log-entry p-2 text-red-400';
                div.textContent = 'Connection lost. Please refresh to reconnect.';
                logs.appendChild(div);
            };
        }

        function formatLog(log) {
            try {
                const parsed = JSON.parse(log);
                return isFormatted ? JSON.stringify(parsed, null, 2) : JSON.stringify(parsed);
            } catch (e) {
                return log;
            }
        }

        function addLog(log) {
            const div = document.createElement('div');
            div.className = 'log-entry p-2';
            const pre = document.createElement('pre');
            pre.innerHTML = hljs.highlight(formatLog(log), { language: 'json' }).value;
            div.appendChild(pre);
            logs.appendChild(div);
            logs.scrollTop = logs.scrollHeight;
        }

        toggleButton.addEventListener('click', () => {
            isFormatted = !isFormatted;
            logs.innerHTML = '';
            toggleButton.textContent = isFormatted ? 'Raw JSON' : 'Formatted JSON';
            connectSource();
        });

        connectSource();
    </script>
</body>
</html>
`)
		}
	})

	http.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			settings := Settings{
				CPUProfile:      *f.cpuprofile,
				LogLevel:        *f.logLevel,
				LogFile:         *f.logFile,
				Compress:        *f.compress,
				TSIG:            *f.tsig,
				SOReusePort:     *f.soreuseport,
				CPU:             *f.cpu,
				BaseDomain:      *f.baseDomain,
				CacheLimit:      *f.cacheLimit,
				DNSServers:      *f.dnsServers,
				VoidLookupLimit: *f.voidLookupLimit,
				CacheTTL:        *f.cacheTTL,
				MaxConcurrent:   *f.maxConcurrent,
				MetricsPort:     *f.metricsPort,
			}
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(settings); err != nil {
				http.Error(w, "Failed to encode settings", http.StatusInternalServerError)
				return
			}

		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}

			var newSettings Settings
			if err := json.Unmarshal(body, &newSettings); err != nil {
				http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
				return
			}

			// Validate settings
			switch strings.ToUpper(newSettings.LogLevel) {
			case "NONE", "INFO", "DEBUG", "TRACE":
			default:
				http.Error(w, "Invalid loglevel: must be NONE, INFO, DEBUG, or TRACE", http.StatusBadRequest)
				return
			}
			if newSettings.CacheTTL < 0 {
				http.Error(w, "CacheTTL must be non-negative", http.StatusBadRequest)
				return
			}
			if newSettings.CacheLimit < 0 {
				http.Error(w, "CacheLimit must be non-negative", http.StatusBadRequest)
				return
			}
			if newSettings.MaxConcurrent <= 0 {
				http.Error(w, "MaxConcurrent must be positive", http.StatusBadRequest)
				return
			}
			if newSettings.MetricsPort <= 0 {
				http.Error(w, "MetricsPort must be positive", http.StatusBadRequest)
				return
			}
			if newSettings.SOReusePort < 0 {
				http.Error(w, "SOReusePort must be non-negative", http.StatusBadRequest)
				return
			}
			if newSettings.CPU < 0 {
				http.Error(w, "CPU must be non-negative", http.StatusBadRequest)
				return
			}

			// Check for settings requiring restart
			restartRequired := false
			messages := []string{}
			if newSettings.SOReusePort != *f.soreuseport {
				restartRequired = true
				messages = append(messages, "SOReusePort change requires program restart")
			}
			if newSettings.MetricsPort != *f.metricsPort {
				restartRequired = true
				messages = append(messages, "MetricsPort change requires program restart")
			}
			if newSettings.CPU != *f.cpu {
				restartRequired = true
				messages = append(messages, "CPU change requires program restart")
			}

			// Update settings
			*f.cpuprofile = newSettings.CPUProfile
			*f.logLevel = newSettings.LogLevel
			*f.logFile = newSettings.LogFile
			*f.compress = newSettings.Compress
			*f.tsig = newSettings.TSIG
			*f.soreuseport = newSettings.SOReusePort
			*f.cpu = newSettings.CPU
			*f.baseDomain = newSettings.BaseDomain
			*f.cacheLimit = newSettings.CacheLimit
			*f.dnsServers = newSettings.DNSServers
			*f.voidLookupLimit = newSettings.VoidLookupLimit
			*f.cacheTTL = newSettings.CacheTTL
			*f.maxConcurrent = newSettings.MaxConcurrent
			*f.metricsPort = newSettings.MetricsPort

			// Reinitialize components
			configureLogger(logBuffer, *f.logLevel, *f.logFile)
			cache.mu.Lock()
			cache.limit = *f.cacheLimit
			cache.evictOldest()
			cache.mu.Unlock()
			cacheLimitBytes.Set(float64(*f.cacheLimit))
			setupResolverPool(*f.dnsServers)
			spfSemaphore = make(chan struct{}, *f.maxConcurrent)

			// Log update
			response := map[string]interface{}{
				"status":  "updated",
				"message": "Settings updated successfully",
			}
			if restartRequired {
				response["status"] = "updated_with_restart_required"
				response["message"] = "Some settings updated, but restart required for: " + strings.Join(messages, ", ")
			}
			logger.Info(map[string]interface{}{
				"message":  "Settings updated via /settings",
				"settings": newSettings,
				"restart":  restartRequired,
			})

			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(response); err != nil {
				http.Error(w, "Failed to encode response", http.StatusInternalServerError)
				return
			}

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	addr := fmt.Sprintf(":%d", *f.metricsPort)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			logger.Info(map[string]interface{}{
				"error": fmt.Sprintf("Failed to start metrics server: %s", err.Error()),
			})
		}
	}()
	logger.Info(map[string]interface{}{
		"message": fmt.Sprintf("Metrics, logs, and settings server started on port %d", *f.metricsPort),
	})

	go logBuffer.Broadcast()
}

func printConfig(f *flags) {
	logger.Info(map[string]interface{}{
		"message": "Configuration",
		"config": map[string]interface{}{
			"SPFFY_CPUPROFILE":      *f.cpuprofile,
			"SPFFY_LOGLEVEL":        *f.logLevel,
			"SPFFY_LOGFILE":         *f.logFile,
			"SPFFY_COMPRESS":        *f.compress,
			"SPFFY_TSIG":            *f.tsig,
			"SPFFY_SOREUSEPORT":     *f.soreuseport,
			"SPFFY_CPU":             *f.cpu,
			"SPFFY_BASEDOMAIN":      *f.baseDomain,
			"SPFFY_CACHELIMIT":      *f.cacheLimit,
			"SPFFY_DNSSERVERS":      *f.dnsServers,
			"SPFFY_VOIDLOOKUPLIMIT": *f.voidLookupLimit,
			"SPFFY_CACHETTL":        *f.cacheTTL,
			"SPFFY_MAXCONCURRENT":   *f.maxConcurrent,
			"SPFFY_METRICSPORT":     *f.metricsPort,
		},
	})
}

func main() {
	f := &flags{
		cpuprofile:      flag.String("cpuprofile", "", "write cpu profile to file"),
		logLevel:        flag.String("loglevel", "INFO", "log level: NONE, INFO, DEBUG, TRACE"),
		logFile:         flag.String("logfile", "", "write JSON logs to file (default: stdout)"),
		compress:        flag.Bool("compress", false, "compress replies"),
		tsig:            flag.String("tsig", "", "use SHA256 hmac tsig: keyname:base64"),
		soreuseport:     flag.Int("soreuseport", 0, "number of server instances to start with SO_REUSEPORT (0 to disable)"),
		cpu:             flag.Int("cpu", 0, "number of cpu to use"),
		baseDomain:      flag.String("basedomain", "_spf-stage.spffy.dev", "base domain for SPF macro queries"),
		cacheLimit:      flag.Int64("cachelimit", 1024*1024*1024, "cache memory limit in bytes (default: 1GB)"),
		dnsServers:      flag.String("dnsservers", "", "comma-separated list of DNS servers to use for lookups (default: system resolver)"),
		voidLookupLimit: flag.Uint("voidlookuplimit", 20, "maximum number of void DNS lookups allowed during SPF evaluation"),
		cacheTTL:        flag.Int("cachettl", 15, "cache TTL for SPF results in seconds"),
		maxConcurrent:   flag.Int("maxconcurrent", 1000, "maximum concurrent SPF lookups"),
		metricsPort:     flag.Int("metricsport", 8080, "port for metrics server"),
	}

	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
		fmt.Println("\nEnvironment Variables:")
		fmt.Println("  All flags can also be set via environment variables with SPFFY_ prefix:")
		fmt.Println("  SPFFY_CPUPROFILE, SPFFY_LOGLEVEL, SPFFY_LOGFILE, SPFFY_COMPRESS,")
		fmt.Println("  SPFFY_TSIG, SPFFY_SOREUSEPORT, SPFFY_CPU, SPFFY_BASEDOMAIN,")
		fmt.Println("  SPFFY_CACHELIMIT, SPFFY_DNSSERVERS, SPFFY_VOIDLOOKUPLIMIT,")
		fmt.Println("  SPFFY_CACHETTL, SPFFY_MAXCONCURRENT, SPFFY_METRICSPORT")
		fmt.Println("\nDNS Servers:")
		fmt.Println("  Use comma-separated list for multiple servers (load balanced).")
		fmt.Println("  Example: SPFFY_DNSSERVERS=8.8.8.8:53,1.1.1.1:53,9.9.9.9:53")
		fmt.Println("  If not specified, system resolver is used.")
		fmt.Println("\nSO_REUSEPORT:")
		fmt.Println("  Set soreuseport to the number of server instances to start.")
		fmt.Println("  Each instance uses SO_REUSEPORT to share the same port, enabling kernel-level load balancing.")
		fmt.Println("  Example: SPFFY_SOREUSEPORT=4 starts 4 TCP and 4 UDP servers.")
		fmt.Println("\nLogs Endpoint:")
		fmt.Println("  Access /logs on the metrics port to view streaming logs in the browser.")
		fmt.Println("\nSettings Endpoint:")
		fmt.Println("  GET /settings to view current settings as JSON.")
		fmt.Println("  POST /settings with JSON to update settings dynamically.")
	}
	flag.Parse()

	loadEnvConfig(f)

	logBuffer := NewLogBuffer(1000)
	configureLogger(logBuffer, *f.logLevel, *f.logFile)

	printConfig(f)

	if *f.tsig != "" {
		a := strings.SplitN(*f.tsig, ":", 2)
		name, secret = dns.Fqdn(a[0]), a[1]
	}
	if *f.cpuprofile != "" {
		file, err := os.Create(*f.cpuprofile)
		if err != nil {
			logger.Info(map[string]interface{}{
				"error": fmt.Sprintf("Failed to create CPU profile: %v", err),
			})
			os.Exit(1)
		}
		pprof.StartCPUProfile(file)
		defer pprof.StopCPUProfile()
	}

	cache.limit = *f.cacheLimit

	setupResolverPool(*f.dnsServers)

	if logger.level >= LevelDebug {
		if *f.dnsServers == "" {
			logger.Debug(map[string]interface{}{
				"message": "Using system resolver",
			})
		} else {
			logger.Debug(map[string]interface{}{
				"message": fmt.Sprintf("Using DNS servers: %s (load balanced)", *f.dnsServers),
			})
		}
	}

	spfSemaphore = make(chan struct{}, *f.maxConcurrent)

	runCacheCleanup(f)

	startMetricsServer(logBuffer, f)

	if *f.cpu != 0 {
		runtime.GOMAXPROCS(*f.cpu)
	}
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		processDNSQuery(w, r, f)
	})
	if *f.soreuseport > 0 {
		for i := 0; i < *f.soreuseport; i++ {
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
	logger.Info(map[string]interface{}{
		"message": fmt.Sprintf("Signal (%s) received, stopping", s),
	})
}
