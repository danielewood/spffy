// Package main implements a name server that responds to TXT queries for any domain
// with a specific SPF record. All other query types receive an NXDOMAIN response.
// Logs queries and responses in JSON format when enabled.
// Module: github.com/danielewood/spffy

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/miekg/dns"
)

var (
	cpuprofile      = flag.String("cpuprofile", "", "write cpu profile to file")
	logEnabled      = flag.Bool("print", false, "enable JSON logging of queries and responses")
	logFile         = flag.String("logfile", "", "write JSON logs to file (default: stdout)")
	compress        = flag.Bool("compress", false, "compress replies")
	tsig            = flag.String("tsig", "", "use SHA256 hmac tsig: keyname:base64")
	soreuseport     = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu             = flag.Int("cpu", 0, "number of cpu to use")
	baseDomain      = flag.String("basedomain", "spf.spffy.dev", "base domain for SPF macro queries")
	cacheLimit      = flag.Int64("cachelimit", 1024*1024*1024, "cache memory limit in bytes (default: 1GB)")
	dnsServer       = flag.String("dnsserver", "8.8.8.8:53", "DNS server to use for lookups")
	voidLookupLimit = flag.Uint("voidlookuplimit", 20, "maximum number of void DNS lookups allowed during SPF evaluation")
	cacheTTL        = flag.Duration("cachettl", 15*time.Second, "cache TTL for SPF results")
	maxConcurrent   = flag.Int("maxconcurrent", 1000, "maximum concurrent SPF lookups")
	logger          *log.Logger
)

// cacheEntry represents a cached SPF result
type cacheEntry struct {
	spfRecord string
	expiry    time.Time
	found     bool  // true if SPF check was successful
	size      int64 // estimated memory size of this entry
}

// dnsCache is a thread-safe cache for SPF lookup results
type dnsCache struct {
	mu        sync.RWMutex
	cache     map[string]*cacheEntry
	totalSize int64
	limit     int64
}

var cache = &dnsCache{
	cache: make(map[string]*cacheEntry),
	limit: 1024 * 1024 * 1024, // 1GB default, will be updated from flag
}

// Semaphore to limit concurrent SPF lookups
var spfSemaphore chan struct{}

// trackingResolver wraps a resolver to count DNS lookups
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

// estimateSize calculates the approximate memory usage of a cache entry
func estimateSize(key string, spfRecord string) int64 {
	size := int64(len(key))       // key string
	size += int64(len(spfRecord)) // SPF record content
	size += 24                    // expiry time.Time
	size += 1                     // found bool
	size += 8                     // size int64

	return size
}

// evictOldest removes the oldest entries until we're under the size limit
func (c *dnsCache) evictOldest() {
	if c.totalSize <= c.limit {
		return
	}

	// Collect all entries with their expiry times
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

	// Sort by expiry time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].expiry.After(entries[j].expiry) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove oldest entries until we're under the limit
	for _, entry := range entries {
		if c.totalSize <= c.limit {
			break
		}
		c.totalSize -= entry.entry.size
		delete(c.cache, entry.key)
	}
}

// get retrieves a cached entry if it exists and hasn't expired
func (c *dnsCache) get(key string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiry) {
		// Entry expired, but we'll clean it up later
		return nil, false
	}

	return entry, true
}

// set stores an entry in the cache with configurable expiry
func (c *dnsCache) set(key string, spfRecord string, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := estimateSize(key, spfRecord)

	// Check if adding this entry would exceed the limit
	if size > c.limit {
		// Entry too large, don't cache it
		return
	}

	// Remove existing entry if it exists
	if existing, exists := c.cache[key]; exists {
		c.totalSize -= existing.size
	}

	// Add new entry
	entry := &cacheEntry{
		spfRecord: spfRecord,
		expiry:    time.Now().Add(*cacheTTL),
		found:     found,
		size:      size,
	}

	c.cache[key] = entry
	c.totalSize += size

	// Evict oldest entries if we're over the limit
	c.evictOldest()
}

// cleanup removes expired entries from the cache
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
}

// getStats returns cache statistics
func (c *dnsCache) getStats() (entries int, totalSize int64, limit int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache), c.totalSize, c.limit
}

// startCacheCleanup starts a goroutine that periodically cleans up expired cache entries
func startCacheCleanup() {
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Clean up every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cache.cleanup()
			}
		}
	}()
}

func initLogger() {
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

// logDNSMessage logs the DNS query and response in JSON format.
func logDNSMessage(r *dns.Msg, m *dns.Msg, clientAddr string, extraData map[string]interface{}) {
	if !*logEnabled {
		return
	}

	// Define types first
	type queryInfo struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}

	type responseInfo struct {
		Status string   `json:"status"`
		Answer []string `json:"answer,omitempty"`
	}

	// Structure for JSON log
	type logEntry struct {
		Timestamp  string                 `json:"timestamp"`
		ClientAddr string                 `json:"client_addr"`
		Query      queryInfo              `json:"query"`
		Response   responseInfo           `json:"response"`
		Debug      map[string]interface{} `json:"debug,omitempty"`
	}

	// Extract query info
	query := queryInfo{
		Name: r.Question[0].Name,
		Type: dns.TypeToString[r.Question[0].Qtype],
	}

	// Extract response info
	response := responseInfo{
		Status: dns.RcodeToString[m.Rcode],
	}
	for _, rr := range m.Answer {
		// Extract clean content based on record type
		switch v := rr.(type) {
		case *dns.TXT:
			// Join all TXT strings without quotes
			response.Answer = append(response.Answer, strings.Join(v.Txt, ""))
		default:
			// Fallback to string representation for other types
			response.Answer = append(response.Answer, rr.String())
		}
	}

	// Create log entry
	entry := logEntry{
		Timestamp:  time.Now().Format(time.RFC3339),
		ClientAddr: clientAddr,
		Query:      query,
		Response:   response,
		Debug:      extraData,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		return // Silently fail if we can't marshal
	}

	// Log the JSON string
	logger.Println(string(jsonData))
}

// parseSPFMacro parses SPF macro format queries and extracts IP, version, and domain
func parseSPFMacro(queryName string) (ip, version, domain string, valid bool) {
	// Remove trailing dot and check if it ends with the configured base domain
	queryName = strings.TrimSuffix(queryName, ".")
	baseDomainSuffix := "." + *baseDomain
	if !strings.HasSuffix(queryName, baseDomainSuffix) {
		return "", "", "", false
	}

	// Remove base domain suffix
	withoutSuffix := strings.TrimSuffix(queryName, baseDomainSuffix)
	parts := strings.Split(withoutSuffix, ".")

	if len(parts) < 3 {
		return "", "", "", false
	}

	// Check if it's IPv4 (in-addr) or IPv6 (ip6)
	var ipParts []string
	var versionType string
	var domainStart int

	// Look for in-addr or ip6 in the parts
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

	// Extract domain (everything after version type)
	domain = strings.Join(parts[domainStart:], ".")

	// Reconstruct IP based on version
	var reconstructedIP string
	if versionType == "in-addr" {
		// IPv4: reverse the octets
		if len(ipParts) != 4 {
			return "", "", "", false
		}
		// Reverse the order for IPv4
		reversedParts := make([]string, len(ipParts))
		for i, part := range ipParts {
			reversedParts[len(ipParts)-1-i] = part
		}
		reconstructedIP = strings.Join(reversedParts, ".")

		// Validate it's a proper IPv4
		if net.ParseIP(reconstructedIP) == nil {
			return "", "", "", false
		}
	} else if versionType == "ip6" {
		// IPv6: reconstruct from nibbles
		if len(ipParts) != 32 {
			return "", "", "", false
		}
		// Reverse nibbles and group into 4-char hex groups
		var hexGroups []string
		for i := len(ipParts) - 4; i >= 0; i -= 4 {
			group := ipParts[i+3] + ipParts[i+2] + ipParts[i+1] + ipParts[i]
			hexGroups = append(hexGroups, group)
		}
		reconstructedIP = strings.Join(hexGroups, ":")

		// Validate and normalize IPv6
		parsedIP := net.ParseIP(reconstructedIP)
		if parsedIP == nil {
			return "", "", "", false
		}
		reconstructedIP = parsedIP.String()
	}

	return reconstructedIP, versionType, domain, true
}

func handleReflect(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress

	// Get client address
	clientAddr := w.RemoteAddr().String()
	queryName := r.Question[0].Name
	extraData := make(map[string]interface{})

	// Early abort #1: Only handle TXT queries
	if r.Question[0].Qtype != dns.TypeTXT {
		extraData["reject"] = "non_txt"
		extraData["type"] = dns.TypeToString[r.Question[0].Qtype]
		m.SetRcode(r, dns.RcodeNameError)
		logDNSMessage(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	// Early abort #2: Must end with base domain
	queryNameTrimmed := strings.TrimSuffix(queryName, ".")
	baseDomainSuffix := "." + *baseDomain
	if !strings.HasSuffix(queryNameTrimmed, baseDomainSuffix) {
		extraData["reject"] = "wrong_domain"
		extraData["expected"] = baseDomainSuffix
		m.SetRcode(r, dns.RcodeNameError)
		logDNSMessage(r, m, clientAddr, extraData)
		w.WriteMsg(m)
		return
	}

	// Now do the actual SPF macro parsing and processing
	ip, _, domain, valid := parseSPFMacro(queryName)

	if valid {
		// Add parsed components to debug data
		extraData["ip"] = ip
		extraData["domain"] = domain
		extraData["spf_domain"] = fmt.Sprintf("_spffy.%s", domain)

		// Create cache key combining IP and domain
		cacheKey := fmt.Sprintf("%s|%s", ip, domain)

		// Check cache first
		if cachedEntry, found := cache.get(cacheKey); found {
			extraData["cache"] = "hit"
			if cachedEntry.found {
				extraData["result"] = "pass"
				// Create TXT record with the cached SPF result
				t := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    15, // Use cache TTL
					},
					Txt: []string{cachedEntry.spfRecord},
				}
				m.Answer = append(m.Answer, t)
			} else {
				extraData["result"] = "fail"
				m.SetRcode(r, dns.RcodeNameError)
			}
		} else {
			// Cache miss, perform SPF lookup
			extraData["cache"] = "miss"

			// Acquire semaphore to limit concurrent SPF lookups
			select {
			case spfSemaphore <- struct{}{}:
				// Got semaphore, proceed with lookup
				defer func() { <-spfSemaphore }()
			case <-time.After(1 * time.Second):
				// Timeout waiting for semaphore - too many concurrent lookups
				extraData["error"] = "too_many_concurrent_lookups"
				extraData["result"] = "temperror"
				m.SetRcode(r, dns.RcodeServerFailure)
				logDNSMessage(r, m, clientAddr, extraData)
				w.WriteMsg(m)
				return
			}

			// Parse IP address
			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				extraData["error"] = "invalid_ip"
				extraData["result"] = "error"
				m.SetRcode(r, dns.RcodeServerFailure)
			} else {
				spfDomain := fmt.Sprintf("_spffy.%s", domain)

				// Create custom resolver with DNS lookup tracking
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				baseResolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: 5 * time.Second}
						return d.DialContext(ctx, network, *dnsServer)
					},
				}

				// Track DNS lookup count
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

				startTime := time.Now()
				result, spfErr := spf.CheckHostWithSender(ipAddr, spfDomain, fmt.Sprintf("test@%s", spfDomain), opts...)
				spfDuration := time.Since(startTime)

				extraData["duration_ms"] = spfDuration.Milliseconds()
				extraData["dns_lookups"] = lookupCount

				if spfErr != nil {
					extraData["error"] = spfErr.Error()
				}

				// Also try to get the original SPF record to detect fail type
				var originalFailType string = "~all" // default to softfail

				// Look up the original SPF record to detect fail mechanism
				spfMsg := new(dns.Msg)
				spfMsg.SetQuestion(dns.Fqdn(spfDomain), dns.TypeTXT)
				spfClient := new(dns.Client)
				spfClient.Timeout = 3 * time.Second

				if spfResp, _, spfLookupErr := spfClient.Exchange(spfMsg, *dnsServer); spfLookupErr == nil && spfResp.Rcode == dns.RcodeSuccess {
					for _, rr := range spfResp.Answer {
						if txtRR, ok := rr.(*dns.TXT); ok {
							spfRecord := strings.Join(txtRR.Txt, "")
							if strings.HasPrefix(strings.ToLower(spfRecord), "v=spf1") {
								// Only support ~all (softfail) and -all (hardfail)
								// Default to ~all for anything else
								if strings.Contains(spfRecord, "-all") {
									originalFailType = "-all"
								} else {
									originalFailType = "~all" // fallback for ~all, ?all, +all, or undefined
								}
								extraData["fail_type"] = originalFailType
								break
							}
						}
					}
				}

				// Generate appropriate SPF record based on result
				var spfRecord string
				var resultFound bool

				switch result {
				case spf.Pass:
					if ipAddr.To4() != nil {
						// IPv4 - use detected fail type from original record
						spfRecord = fmt.Sprintf("v=spf1 ip4:%s %s", ip, originalFailType)
					} else {
						// IPv6 - use detected fail type from original record
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
					// Don't cache temporary errors
					logDNSMessage(r, m, clientAddr, extraData)
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

				// Cache the result
				cache.set(cacheKey, spfRecord, resultFound)

				// Create response
				if resultFound {
					t := &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   r.Question[0].Name,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    300, // 5 minute TTL for successful results
						},
						Txt: []string{spfRecord},
					}
					m.Answer = append(m.Answer, t)
				} else {
					m.SetRcode(r, dns.RcodeNameError)
				}
			}
		}
	} else {
		// Invalid SPF macro format
		extraData["reject"] = "invalid_format"
		m.SetRcode(r, dns.RcodeNameError)
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
		} else {
			extraData["tsig_error"] = w.TsigStatus().Error()
		}
	}

	// Log the query and response
	logDNSMessage(r, m, clientAddr, extraData)

	w.WriteMsg(m)
}

func serve(net, name, secret string, soreuseport bool) {
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

func main() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
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

	// Initialize logger
	initLogger()

	// Set cache limit from flag
	cache.limit = *cacheLimit

	// Initialize semaphore for limiting concurrent SPF lookups
	spfSemaphore = make(chan struct{}, *maxConcurrent)

	// Start cache cleanup routine
	startCacheCleanup()

	if *cpu != 0 {
		runtime.GOMAXPROCS(*cpu)
	}
	// Register handler for all domains
	dns.HandleFunc(".", handleReflect)
	if *soreuseport > 0 {
		for i := 0; i < *soreuseport; i++ {
			go serve("tcp", name, secret, true)
			go serve("udp", name, secret, true)
		}
	} else {
		go serve("tcp", name, secret, false)
		go serve("udp", name, secret, false)
	}
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
