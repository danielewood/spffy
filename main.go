package main

import (
	"fmt"
	// "encoding/json" // Unused
	// "io" // Unused
	// "net/http" // Unused by main, http server is in pkg/server
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns" // Standard DNS library
	"github.com/prometheus/client_golang/prometheus"

	"github.com/danielewood/spffy/pkg/cache"
	"github.com/danielewood/spffy/pkg/config"
	spffydns "github.com/danielewood/spffy/pkg/dns"
	"github.com/danielewood/spffy/pkg/logging"
	"github.com/danielewood/spffy/pkg/resolver"
	"github.com/danielewood/spffy/pkg/server"
)

// configFlags is loaded from command-line arguments and environment variables.
var configFlags *config.Flags

// Prometheus metrics are typically global.
var (
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

// configureLogger initializes and returns a logger.
func configureLoggerFunc(logLevel, logFile string, buffer *logging.LogBuffer) logging.LoggerInterface {
	return logging.NewLogger(logLevel, logFile, buffer)
}

func main() {
	configFlags = config.GetInitialSettings()

	logBuffer := logging.NewLogBuffer(1000)
	logger := configureLoggerFunc(*configFlags.LogLevel, *configFlags.LogFile, logBuffer)

	config.PrintConfig(configFlags, logger.Info)

	// Instantiate Cache Prometheus metrics
	cacheEntriesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_entries", Help: "Number of entries in the SPF cache",
	})
	cacheSizeBytesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_size_bytes", Help: "Total size of cache entries in bytes",
	})
	cacheLimitBytesGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_limit_bytes", Help: "Cache size limit in bytes",
	})
	cacheHitRatioGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_hit_ratio", Help: "Ratio of cache hits to total queries",
	})
	cacheOldestEntryAgeGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_oldest_entry_age_seconds", Help: "Age of the oldest cache entry in seconds",
	})
	cacheYoungestEntryAgeGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "spffy_cache_youngest_entry_age_seconds", Help: "Age of the youngest cache entry in seconds",
	})
	cacheMostUsedEntryGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spffy_cache_most_used_entry", Help: "Number of hits for the most used cache entry",
	}, []string{"key"})
	cacheHitsTotalCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "spffy_cache_hits_total", Help: "Total number of cache hits",
	})
	cacheMissesTotalCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "spffy_cache_misses_total", Help: "Total number of cache misses",
	})

	// Register common Prometheus metrics (used by both cache types or general app)
	prometheus.MustRegister(cacheHitRatioGauge)
	prometheus.MustRegister(cacheHitsTotalCounter)
	prometheus.MustRegister(cacheMissesTotalCounter)
	prometheus.MustRegister(queryTotal)
	prometheus.MustRegister(lookupDuration)
	prometheus.MustRegister(dnsLookups)
	prometheus.MustRegister(queryResponseTime)
	prometheus.MustRegister(requestsPerSecond)
	prometheus.MustRegister(concurrentQueries)

	// Initialize the cache
	var theCache cache.CacheInterface
	var err error // Declare error variable for cache initialization

	cacheTypeLower := strings.ToLower(*configFlags.CacheType)

	if cacheTypeLower == "redis" {
		// Register Redis-specific or common metrics used by RedisCache
		// (Hits, Misses, Ratio are already registered as common)
		logger.Info(map[string]interface{}{"message": "Using Redis cache", "addr": *configFlags.RedisAddr, "db": *configFlags.RedisDB})
		theCache, err = cache.NewRedisCache(
			*configFlags.RedisAddr,
			*configFlags.RedisPassword,
			*configFlags.RedisDB,
			*configFlags.CacheTTL,
			cacheHitsTotalCounter,   // Pass common metric
			cacheMissesTotalCounter, // Pass common metric
			cacheHitRatioGauge,      // Pass common metric
		)
		if err != nil {
			logger.Error(map[string]interface{}{"message": fmt.Sprintf("Failed to initialize Redis cache: %v. Ensure Redis is running and accessible.", err)})
			os.Exit(1)
		}
		logger.Info(map[string]interface{}{"message": "Successfully connected to Redis cache."})

	} else {
		if cacheTypeLower != "inmemory" && cacheTypeLower != "" { // Allow empty to mean default
			logger.Warn(map[string]interface{}{"message": fmt.Sprintf("Unknown cache type '%s', defaulting to inmemory.", *configFlags.CacheType)})
		}
		// Register DNSCache specific metrics only if using inmemory cache
		prometheus.MustRegister(cacheEntriesGauge)
		prometheus.MustRegister(cacheSizeBytesGauge)
		prometheus.MustRegister(cacheLimitBytesGauge)
		prometheus.MustRegister(cacheOldestEntryAgeGauge)
		prometheus.MustRegister(cacheYoungestEntryAgeGauge)
		prometheus.MustRegister(cacheMostUsedEntryGaugeVec)
		// Hits, Misses, Ratio are already registered as common

		logger.Info(map[string]interface{}{"message": "Using in-memory cache."})
		theCache = cache.NewDNSCache(
			*configFlags.CacheTTL,
			*configFlags.CacheLimit,
			cacheEntriesGauge,
			cacheSizeBytesGauge,
			cacheLimitBytesGauge,
			cacheHitRatioGauge,
			cacheOldestEntryAgeGauge,
			cacheYoungestEntryAgeGauge,
			cacheMostUsedEntryGaugeVec,
			cacheHitsTotalCounter,
			cacheMissesTotalCounter,
		)
		// For in-memory cache, start the cleanup routine
		// This check is important because RunCacheCleanup expects *cache.DNSCache.
		if concreteCache, ok := theCache.(*cache.DNSCache); ok {
			logger.Info(map[string]interface{}{"message": "Starting in-memory cache cleanup routine."})
			cache.RunCacheCleanup(concreteCache, 30*time.Second)
		} else {
			// This case should not happen if "inmemory" type correctly initializes DNSCache.
			logger.Error(map[string]interface{}{"message": "In-memory cache initialization failed to return *cache.DNSCache, cleanup routine not started."})
		}
	}

	// Ensure theCache is not nil before proceeding (should be caught by os.Exit above if Redis fails)
	if theCache == nil {
		logger.Error(map[string]interface{}{"message": "Cache initialization failed, exiting."})
		os.Exit(1)
	}

	var tsigName, tsigSecret string
	if *configFlags.TSIG != "" {
		a := strings.SplitN(*configFlags.TSIG, ":", 2)
		tsigName, tsigSecret = dns.Fqdn(a[0]), a[1]
	}

	if *configFlags.CPUProfile != "" {
		file, err := os.Create(*configFlags.CPUProfile)
		if err != nil {
			logger.Info(map[string]interface{}{"error": fmt.Sprintf("Failed to create CPU profile: %v", err)})
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			logger.Info(map[string]interface{}{"error": fmt.Sprintf("Failed to start CPU profile: %v", err)})
		} else {
			defer pprof.StopCPUProfile()
		}
	}

	currentResolverPool := resolver.NewResolverPool(*configFlags.DNSServers)
	spfSemaphore := make(chan struct{}, *configFlags.MaxConcurrent)

	dnsHandler := spffydns.NewHandler(
		logger,
		theCache,
		currentResolverPool,
		configFlags,
		spfSemaphore,
		queryTotal,
		lookupDuration,
		dnsLookups,
		queryResponseTime,
		requestsPerSecond,
		concurrentQueries,
	)

	if logger.GetLevel() >= logging.LevelDebug {
		if *configFlags.DNSServers == "" {
			logger.Debug(map[string]interface{}{"message": "Using system resolver for main application."})
		} else {
			logger.Debug(map[string]interface{}{"message": fmt.Sprintf("Using DNS servers: %s for main application.", *configFlags.DNSServers)})
		}
	}

	// The cache cleanup goroutine is now started conditionally within the cache initialization block for in-memory cache.
	// No need for a separate block here.

	httpServer := server.NewHTTPServer(
		logger,
		logBuffer,
		configFlags,
		theCache,
		&currentResolverPool,
		&spfSemaphore,
	)
	go httpServer.Start()

	if *configFlags.CPU != 0 {
		runtime.GOMAXPROCS(*configFlags.CPU)
	}

	dns.HandleFunc(".", dnsHandler.ProcessDNSQuery)
	dnsHandler.StartServerInstances(tsigName, tsigSecret, *configFlags.SOReusePort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	logger.Info(map[string]interface{}{"message": fmt.Sprintf("Signal (%s) received, stopping", s)})
}
