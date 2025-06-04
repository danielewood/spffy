package cache

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CacheEntry stores information about a cached DNS record.
type CacheEntry struct {
	SPFRecord string
	Expiry    time.Time
	Found     bool
	Size      int64
	Hits      uint64
}

// DNSCache holds cache entries and manages their lifecycle.
type DNSCache struct {
	mu          sync.RWMutex
	cache       map[string]*CacheEntry
	totalSize   int64
	totalHits   uint64
	totalMisses uint64

	// Configuration
	cacheTTLSeconds int
	cacheLimitBytes int64

	// Prometheus Metrics
	entriesGauge          prometheus.Gauge
	sizeBytesGauge        prometheus.Gauge
	limitBytesGauge       prometheus.Gauge
	hitRatioGauge         prometheus.Gauge
	oldestEntryAgeGauge   prometheus.Gauge
	youngestEntryAgeGauge prometheus.Gauge
	mostUsedEntryGaugeVec *prometheus.GaugeVec
	hitsTotalCounter      prometheus.Counter
	missesTotalCounter    prometheus.Counter
}

// NewDNSCache creates and initializes a new DNSCache.
func NewDNSCache(
	ttlSeconds int,
	limitBytes int64,
	entriesGauge prometheus.Gauge,
	sizeBytesGauge prometheus.Gauge,
	limitBytesGauge prometheus.Gauge,
	hitRatioGauge prometheus.Gauge,
	oldestEntryAgeGauge prometheus.Gauge,
	youngestEntryAgeGauge prometheus.Gauge,
	mostUsedEntryGaugeVec *prometheus.GaugeVec,
	hitsTotalCounter prometheus.Counter,
	missesTotalCounter prometheus.Counter,
) *DNSCache {
	dc := &DNSCache{
		cache:                 make(map[string]*CacheEntry),
		cacheTTLSeconds:       ttlSeconds,
		cacheLimitBytes:       limitBytes,
		entriesGauge:          entriesGauge,
		sizeBytesGauge:        sizeBytesGauge,
		limitBytesGauge:       limitBytesGauge,
		hitRatioGauge:         hitRatioGauge,
		oldestEntryAgeGauge:   oldestEntryAgeGauge,
		youngestEntryAgeGauge: youngestEntryAgeGauge,
		mostUsedEntryGaugeVec: mostUsedEntryGaugeVec,
		hitsTotalCounter:      hitsTotalCounter,
		missesTotalCounter:    missesTotalCounter,
	}
	if dc.limitBytesGauge != nil {
		dc.limitBytesGauge.Set(float64(dc.cacheLimitBytes))
	}
	return dc
}

// calcEntrySize calculates the approximate size of a cache entry.
// It's an unexported helper function.
func calcEntrySize(key string, spfRecord string) int64 {
	// Rough estimation:
	// size of key string
	// size of spfRecord string
	// size of Expiry (time.Time, approx 24 bytes)
	// size of Found (bool, 1 byte)
	// size of Size (int64, 8 bytes)
	// size of Hits (uint64, 8 bytes)
	// Plus some overhead for map storage, etc.
	size := int64(len(key))
	size += int64(len(spfRecord))
	size += 24 // time.Time
	size += 1  // bool
	size += 8  // int64 (Size)
	size += 8  // uint64 (Hits)
	return size
}

// EvictOldest removes the oldest entries until the cache size is within limits.
func (c *DNSCache) EvictOldest() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.totalSize <= c.cacheLimitBytes {
		return
	}

	// Create a slice of entries to sort by expiry
	type entryWithKey struct {
		key    string
		entry  *CacheEntry
		expiry time.Time
	}

	var entriesToSort []entryWithKey
	for k, e := range c.cache {
		entriesToSort = append(entriesToSort, entryWithKey{key: k, entry: e, expiry: e.Expiry})
	}

	// Sort entries: oldest first
	// A more efficient way would be a min-heap, but for typical cache sizes, this is acceptable.
	for i := 0; i < len(entriesToSort)-1; i++ {
		for j := i + 1; j < len(entriesToSort); j++ {
			if entriesToSort[i].expiry.After(entriesToSort[j].expiry) {
				entriesToSort[i], entriesToSort[j] = entriesToSort[j], entriesToSort[i]
			}
		}
	}

	for _, entryToDelete := range entriesToSort {
		if c.totalSize <= c.cacheLimitBytes {
			break
		}
		// Ensure the entry still exists as it might have been removed by another process (unlikely with current locking)
		if actualEntry, exists := c.cache[entryToDelete.key]; exists && actualEntry == entryToDelete.entry {
			c.totalSize -= actualEntry.Size
			delete(c.cache, entryToDelete.key)
		}
	}
	// Update metrics after eviction
	if c.entriesGauge != nil {
		c.entriesGauge.Set(float64(len(c.cache)))
	}
	if c.sizeBytesGauge != nil {
		c.sizeBytesGauge.Set(float64(c.totalSize))
	}
}

// Get retrieves an entry from the cache.
func (c *DNSCache) Get(key string) (*CacheEntry, bool) {
	c.mu.Lock() // Changed to full lock to protect hits count update
	defer c.mu.Unlock()

	entry, exists := c.cache[key]
	if !exists {
		c.totalMisses++
		if c.missesTotalCounter != nil {
			c.missesTotalCounter.Inc()
		}
		c.updateCacheMetricsInternal() // Internal call, already locked
		return nil, false
	}

	if time.Now().After(entry.Expiry) {
		c.totalSize -= entry.Size
		delete(c.cache, key)
		c.totalMisses++
		if c.missesTotalCounter != nil {
			c.missesTotalCounter.Inc()
		}
		c.updateCacheMetricsInternal() // Internal call, already locked
		return nil, false
	}

	entry.Hits++
	c.totalHits++
	if c.hitsTotalCounter != nil {
		c.hitsTotalCounter.Inc()
	}
	c.updateCacheMetricsInternal() // Internal call, already locked
	return entry, true
}

// Set adds or updates an entry in the cache.
func (c *DNSCache) Set(key string, spfRecord string, found bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := calcEntrySize(key, spfRecord)

	// Do not add if the entry itself is larger than the total limit
	if size > c.cacheLimitBytes && c.cacheLimitBytes > 0 { // c.cacheLimitBytes > 0 ensures that if limit is 0 or negative, we can still add (effectively no limit)
		return
	}

	if existing, exists := c.cache[key]; exists {
		c.totalSize -= existing.Size
	}

	entry := &CacheEntry{
		SPFRecord: spfRecord,
		Expiry:    time.Now().Add(time.Duration(c.cacheTTLSeconds) * time.Second),
		Found:     found,
		Size:      size,
		Hits:      0,
	}

	c.cache[key] = entry
	c.totalSize += size
	c.evictOldestInternal()        // Internal call, already locked
	c.updateCacheMetricsInternal() // Internal call, already locked

	if c.entriesGauge != nil {
		c.entriesGauge.Set(float64(len(c.cache)))
	}
	if c.sizeBytesGauge != nil {
		c.sizeBytesGauge.Set(float64(c.totalSize))
	}
}

// Cleanup removes expired entries from the cache.
func (c *DNSCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.Expiry) {
			c.totalSize -= entry.Size
			delete(c.cache, key)
		}
	}

	if c.entriesGauge != nil {
		c.entriesGauge.Set(float64(len(c.cache)))
	}
	if c.sizeBytesGauge != nil {
		c.sizeBytesGauge.Set(float64(c.totalSize))
	}
	c.updateCacheMetricsInternal() // Internal call, already locked
}

// updateCacheMetricsInternal updates various cache-related Prometheus gauges.
// This is an internal version that assumes locks are already held.
func (c *DNSCache) updateCacheMetricsInternal() {
	if c.hitRatioGauge != nil {
		if c.totalHits+c.totalMisses > 0 {
			c.hitRatioGauge.Set(float64(c.totalHits) / float64(c.totalHits+c.totalMisses))
		} else {
			c.hitRatioGauge.Set(0)
		}
	}

	now := time.Now()
	var oldestAge, youngestAge time.Duration
	var maxHits uint64
	var mostUsedKey string = "none" // Default if cache is empty

	if len(c.cache) > 0 {
		first := true
		for key, entry := range c.cache {
			// Age is calculated from the time it was supposed to expire minus its TTL
			// This gives the duration it has been in the cache.
			entryCreationTime := entry.Expiry.Add(-time.Duration(c.cacheTTLSeconds) * time.Second)
			age := now.Sub(entryCreationTime)

			if first {
				oldestAge = age
				youngestAge = age
				first = false
			}

			if age > oldestAge {
				oldestAge = age
			}
			if age < youngestAge {
				youngestAge = age
			}
			if entry.Hits > maxHits {
				maxHits = entry.Hits
				mostUsedKey = key
			}
		}
	} else {
		// Handle case for empty cache, set ages to 0 or some indicator
		oldestAge = 0
		youngestAge = 0
		maxHits = 0
	}

	if c.oldestEntryAgeGauge != nil {
		c.oldestEntryAgeGauge.Set(oldestAge.Seconds())
	}
	if c.youngestEntryAgeGauge != nil {
		c.youngestEntryAgeGauge.Set(youngestAge.Seconds())
	}
	// Clear previous most used entry if it's different or cache is empty
	// This is tricky with GaugeVec. A simpler approach for tests might be to not reset,
	// or only set if mostUsedKey is not "none".
	// For a real system, you might need to manage labels more carefully if they change often.
	if c.mostUsedEntryGaugeVec != nil && mostUsedKey != "none" {
		c.mostUsedEntryGaugeVec.WithLabelValues(mostUsedKey).Set(float64(maxHits))
	} else if c.mostUsedEntryGaugeVec != nil {
		// If cache is empty, perhaps reset the old "most used" if its hits are now 0,
		// or just leave it. For simplicity, we'll just not update if no key is most active.
		// Alternatively, find the previous mostUsedKey and set its gauge to 0 if it's no longer the most used.
		// This requires storing the previous mostUsedKey.
		// For now, we'll just update the current most used.
	}
}

// evictOldestInternal is the internal version of EvictOldest, assumes locks are held.
func (c *DNSCache) evictOldestInternal() {
	// This is a simplified version for internal call, actual logic is in EvictOldest
	// The public EvictOldest acquires lock and then calls this or similar logic
	// For now, direct call to the public EvictOldest logic structure is complex due to lock nuances
	// Re-evaluating if a separate internal is needed or if public can be called carefully.
	// For simplicity, we'll assume the main logic of eviction is complex enough to be in one place.
	// The public EvictOldest handles its own locking.
	// Let's refine: evictOldestInternal should contain the core logic without acquiring new locks.

	if c.totalSize <= c.cacheLimitBytes {
		return
	}

	type entryWithKey struct {
		key    string
		entry  *CacheEntry
		expiry time.Time
	}
	var entriesToSort []entryWithKey
	for k, e := range c.cache {
		entriesToSort = append(entriesToSort, entryWithKey{key: k, entry: e, expiry: e.Expiry})
	}

	// Sort entries: oldest first
	for i := 0; i < len(entriesToSort)-1; i++ {
		for j := i + 1; j < len(entriesToSort); j++ {
			if entriesToSort[i].expiry.After(entriesToSort[j].expiry) {
				entriesToSort[i], entriesToSort[j] = entriesToSort[j], entriesToSort[i]
			}
		}
	}

	for _, entryToDelete := range entriesToSort {
		if c.totalSize <= c.cacheLimitBytes {
			break
		}
		if actualEntry, exists := c.cache[entryToDelete.key]; exists && actualEntry == entryToDelete.entry {
			c.totalSize -= actualEntry.Size
			delete(c.cache, entryToDelete.key)
		}
	}
}

// GetStats returns current cache statistics.
func (c *DNSCache) GetStats() (entries int, totalSize int64, limit int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache), c.totalSize, c.cacheLimitBytes
}

// RunCacheCleanup periodically calls the Cleanup method on the provided DNSCache instance.
// The DNSCache instance is passed as CacheInterface to allow for testing with mocks if needed,
// though the Cleanup method itself is part of the concrete DNSCache type.
// For direct use with DNSCache, it's fine. If RunCacheCleanup needed to be tested
// independently with a mock cache that has a Cleanup method, then dc would need to be CacheInterface.
func RunCacheCleanup(dc *DNSCache, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				dc.Cleanup()
				// Add a way to stop this goroutine if the cache itself can be closed/destroyed.
				// For example, by checking a done channel on the DNSCache struct.
			}
		}
	}()
}

// CacheInterface defines the methods a cache should implement for DNS query processing
// and dynamic configuration updates.
type CacheInterface interface {
	Get(key string) (*CacheEntry, bool)
	Set(key string, spfRecord string, found bool)
	SetLimit(limit int64)
	SetTTL(ttlSeconds int)
	// EvictOldest() // Not strictly needed by ProcessDNSQuery for Handler, internal to cache
	// Cleanup()     // Called by RunCacheCleanup, internal to cache package scope
	// GetStats()    // For metrics or info, not directly by query processing logic for Handler
}

// SetLimit updates the cache size limit.
func (c *DNSCache) SetLimit(limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheLimitBytes = limit
	if c.limitBytesGauge != nil {
		c.limitBytesGauge.Set(float64(c.cacheLimitBytes))
	}
	// Trigger eviction immediately if new limit is smaller than current size
	c.evictOldestInternal()
	// Update other size-related metrics
	if c.entriesGauge != nil {
		c.entriesGauge.Set(float64(len(c.cache)))
	}
	if c.sizeBytesGauge != nil {
		c.sizeBytesGauge.Set(float64(c.totalSize))
	}
}

// SetTTL updates the cache TTL.
// Note: This only affects new entries. Existing entry expiry times are not changed.
func (c *DNSCache) SetTTL(ttlSeconds int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheTTLSeconds = ttlSeconds
}
