package cache

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Helper function to get gauge value for testing
func getGaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	g.Write(m)
	return m.GetGauge().GetValue()
}

// Helper function to get counter value for testing
func getCounterValue(c prometheus.Counter) float64 {
	m := &dto.Metric{}
	c.Write(m)
	return m.GetCounter().GetValue()
}

func newTestMetrics() (prometheus.Gauge, prometheus.Gauge, prometheus.Gauge, prometheus.Gauge, prometheus.Gauge, prometheus.Gauge, *prometheus.GaugeVec, prometheus.Counter, prometheus.Counter) {
	entriesGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_cache_entries"})
	sizeBytesGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_cache_size_bytes"})
	limitBytesGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_cache_limit_bytes"})
	hitRatioGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_cache_hit_ratio"})
	oldestEntryAgeGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_cache_oldest_entry_age_seconds"})
	youngestEntryAgeGauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_cache_youngest_entry_age_seconds"})
	mostUsedEntryGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_cache_most_used_entry"}, []string{"key"})
	hitsTotalCounter := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_cache_hits_total"})
	missesTotalCounter := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_cache_misses_total"})
	return entriesGauge, sizeBytesGauge, limitBytesGauge, hitRatioGauge, oldestEntryAgeGauge, youngestEntryAgeGauge, mostUsedEntryGaugeVec, hitsTotalCounter, missesTotalCounter
}

func TestNewDNSCache(t *testing.T) {
	ttl := 300
	limit := int64(1024)
	eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc := newTestMetrics()

	dc := NewDNSCache(ttl, limit, eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc)

	if dc == nil {
		t.Fatal("NewDNSCache returned nil")
	}
	if dc.cacheTTLSeconds != ttl {
		t.Errorf("cacheTTLSeconds = %d; want %d", dc.cacheTTLSeconds, ttl)
	}
	if dc.cacheLimitBytes != limit {
		t.Errorf("cacheLimitBytes = %d; want %d", dc.cacheLimitBytes, limit)
	}
	if getGaugeValue(dc.limitBytesGauge) != float64(limit) {
		t.Errorf("limitBytesGauge was not set correctly: got %f, want %f", getGaugeValue(dc.limitBytesGauge), float64(limit))
	}
	if dc.cache == nil {
		t.Error("cache map was not initialized")
	}
}

func TestDNSCache_SetAndGet(t *testing.T) {
	eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc := newTestMetrics()
	dc := NewDNSCache(60, 1024, eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc)

	key := "example.com|1.2.3.4"
	spfRecord := "v=spf1 mx -all"
	foundInSPF := true

	// 1. Test Set and basic Get
	dc.Set(key, spfRecord, foundInSPF)
	entry, found := dc.Get(key)
	if !found {
		t.Fatalf("Get() after Set() failed, entry not found for key: %s", key)
	}
	if entry.SPFRecord != spfRecord {
		t.Errorf("entry.SPFRecord = %s; want %s", entry.SPFRecord, spfRecord)
	}
	if entry.Found != foundInSPF {
		t.Errorf("entry.Found = %v; want %v", entry.Found, foundInSPF)
	}
	if getCounterValue(htc) != 1 {
		t.Errorf("cacheHitsTotalCounter = %f; want 1", getCounterValue(htc))
	}
	if getGaugeValue(eg) != 1 {
		t.Errorf("entriesGauge = %f; want 1", getGaugeValue(eg))
	}

	// 2. Test Get miss
	_, found = dc.Get("nonexistent.com|1.2.3.4")
	if found {
		t.Error("Get() for nonexistent key succeeded unexpectedly")
	}
	if getCounterValue(mtc) != 1 {
		t.Errorf("cacheMissesTotalCounter = %f; want 1 after miss", getCounterValue(mtc))
	}

	// 3. Test Expiry
	// For expiry, create a new cache instance with new metrics to ensure clean counts
	expEg, expSbg, expLbg, expHrg, expOag, expYag, expMuegv, expHtc, expMtc := newTestMetrics()
	dcExpiry := NewDNSCache(1, 1024, expEg, expSbg, expLbg, expHrg, expOag, expYag, expMuegv, expHtc, expMtc) // 1 second TTL
	dcExpiry.Set(key, spfRecord, foundInSPF)                                                                  // This will inc expHtc once due to Get within Set if entry exists (it doesn't first time)
	// Actually, Set itself doesn't call Get. It's Get that increments hit/miss.
	// So after Set, no hit/miss counter change.

	time.Sleep(1500 * time.Millisecond) // Wait for entry to expire

	entry, found = dcExpiry.Get(key)
	if found {
		t.Errorf("Get() after expiry succeeded unexpectedly; entry: %+v", entry)
	}
	if getCounterValue(expMtc) != 1 {
		t.Errorf("cacheMissesTotalCounter after expiry = %f; want 1", getCounterValue(expMtc))
	}
	if getCounterValue(expHtc) != 0 { // Should not be a hit
		t.Errorf("cacheHitsTotalCounter after expiry = %f; want 0", getCounterValue(expHtc))
	}
}

func TestDNSCache_EvictOldest(t *testing.T) {
	eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc := newTestMetrics()
	// Set a small limit to easily trigger eviction. calcEntrySize("k","v") is approx 40-50 bytes.
	// Let's assume entry size is ~50 bytes. Limit to 120 bytes (should fit 2 entries).
	dc := NewDNSCache(300, 120, eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc)

	dc.Set("key1", "val1_loooong", true)  // ~50-60
	time.Sleep(5 * time.Millisecond)      // Ensure key1 is older than key2
	dc.Set("key2", "val2_loooong", false) // ~50-60

	if len(dc.cache) != 2 {
		t.Fatalf("Expected 2 entries before eviction trigger, got %d", len(dc.cache))
	}

	time.Sleep(5 * time.Millisecond)     // Ensure key2 is older than key3
	dc.Set("key3", "val3_loooong", true) // This should trigger eviction of key1

	if len(dc.cache) != 2 {
		t.Errorf("Expected 2 entries after eviction, got %d. Cache: %v", len(dc.cache), dc.cache)
	}
	if _, found := dc.cache["key1"]; found {
		t.Error("key1 was not evicted")
	}
	if _, found := dc.cache["key2"]; !found {
		t.Error("key2 was evicted unexpectedly")
	}
	if _, found := dc.cache["key3"]; !found {
		t.Error("key3 was not added or was evicted unexpectedly")
	}
	// key1 should be evicted, key2 and key3 should remain.
	if _, found := dc.cache["key1"]; found {
		t.Error("key1 was not evicted as expected")
	}

	currentSize := getGaugeValue(sbg)
	if currentSize > float64(dc.cacheLimitBytes) {
		t.Errorf("Cache size %f exceeds limit %d after eviction", currentSize, dc.cacheLimitBytes)
	}

	// Test evicting multiple entries
	// At this point, cache has key2 (size 58) and key3 (size 58). key2 is older. Total size 116. Limit 120.
	time.Sleep(5 * time.Millisecond)          // Ensure key3 is older than key4
	key4Val := "val4_very_very_loooooooooong" // len=30. size = 4+30+24+1+8+8 = 75
	dc.Set("key4", key4Val, true)
	// Adding key4 (75) to current 116 would be 191.
	// To stay under 120, need to remove items.
	// Evict key2 (oldest): 191 - 58 = 133. Still > 120.
	// Evict key3 (next oldest): 133 - 58 = 75. Now <= 120.
	// So, cache should only contain key4.

	if len(dc.cache) != 1 {
		t.Errorf("Expected 1 entry after second eviction (only key4), got %d. Cache: %v", len(dc.cache), dc.cache)
	}
	if _, found := dc.cache["key2"]; found {
		t.Error("key2 was not evicted on second pass as expected")
	}
	if _, found := dc.cache["key3"]; found { // key3 should also be evicted
		t.Error("key3 was not evicted on second pass as expected (to make space for key4)")
	}
	if _, found := dc.cache["key4"]; !found {
		t.Error("key4 was not added or was evicted unexpectedly on second pass")
	}
}

func TestCalcEntrySize(t *testing.T) {
	// Basic check, as it's an estimation
	size1 := calcEntrySize("example.com", "v=spf1 -all")
	if size1 < 20 || size1 > 100 { // Rough expected range
		t.Errorf("calcEntrySize returned unexpected size: %d", size1)
	}
	size2 := calcEntrySize("short", "short")
	if size2 > size1 {
		t.Errorf("calcEntrySize for shorter strings (%d) was larger than for longer strings (%d)", size2, size1)
	}
}

func TestDNSCache_Cleanup(t *testing.T) {
	eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc := newTestMetrics()
	dc := NewDNSCache(1, 1024, eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc) // 1 second TTL

	dc.Set("key1", "val1", true)
	dc.Set("key2", "val2", true)

	if len(dc.cache) != 2 {
		t.Fatal("Expected 2 entries before cleanup")
	}

	time.Sleep(1500 * time.Millisecond) // Wait for entries to expire
	dc.Cleanup()

	if len(dc.cache) != 0 {
		t.Errorf("Expected 0 entries after Cleanup, got %d. Cache: %v", len(dc.cache), dc.cache)
	}
	if getGaugeValue(eg) != 0 {
		t.Errorf("entriesGauge = %f after cleanup; want 0", getGaugeValue(eg))
	}
}

// Test for RunCacheCleanup is harder as it involves a long-running goroutine.
// We can test the Cleanup method itself (as done above).
// To test RunCacheCleanup, one might need to use channels to signal cleanup completion
// or mock time, which is more involved. For now, direct test of Cleanup method is sufficient.

func TestDNSCache_UpdateMetrics(t *testing.T) {
	eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc := newTestMetrics()
	dc := NewDNSCache(60, 1024, eg, sbg, lbg, hrg, oag, yag, muegv, htc, mtc)

	// Initial state
	dc.updateCacheMetricsInternal() // Call directly for testing this unit
	if getGaugeValue(hrg) != 0 {
		t.Errorf("Initial HitRatio = %f; want 0", getGaugeValue(hrg))
	}
	if getGaugeValue(oag) != 0 {
		t.Errorf("Initial OldestAge = %f; want 0", getGaugeValue(oag))
	}
	if getGaugeValue(yag) != 0 {
		t.Errorf("Initial YoungestAge = %f; want 0", getGaugeValue(yag))
	}

	// Add one entry
	dc.Set("key1", "v1", true) // This calls updateCacheMetricsInternal via Set
	// After Set, metrics are updated. Let's call it again to be sure about the state we test.
	// dc.updateCacheMetricsInternal() // Not needed as Set calls it.

	if getGaugeValue(hrg) != 0 { // 0 hits, 0 misses initially from Set, then 0 hits / 0 misses = 0 ratio.
		t.Errorf("HitRatio after 1 set = %f; want 0 or NaN, check prometheus behavior for 0/0", getGaugeValue(hrg))
	}
	// Ages will be non-zero and positive.
	if getGaugeValue(oag) <= 0 {
		t.Errorf("OldestAge after 1 set = %f; want >0", getGaugeValue(oag))
	}
	if getGaugeValue(yag) <= 0 {
		t.Errorf("YoungestAge after 1 set = %f; want >0", getGaugeValue(yag))
	}

	// Simulate a hit
	dc.Get("key1") // This calls updateCacheMetricsInternal via Get
	if getGaugeValue(hrg) != 1.0 {
		t.Errorf("HitRatio after 1 hit = %f; want 1.0", getGaugeValue(hrg))
	} // 1 hit / 1 total = 1.0

	// Simulate a miss
	dc.Get("key2_miss") // This calls updateCacheMetricsInternal via Get
	if val := getGaugeValue(hrg); val != 0.5 {
		t.Errorf("HitRatio after 1 hit, 1 miss = %f; want 0.5", val)
	} // 1 hit / 2 total = 0.5

	// Test most used entry (key1 should be it)
	// Need to inspect muegv. This is harder with the test helper.
	// For now, we assume WithLabelValues().Set() works if other metrics are fine.
	// A more detailed test would involve iterating over metrics from a test registry.
}
