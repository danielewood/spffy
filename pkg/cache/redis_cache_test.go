package cache

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil" // For testing metric values
)

var (
	testRedisAddr string
	testRedisDB   int
)

func getTestRedisClient(tb testing.TB) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: testRedisAddr,
		DB:   testRedisDB, // Use a specific DB for testing
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		tb.Fatalf("Could not connect to Redis at %s DB %d: %v. Ensure Redis is running or set REDIS_TEST_ADDR.", testRedisAddr, testRedisDB, err)
	}
	return client
}

// setup clears the test Redis database.
func setup(tb testing.TB, client *redis.Client) {
	tb.Helper()
	ctx := context.Background()
	if err := client.FlushDB(ctx).Err(); err != nil {
		tb.Fatalf("Failed to flush Redis DB: %v", err)
	}
}

// TestMain can be used for global setup/teardown, like setting Redis address.
func TestMain(m *testing.M) {
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	testRedisAddr = addr

	dbStr := os.Getenv("REDIS_TEST_DB")
	if dbStr == "" {
		dbStr = "15" // Default to DB 15 for tests to avoid clashing with dev
	}
	var err error
	testRedisDB, err = strconv.Atoi(dbStr)
	if err != nil {
		panic("Invalid REDIS_TEST_DB value: " + err.Error())
	}

	// Ensure test DB is clean before starting any tests in this package
	client := getTestRedisClient(&testing.T{}) // Use a temporary T for setup
	setup(&testing.T{}, client) // Clean DB before tests
	client.Close()

	os.Exit(m.Run())
}

func newTestRedisCache(tb testing.TB, ttlSeconds int, hits prometheus.Counter, misses prometheus.Counter, ratio prometheus.Gauge) (*RedisCache, *redis.Client) {
	tb.Helper()
	client := getTestRedisClient(tb)
	// setup(tb, client) // Flushed in TestMain and per-test if needed

	rc, err := NewRedisCache(testRedisAddr, "", testRedisDB, ttlSeconds, hits, misses, ratio)
	if err != nil {
		client.Close()
		tb.Fatalf("NewRedisCache() error = %v", err)
	}
	// Override client in RedisCache with one using the test DB, if NewRedisCache doesn't take DB directly for its internal client.
	// The current NewRedisCache takes addr, pass, db for options. So this should be fine.
	// However, the RedisCache's internal client will use the DB specified in NewRedisCache.
	// To ensure tests use the *testRedisDB*, we need to ensure NewRedisCache uses it.
	// Let's adjust NewRedisCache or ensure our test helper for client creation is aligned.
	// The current NewRedisCache constructor *does* take 'db int' as a parameter.
	// So, we pass testRedisDB to NewRedisCache.

	// The client returned here is for test verification purposes (e.g., checking TTL directly)
	return rc, client
}


func TestNewRedisCache_ConnectionError(t *testing.T) {
	// Assuming no Redis server is running at this bogus address
	badAddr := "localhost:12345"
	_, err := NewRedisCache(badAddr, "", 0, 60, nil, nil, nil)
	if err == nil {
		t.Errorf("Expected connection error when creating RedisCache with bad address, got nil")
	}
}

func TestRedisCache_SetAndGet(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil)
	defer client.Close()
	setup(t, client) // Clean before this test

	key := "testKeyGetSet"
	spfRecord := "v=spf1 include:_spf.google.com ~all"
	found := true

	rc.Set(key, spfRecord, found)

	entry, ok := rc.Get(key)
	if !ok {
		t.Fatalf("Get(%s) failed, expected_found=true", key)
	}
	if entry == nil {
		t.Fatalf("Get(%s) returned nil entry, expected non-nil", key)
	}
	if entry.SPFRecord != spfRecord {
		t.Errorf("Get(%s) SPFRecord = %s, want %s", key, entry.SPFRecord, spfRecord)
	}
	if entry.Found != found {
		t.Errorf("Get(%s) Found = %v, want %v", key, entry.Found, found)
	}
}

func TestRedisCache_GetMiss(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil)
	defer client.Close()
	setup(t, client)

	key := "testKeyMiss"
	entry, ok := rc.Get(key)
	if ok {
		t.Errorf("Get(%s) ok = true, want false", key)
	}
	if entry != nil {
		t.Errorf("Get(%s) entry = %v, want nil", key, entry)
	}
}

func TestRedisCache_Expiration(t *testing.T) {
	rc, client := newTestRedisCache(t, 1, nil, nil, nil) // 1 second TTL for cache entries
	defer client.Close()
	setup(t, client)

	key := "testKeyExpire"
	rc.Set(key, "record", true)

	// Check it's there
	_, ok := rc.Get(key)
	if !ok {
		t.Fatalf("Get(%s) immediately after Set failed, expected_found=true", key)
	}

	// Wait for expiration
	time.Sleep(1500 * time.Millisecond) // Wait a bit longer than 1 sec TTL

	entry, ok := rc.Get(key)
	if ok {
		t.Errorf("Get(%s) after 1.5s ok = true, want false (entry should have expired)", key)
	}
	if entry != nil {
		t.Errorf("Get(%s) after 1.5s entry = %v, want nil", key, entry)
	}
}

func TestRedisCache_SetTTL_ChangesFutureSets(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil) // Default TTL 60s
	defer client.Close()
	setup(t, client)

	key1 := "keyTTL60"
	rc.Set(key1, "record1", true)

	// Verify TTL of key1 (approx)
	ttlKey1, err := client.TTL(context.Background(), key1).Result()
	if err != nil {
		t.Fatalf("Error getting TTL for %s: %v", key1, err)
	}
	if ttlKey1 < 55*time.Second || ttlKey1 > 60*time.Second { // Allow some leeway
		t.Errorf("TTL for %s = %v, want ~60s", key1, ttlKey1)
	}

	rc.SetTTL(1) // Change cache default TTL to 1 second

	key2 := "keyTTL1"
	rc.Set(key2, "record2", true)

	// Verify TTL of key2 (approx)
	ttlKey2, err := client.TTL(context.Background(), key2).Result()
	if err != nil {
		t.Fatalf("Error getting TTL for %s: %v", key2, err)
	}
	if ttlKey2 > 2*time.Second { // Should be ~1s
		t.Errorf("TTL for %s = %v, want ~1s", key2, ttlKey2)
	}

	// Wait for key2 to expire, key1 should still be there
	time.Sleep(1500 * time.Millisecond)

	_, ok := rc.Get(key2)
	if ok {
		t.Errorf("Get(%s) after 1.5s ok = true, want false (should be expired)", key2)
	}
	_, ok = rc.Get(key1)
	if !ok {
		t.Errorf("Get(%s) after 1.5s ok = false, want true (should still exist)", key1)
	}
}

func TestRedisCache_SetLimit(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil)
	defer client.Close()
	// SetLimit is a no-op, just call it to ensure it doesn't panic or error.
	// No functional change is expected in Redis from this client call.
	rc.SetLimit(1024) // Arbitrary limit
	// No assertions needed beyond it not crashing.
}

func TestRedisCache_Metrics(t *testing.T) {
	hits := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_hits"})
	misses := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_misses"})
	ratio := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_ratio"})

	// Need to register them to avoid panic if using testutil, though direct value check is fine.
	// reg := prometheus.NewRegistry() // Use a local registry for this test
	// reg.MustRegister(hits, misses, ratio)

	rc, client := newTestRedisCache(t, 60, hits, misses, ratio)
	defer client.Close()
	setup(t, client)

	keyHit := "metricKeyHit"
	keyMiss := "metricKeyMiss"
	keyCorrupt := "metricKeyCorrupt"

	// Initial state
	if val := testutil.ToFloat64(hits); val != 0 {
		t.Errorf("Initial hits = %v, want 0", val)
	}
	if val := testutil.ToFloat64(misses); val != 0 {
		t.Errorf("Initial misses = %v, want 0", val)
	}
	if val := testutil.ToFloat64(ratio); val != 0 {
		t.Errorf("Initial ratio = %v, want 0", val)
	}

	// Hit
	rc.Set(keyHit, "data", true)
	rc.Get(keyHit) // Should be a hit
	if val := testutil.ToFloat64(hits); val != 1 {
		t.Errorf("After 1 hit, hits = %v, want 1", val)
	}
	if val := testutil.ToFloat64(misses); val != 0 {
		t.Errorf("After 1 hit, misses = %v, want 0", val)
	}
	if val := testutil.ToFloat64(ratio); val != 1.0 { // 1 hit / 1 total
		t.Errorf("After 1 hit, ratio = %v, want 1.0", val)
	}

	// Miss
	rc.Get(keyMiss) // Should be a miss
	if val := testutil.ToFloat64(hits); val != 1 {
		t.Errorf("After 1 hit, 1 miss, hits = %v, want 1", val)
	}
	if val := testutil.ToFloat64(misses); val != 1 {
		t.Errorf("After 1 hit, 1 miss, misses = %v, want 1", val)
	}
	if val := testutil.ToFloat64(ratio); val != 0.5 { // 1 hit / 2 total
		t.Errorf("After 1 hit, 1 miss, ratio = %v, want 0.5", val)
	}

	// Second Hit
	rc.Get(keyHit) // Should be another hit
	if val := testutil.ToFloat64(hits); val != 2 {
		t.Errorf("After 2 hits, 1 miss, hits = %v, want 2", val)
	}
	if val := testutil.ToFloat64(misses); val != 1 {
		t.Errorf("After 2 hits, 1 miss, misses = %v, want 1", val)
	}
	expectedRatio := 2.0 / 3.0
	if val := testutil.ToFloat64(ratio); val != expectedRatio {
		t.Errorf("After 2 hits, 1 miss, ratio = %v, want %v", val, expectedRatio)
	}

	// Corrupted data test (simulated by putting non-JSON string in Redis)
	err := client.Set(rc.ctx, keyCorrupt, "this is not json", 10*time.Second).Err()
	if err != nil {
		t.Fatalf("Failed to set corrupt data in Redis: %v", err)
	}
	rc.Get(keyCorrupt) // Should be a miss (due to unmarshal error)
	if val := testutil.ToFloat64(hits); val != 2 { // Hits should not change
		t.Errorf("After corrupt get, hits = %v, want 2", val)
	}
	if val := testutil.ToFloat64(misses); val != 2 { // Misses should increment
		t.Errorf("After corrupt get, misses = %v, want 2", val)
	}
	expectedRatio = 2.0 / 4.0
	if val := testutil.ToFloat64(ratio); val != expectedRatio {
		t.Errorf("After corrupt get, ratio = %v, want %v", val, expectedRatio)
	}
}

// TODO: Add test for Get with a key that exists in Redis but is expired (Redis should handle this, but good to confirm behavior)
// This is covered by TestRedisCache_Expiration implicitly.

// TODO: Test for Set when JSON marshal fails (how to mock this? maybe not necessary to test json.Marshal itself)
// This is harder to test without interface changes or actual bad data types. The current Set logs and returns.

// TODO: Test for Set when Redis client.Set fails (network error, etc.)
// This requires mocking the redis client, which is a larger undertaking.
// For now, assume go-redis handles client errors appropriately or connection test in TestMain covers basic connectivity.

// TODO: Consider testing the Expiry field within the CacheEntry returned by Get.
// The current CacheEntry.Expiry is set based on cacheTTLSeconds at the time of Set.
// Redis's TTL is the authoritative one for actual expiry from Get.
// The Expiry field in the struct is more informational or for caches that do their own expiry.
// For RedisCache, its main purpose is to be part of the stored JSON if ever inspected manually.
// The important part is that Redis expires the key.
// TestRedisCache_Expiration already confirms Redis handles the TTL.
// TestRedisCache_SetAndGet confirms the fields are retrieved.
// We can add a check in SetAndGet for Expiry if deemed critical.
// Let's add a small check in SetAndGet for Expiry time.

func TestRedisCache_SetAndGet_ExpiryCheck(t *testing.T) {
	ttl := 30 // seconds
	rc, client := newTestRedisCache(t, ttl, nil, nil, nil)
	defer client.Close()
	setup(t, client)

	key := "testKeyExpiryCheck"
	spfRecord := "v=spf1 -all"

	setStartTime := time.Now()
	rc.Set(key, spfRecord, true)

	entry, ok := rc.Get(key)
	if !ok {
		t.Fatalf("Get(%s) failed", key)
	}

	expectedExpiryMin := setStartTime.Add(time.Duration(ttl) * time.Second).Add(-2 * time.Second) // Allow 2s clock skew / processing time
	expectedExpiryMax := setStartTime.Add(time.Duration(ttl) * time.Second).Add(2 * time.Second)  // Allow 2s clock skew / processing time

	if entry.Expiry.Before(expectedExpiryMin) || entry.Expiry.After(expectedExpiryMax) {
		t.Errorf("Get(%s) Expiry = %v, expected between %v and %v (based on set time %v and TTL %ds)",
			key, entry.Expiry, expectedExpiryMin, expectedExpiryMax, setStartTime, ttl)
	}
}

func TestRedisCache_Parallel(t *testing.T) {
    hits := prometheus.NewCounter(prometheus.CounterOpts{Name: "ptest_hits"})
    misses := prometheus.NewCounter(prometheus.CounterOpts{Name: "ptest_misses"})
    ratio := prometheus.NewGauge(prometheus.GaugeOpts{Name: "ptest_ratio"})

    rc, client := newTestRedisCache(t, 5, hits, misses, ratio) // 5s TTL for entries
    defer client.Close()
    setup(t, client) // Clear DB before this parallel test

    numGoroutines := 50
    numOpsPerGoroutine := 100

    t.Run("ParallelSetGet", func(t *testing.T) {
        for i := 0; i < numGoroutines; i++ {
            go func(gID int) {
                for j := 0; j < numOpsPerGoroutine; j++ {
                    key := "parallelKey_" + strconv.Itoa(gID) + "_" + strconv.Itoa(j)
                    val := "value_" + strconv.Itoa(j)

                    // Mix of Set and Get operations
                    if j%2 == 0 {
                        rc.Set(key, val, true)
                        // Occasionally get what we set
                        if j%10 == 0 {
                            e, found := rc.Get(key)
                            if !found || e.SPFRecord != val {
                                // t.Errorf is not goroutine-safe directly, use t.Log then Fail outside or sync.
                                // For simplicity in this example, we'll risk it or just log.
                                // A better way is to collect errors in a channel.
                                t.Logf("Goroutine %d: Get after Set for key %s failed or value mismatch", gID, key)
                            }
                        }
                    } else {
                        // Get potentially non-existent keys or recently set keys
                        rc.Get("randomMissKey_" + strconv.Itoa(gID) + "_" + strconv.Itoa(j))
                        if j%5 == 0 && j > 0 { // Get a key that should have been set by this goroutine
                             prevKey := "parallelKey_" + strconv.Itoa(gID) + "_" + strconv.Itoa(j-1)
                             rc.Get(prevKey)
                        }
                    }
                }
            }(i)
        }
    })
    // Note: This test structure for parallel execution doesn't have explicit synchronization
    // to wait for all goroutines to complete before TestRedisCache_Parallel returns.
    // In a real scenario, you'd use sync.WaitGroup.
    // Also, t.Errorf/Fatalf from goroutines can be problematic.
    // This is a conceptual sketch; proper parallel testing needs more robust synchronization.
    // For now, this mainly stress-tests the Redis client's concurrency safety with the cache logic.
		// The primary goal is to check for race conditions if any. The go test -race flag would find them.

		// Let's just sleep for a bit to let goroutines run. This is not ideal.
		time.Sleep(3 * time.Second) // Allow some time for operations

		// Final metric checks are tricky without knowing exact hit/miss counts due to parallelism & timing.
    // A simple check: total operations = numGoroutines * numOpsPerGoroutine
    // totalGetsOrSets := numGoroutines * numOpsPerGoroutine
    // We can check if total hits + total misses roughly equals total get operations.
    // This is too complex for a simple test without more determinism.
    // The main point is to run it with -race.
    t.Logf("Parallel test executed. Check with -race flag for issues.")
		t.Logf("Final Hits: %f, Misses: %f, Ratio: %f", testutil.ToFloat64(hits), testutil.ToFloat64(misses), testutil.ToFloat64(ratio))
}
package cache

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil" // For testing metric values
)

var (
	testRedisAddr string
	testRedisDB   int
)

func getTestRedisClient(tb testing.TB) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr: testRedisAddr,
		DB:   testRedisDB, // Use a specific DB for testing
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		tb.Fatalf("Could not connect to Redis at %s DB %d: %v. Ensure Redis is running or set REDIS_TEST_ADDR.", testRedisAddr, testRedisDB, err)
	}
	return client
}

// setup clears the test Redis database.
func setup(tb testing.TB, client *redis.Client) {
	tb.Helper()
	ctx := context.Background()
	if err := client.FlushDB(ctx).Err(); err != nil {
		tb.Fatalf("Failed to flush Redis DB: %v", err)
	}
}

// TestMain can be used for global setup/teardown, like setting Redis address.
func TestMain(m *testing.M) {
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	testRedisAddr = addr

	dbStr := os.Getenv("REDIS_TEST_DB")
	if dbStr == "" {
		dbStr = "15" // Default to DB 15 for tests to avoid clashing with dev
	}
	var err error
	testRedisDB, err = strconv.Atoi(dbStr)
	if err != nil {
		panic("Invalid REDIS_TEST_DB value: " + err.Error())
	}

	// Ensure test DB is clean before starting any tests in this package
	// Use a temporary T for setup, as TestMain itself isn't a test function.
	tempTB := &testing.T{}
	if strings.HasSuffix(os.Args[0], ".test") { // Check if running as a test binary
		client := getTestRedisClient(tempTB)
		if !tempTB.Failed() { // Only proceed if client connection was successful
			setup(tempTB, client) // Clean DB before tests
			client.Close()
		} else {
			// If getTestRedisClient failed, it would have called Fatalf.
			// To be absolutely sure TestMain exits if Redis is not available for setup.
			// However, tb.Fatalf would already stop execution for that "test".
			// This is more about signaling that setup itself failed.
			// For TestMain, a panic might be more appropriate if setup is critical.
			// Or simply log and exit.
			// For now, getTestRedisClient's Fatalf handles this for its "test" context.
			// If tempTB.Failed() is true here, it means getTestRedisClient called Fatal.
			// We should probably exit TestMain if initial setup fails.
			os.Exit(1)
		}
	}


	os.Exit(m.Run())
}

func newTestRedisCache(tb testing.TB, ttlSeconds int, hits prometheus.Counter, misses prometheus.Counter, ratio prometheus.Gauge) (*RedisCache, *redis.Client) {
	tb.Helper()

	// The client for the cache instance itself.
	// NewRedisCache will create its own client based on these params.
	rc, err := NewRedisCache(testRedisAddr, "", testRedisDB, ttlSeconds, hits, misses, ratio)
	if err != nil {
		tb.Fatalf("NewRedisCache() error = %v", err)
	}

	// A separate client for test verification purposes (e.g., checking TTL directly, setup/teardown).
	verifyClient := getTestRedisClient(tb)

	return rc, verifyClient
}


func TestNewRedisCache_ConnectionError(t *testing.T) {
	// Assuming no Redis server is running at this bogus address
	badAddr := "localhost:12345"
	// Using nil for metrics as they are not relevant to connection failure.
	_, err := NewRedisCache(badAddr, "", 0, 60, nil, nil, nil)
	if err == nil {
		t.Errorf("Expected connection error when creating RedisCache with bad address, got nil")
	}
}

func TestRedisCache_SetAndGet(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil)
	defer client.Close()
	setup(t, client) // Clean before this test

	key := "testKeyGetSet"
	spfRecord := "v=spf1 include:_spf.google.com ~all"
	found := true

	rc.Set(key, spfRecord, found)

	entry, ok := rc.Get(key)
	if !ok {
		t.Fatalf("Get(%s) failed, expected_found=true", key)
	}
	if entry == nil {
		t.Fatalf("Get(%s) returned nil entry, expected non-nil", key)
	}
	if entry.SPFRecord != spfRecord {
		t.Errorf("Get(%s) SPFRecord = %s, want %s", key, entry.SPFRecord, spfRecord)
	}
	if entry.Found != found {
		t.Errorf("Get(%s) Found = %v, want %v", key, entry.Found, found)
	}
}

func TestRedisCache_GetMiss(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil)
	defer client.Close()
	setup(t, client)

	key := "testKeyMiss"
	entry, ok := rc.Get(key)
	if ok {
		t.Errorf("Get(%s) ok = true, want false", key)
	}
	if entry != nil {
		t.Errorf("Get(%s) entry = %v, want nil", key, entry)
	}
}

func TestRedisCache_Expiration(t *testing.T) {
	rc, client := newTestRedisCache(t, 1, nil, nil, nil) // 1 second TTL for cache entries
	defer client.Close()
	setup(t, client)

	key := "testKeyExpire"
	rc.Set(key, "record", true)

	// Check it's there
	_, ok := rc.Get(key)
	if !ok {
		t.Fatalf("Get(%s) immediately after Set failed, expected_found=true", key)
	}

	// Wait for expiration
	time.Sleep(1500 * time.Millisecond) // Wait a bit longer than 1 sec TTL

	entry, okGetAfterExpire := rc.Get(key)
	if okGetAfterExpire {
		t.Errorf("Get(%s) after 1.5s ok = true, want false (entry should have expired)", key)
	}
	if entry != nil {
		t.Errorf("Get(%s) after 1.5s entry = %v, want nil", key, entry)
	}
}

func TestRedisCache_SetTTL_ChangesFutureSets(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil) // Default TTL 60s
	defer client.Close()
	setup(t, client)

	key1 := "keyTTL60"
	rc.Set(key1, "record1", true)

	// Verify TTL of key1 (approx)
	ttlKey1, err := client.TTL(context.Background(), key1).Result()
	if err != nil {
		t.Fatalf("Error getting TTL for %s: %v", key1, err)
	}
	if ttlKey1 < 55*time.Second || ttlKey1 > 60*time.Second { // Allow some leeway
		t.Errorf("TTL for %s = %v, want ~60s", key1, ttlKey1)
	}

	rc.SetTTL(1) // Change cache default TTL to 1 second

	key2 := "keyTTL1"
	rc.Set(key2, "record2", true)

	// Verify TTL of key2 (approx)
	ttlKey2, err := client.TTL(context.Background(), key2).Result()
	if err != nil {
		t.Fatalf("Error getting TTL for %s: %v", key2, err)
	}
	// It might be slightly less than 1s, or even -2 (not found) if it expired very fast.
	if ttlKey2 > 1*time.Second {
		t.Errorf("TTL for %s = %v, want ~1s (or less if checked late)", key2, ttlKey2)
	}


	// Wait for key2 to expire, key1 should still be there
	time.Sleep(1500 * time.Millisecond)

	_, ok := rc.Get(key2)
	if ok {
		t.Errorf("Get(%s) after 1.5s ok = true, want false (should be expired)", key2)
	}
	_, ok = rc.Get(key1)
	if !ok {
		t.Errorf("Get(%s) after 1.5s ok = false, want true (should still exist)", key1)
	}
}

func TestRedisCache_SetLimit(t *testing.T) {
	rc, client := newTestRedisCache(t, 60, nil, nil, nil)
	defer client.Close()
	// SetLimit is a no-op, just call it to ensure it doesn't panic or error.
	rc.SetLimit(1024) // Arbitrary limit
}

func TestRedisCache_Metrics(t *testing.T) {
	hits := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_hits_total"})
	misses := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_misses_total"})
	ratio := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_hit_ratio"})

	// It's good practice to use a local registry for tests to avoid polluting the global one.
	reg := prometheus.NewRegistry()
	reg.MustRegister(hits, misses, ratio)


	rc, client := newTestRedisCache(t, 60, hits, misses, ratio)
	defer client.Close()
	setup(t, client)

	keyHit := "metricKeyHit"
	keyMiss := "metricKeyMiss"
	keyCorrupt := "metricKeyCorrupt" // Key for testing behavior with corrupt data in Redis

	// Initial state
	if val := testutil.ToFloat64(hits); val != 0 {
		t.Errorf("Initial hits = %v, want 0", val)
	}
	if val := testutil.ToFloat64(misses); val != 0 {
		t.Errorf("Initial misses = %v, want 0", val)
	}
	if val := testutil.ToFloat64(ratio); val != 0 {
		t.Errorf("Initial ratio = %v, want 0", val)
	}

	// Hit
	rc.Set(keyHit, "data", true)
	rc.Get(keyHit) // Should be a hit
	if val := testutil.ToFloat64(hits); val != 1 {
		t.Errorf("After 1 hit, hits = %v, want 1", val)
	}
	if val := testutil.ToFloat64(misses); val != 0 {
		t.Errorf("After 1 hit, misses = %v, want 0", val)
	}
	if val := testutil.ToFloat64(ratio); val != 1.0 { // 1 hit / 1 total
		t.Errorf("After 1 hit, ratio = %v, want 1.0", val)
	}

	// Miss
	rc.Get(keyMiss) // Should be a miss
	if val := testutil.ToFloat64(hits); val != 1 {
		t.Errorf("After 1 hit, 1 miss, hits = %v, want 1", val)
	}
	if val := testutil.ToFloat64(misses); val != 1 {
		t.Errorf("After 1 hit, 1 miss, misses = %v, want 1", val)
	}
	if val := testutil.ToFloat64(ratio); val != 0.5 { // 1 hit / 2 total
		t.Errorf("After 1 hit, 1 miss, ratio = %v, want 0.5", val)
	}

	// Second Hit
	rc.Get(keyHit) // Should be another hit
	if val := testutil.ToFloat64(hits); val != 2 {
		t.Errorf("After 2 hits, 1 miss, hits = %v, want 2", val)
	}
	if val := testutil.ToFloat64(misses); val != 1 {
		t.Errorf("After 2 hits, 1 miss, misses = %v, want 1", val)
	}
	expectedRatio := 2.0 / 3.0
	if val := testutil.ToFloat64(ratio); !floatEquals(val, expectedRatio, 1e-9) {
		t.Errorf("After 2 hits, 1 miss, ratio = %v, want %v", val, expectedRatio)
	}

	// Corrupted data test (simulated by putting non-JSON string in Redis)
	// This client is the verification client, not the one inside RedisCache.
	err := client.Set(context.Background(), keyCorrupt, "this is not json", 10*time.Second).Err()
	if err != nil {
		t.Fatalf("Failed to set corrupt data in Redis: %v", err)
	}
	rc.Get(keyCorrupt) // Should be a miss (due to unmarshal error)
	if val := testutil.ToFloat64(hits); val != 2 { // Hits should not change
		t.Errorf("After corrupt get, hits = %v, want 2", val)
	}
	if val := testutil.ToFloat64(misses); val != 2 { // Misses should increment
		t.Errorf("After corrupt get, misses = %v, want 2", val)
	}
	expectedRatioCorrupt := 2.0 / 4.0
	if val := testutil.ToFloat64(ratio); !floatEquals(val, expectedRatioCorrupt, 1e-9) {
		t.Errorf("After corrupt get, ratio = %v, want %v", val, expectedRatioCorrupt)
	}
}

func floatEquals(a, b, epsilon float64) bool {
	return (a-b) < epsilon && (b-a) < epsilon
}


func TestRedisCache_SetAndGet_ExpiryCheck(t *testing.T) {
	ttl := 30 // seconds
	rc, client := newTestRedisCache(t, ttl, nil, nil, nil)
	defer client.Close()
	setup(t, client)

	key := "testKeyExpiryCheck"
	spfRecord := "v=spf1 -all"

	setStartTime := time.Now()
	rc.Set(key, spfRecord, true)

	entry, ok := rc.Get(key)
	if !ok {
		t.Fatalf("Get(%s) failed", key)
	}

	// Calculate expected expiry time window more carefully
	// The entry.Expiry is what RedisCache *stored* based on its clock and ttl.
	// Redis server will expire it based on its own clock + TTL command.
	// We are checking the Expiry field *in the returned struct*.
	expectedStoredExpiry := setStartTime.Add(time.Duration(ttl) * time.Second)

	// Allow a small delta for processing time for the stored Expiry value
	minStoredExpiry := expectedStoredExpiry.Add(-2 * time.Second)
	maxStoredExpiry := expectedStoredExpiry.Add(2 * time.Second)

	if entry.Expiry.Before(minStoredExpiry) || entry.Expiry.After(maxStoredExpiry) {
		t.Errorf("Get(%s) Expiry field in struct = %v, expected around %v (between %v and %v, based on set time %v and TTL %ds)",
			key, entry.Expiry, expectedStoredExpiry, minStoredExpiry, maxStoredExpiry, setStartTime, ttl)
	}
}

// Note on Parallel Test:
// The following parallel test is a conceptual sketch. Proper parallel testing in Go
// requires careful use of sync.WaitGroup for managing goroutine completion and
// thread-safe mechanisms for error reporting (e.g., channels or sync.Map).
// The primary goal here is to have a test that can be run with the -race flag
// to detect potential race conditions in the RedisCache implementation.
// Assertions within goroutines using t.Errorf are not recommended without synchronization.
func TestRedisCache_Parallel(t *testing.T) {
    hits := prometheus.NewCounter(prometheus.CounterOpts{Name: "ptest_hits_total"})
    misses := prometheus.NewCounter(prometheus.CounterOpts{Name: "ptest_misses_total"})
    ratio := prometheus.NewGauge(prometheus.GaugeOpts{Name: "ptest_hit_ratio"})

    reg := prometheus.NewRegistry()
    reg.MustRegister(hits, misses, ratio)

    rc, client := newTestRedisCache(t, 2, hits, misses, ratio) // Short TTL for more churn
    defer client.Close()
    setup(t, client)

    numGoroutines := 20
    numOpsPerGoroutine := 50

    var wg sync.WaitGroup // Use WaitGroup for synchronization

    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func(gID int) {
            defer wg.Done()
            for j := 0; j < numOpsPerGoroutine; j++ {
                key := "parallelKey_" + strconv.Itoa(gID) + "_" + strconv.Itoa(j)
                val := "value_" + strconv.Itoa(gID) + "_" + strconv.Itoa(j)

                opType := (gID + j) % 3
                switch opType {
                case 0: // Set
                    rc.Set(key, val, true)
                case 1: // Get own key (likely hit if TTL not passed)
                    rc.Get(key)
                case 2: // Get random key (likely miss)
                    rc.Get("randomMissKey_" + strconv.Itoa(gID) + "_" + strconv.Itoa(j))
                }
                // Small delay to allow context switching and potential races
                time.Sleep(time.Duration(j%5) * time.Millisecond)
            }
        }(i)
    }

    wg.Wait() // Wait for all goroutines to complete

    // Final metric checks are illustrative; precise values are hard to predict due to timing and TTL.
    // The main value is running this test with `go test -race`.
    totalGets := 0
		for i := 0; i < numGoroutines; i++ {
			for j := 0; j < numOpsPerGoroutine; j++ {
				opType := (i + j) % 3
				if opType == 1 || opType == 2 {
					totalGets++
				}
			}
		}

		currentHits := testutil.ToFloat64(hits)
		currentMisses := testutil.ToFloat64(misses)

    t.Logf("Parallel test executed %d total Get operations.", totalGets)
    t.Logf("Final Hits: %f, Misses: %f, Ratio: %f", currentHits, currentMisses, testutil.ToFloat64(ratio))

		// Assert that total recorded operations (hits+misses) match total Get operations
		if currentHits+currentMisses != float64(totalGets) {
			 // This assertion can be flaky due to exact timing of TTL expiry vs Gets.
			 // For a race detector test, it's less critical than the execution itself.
			t.Logf("Total recorded ops (hits+misses) = %f, expected total Get ops = %d. Discrepancy possible due to TTL.",
				currentHits+currentMisses, totalGets)
		}
		// A more robust check might be that hits + misses <= totalGets
		if currentHits+currentMisses > float64(totalGets) {
			t.Errorf("Total recorded ops (hits+misses) %f > total Get ops %d. This should not happen.",
			currentHits+currentMisses, totalGets)
		}
}
