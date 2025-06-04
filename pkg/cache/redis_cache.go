package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
)

// redisCacheEntry is used for storing data in Redis.
// Note: The original CacheEntry contains Size and Hits which are not directly translated here.
// Expiry is stored for potential out-of-band checks but Redis TTL is the primary mechanism.
type redisCacheEntry struct {
	SPFRecord string    `json:"spfRecord"`
	Expiry    time.Time `json:"expiry"` // Store expiry for data integrity, though Redis TTL is primary
	Found     bool      `json:"found"`
}

// RedisCache implements the CacheInterface using Redis.
type RedisCache struct {
	client             *redis.Client
	ctx                context.Context
	cacheTTLSeconds    int
	hitsTotalCounter   prometheus.Counter
	missesTotalCounter prometheus.Counter
	hitRatioGauge      prometheus.Gauge
	totalHits          uint64
	totalMisses        uint64
}

// NewRedisCache creates a new RedisCache instance.
// addr is the Redis server address (e.g., "localhost:6379").
// password is the Redis password (empty if none).
// db is the Redis database number.
// ttlSeconds is the default TTL for cache entries.
// hitsCounter, missesCounter, hitRatio are Prometheus metrics.
func NewRedisCache(
	addr, password string,
	db int,
	ttlSeconds int,
	hitsCounter prometheus.Counter,
	missesCounter prometheus.Counter,
	hitRatio prometheus.Gauge,
) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return &RedisCache{
		client:             rdb,
		ctx:                ctx,
		cacheTTLSeconds:    ttlSeconds,
		hitsTotalCounter:   hitsCounter,
		missesTotalCounter: missesCounter,
		hitRatioGauge:      hitRatio,
	}, nil
}

// updateHitRatio updates the hit ratio gauge.
func (rc *RedisCache) updateHitRatio() {
	if rc.hitRatioGauge == nil {
		return
	}
	if rc.totalHits+rc.totalMisses > 0 {
		rc.hitRatioGauge.Set(float64(rc.totalHits) / float64(rc.totalHits+rc.totalMisses))
	} else {
		rc.hitRatioGauge.Set(0)
	}
}

// Get retrieves an entry from the Redis cache.
func (rc *RedisCache) Get(key string) (*CacheEntry, bool) {
	val, err := rc.client.Get(rc.ctx, key).Result()
	if err == redis.Nil {
		rc.totalMisses++
		if rc.missesTotalCounter != nil {
			rc.missesTotalCounter.Inc()
		}
		rc.updateHitRatio()
		return nil, false // Key does not exist
	} else if err != nil {
		// Log error (optional)
		// log.Printf("Redis GET error for key %s: %v", key, err)
		rc.totalMisses++
		if rc.missesTotalCounter != nil {
			rc.missesTotalCounter.Inc()
		}
		rc.updateHitRatio()
		return nil, false // Error occurred
	}

	var entryData redisCacheEntry
	err = json.Unmarshal([]byte(val), &entryData)
	if err != nil {
		// Log error (optional)
		// log.Printf("Error unmarshalling Redis value for key %s: %v", key, err)
		rc.totalMisses++ // Consider this a miss if data is corrupt
		if rc.missesTotalCounter != nil {
			rc.missesTotalCounter.Inc()
		}
		rc.updateHitRatio()
		return nil, false
	}

	// Optional: Double-check expiry, though Redis TTL should handle this.
	// if time.Now().After(entryData.Expiry) {
	//    // Entry considered expired by its own timestamp, even if Redis returned it.
	//    // This could happen if Redis TTL is longer than intended internal Expiry.
	//    // Might also want to delete it from Redis here: rc.client.Del(rc.ctx, key)
	//    return nil, false
	// }

	// Convert redisCacheEntry to the public CacheEntry type expected by the interface.
	// Size and Hits are not stored in redisCacheEntry, so they'll be zero values.
	// Successfully retrieved and unmarshalled. This is a hit.
	rc.totalHits++
	if rc.hitsTotalCounter != nil {
		rc.hitsTotalCounter.Inc()
	}
	rc.updateHitRatio()

	return &CacheEntry{
		SPFRecord: entryData.SPFRecord,
		Expiry:    entryData.Expiry, // This expiry is from when it was written. Redis TTL is authoritative.
		Found:     entryData.Found,
		Size:      0, // Not tracked in Redis cache in the same way as in-memory
		Hits:      0, // Not tracked in Redis cache, individual entry hits aren't stored in Redis by this impl.
	}, true
}

// Set adds or updates an entry in the Redis cache.
func (rc *RedisCache) Set(key string, spfRecord string, found bool) {
	entryToStore := redisCacheEntry{
		SPFRecord: spfRecord,
		Expiry:    time.Now().Add(time.Duration(rc.cacheTTLSeconds) * time.Second),
		Found:     found,
	}

	jsonData, err := json.Marshal(entryToStore)
	if err != nil {
		// Log error (optional)
		// log.Printf("Error marshalling cache entry for key %s: %v", key, err)
		return
	}

	err = rc.client.Set(rc.ctx, key, jsonData, time.Duration(rc.cacheTTLSeconds)*time.Second).Err()
	if err != nil {
		// Log error (optional)
		// log.Printf("Error setting Redis key %s: %v", key, err)
	}
}

// SetLimit updates the cache size limit.
// This is a stubbed implementation. For Redis, this might involve setting
// maxmemory policies, which are typically configured server-side or via CONFIG SET.
// Direct client-side enforcement of byte limits is less common for Redis itself,
// as Redis manages memory internally based on its configuration.
// This method is a no-op for RedisCache, as memory limits are managed by Redis server configuration.
func (rc *RedisCache) SetLimit(limit int64) {
	// No-op: Redis manages its own memory. Limit configuration is done on the Redis server.
	// Optionally, log a message here if a logging mechanism is available:
	// log.Debugf("RedisCache SetLimit called with %d: no-op, configure Redis server maxmemory policy.", limit)
}

// SetTTL updates the cache TTL for new entries.
// This is a stubbed implementation. The TTL will be used when setting entries in Redis.
// Redis handles TTL per key, so this would affect subsequent Set calls.
func (rc *RedisCache) SetTTL(ttlSeconds int) {
	rc.cacheTTLSeconds = ttlSeconds
}

// Ensure RedisCache implements CacheInterface.
// This requires CacheEntry to be an exported type from its original package (e.g. `cache.CacheEntry`)
// or defined publicly/compatibly for the interface.
var _ CacheInterface = (*RedisCache)(nil)
