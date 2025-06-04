package resolver

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe" // Moved import to the top
)

// ResolverPool holds a list of net.Resolvers and distributes lookups among them.
type ResolverPool struct {
	Resolvers []*net.Resolver
	counter   uint64
}

// NewResolverPool creates a new ResolverPool based on a comma-separated string of DNS server addresses.
// If dnsServers string is empty, it defaults to using net.DefaultResolver.
func NewResolverPool(dnsServers string) *ResolverPool {
	rp := &ResolverPool{}

	if dnsServers == "" {
		rp.Resolvers = []*net.Resolver{net.DefaultResolver}
		return rp
	}

	servers := strings.Split(dnsServers, ",")
	for _, server := range servers {
		serverAddr := strings.TrimSpace(server)
		if serverAddr == "" {
			continue
		}

		// Ensure server address includes a port, default to 53 if not specified.
		if !strings.Contains(serverAddr, ":") {
			serverAddr = net.JoinHostPort(serverAddr, "53")
		}

		resolver := &net.Resolver{
			PreferGo: true, // Use Go's built-in resolver
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// 'address' will be ignored, 'serverAddr' from the outer scope is used.
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, serverAddr)
			},
		}
		rp.Resolvers = append(rp.Resolvers, resolver)
	}

	// Fallback to default resolver if no valid custom servers were parsed.
	if len(rp.Resolvers) == 0 {
		rp.Resolvers = []*net.Resolver{net.DefaultResolver}
	}

	return rp
}

// GetResolver returns a net.Resolver from the pool, cycling through available resolvers.
func (rp *ResolverPool) GetResolver() *net.Resolver {
	if len(rp.Resolvers) == 0 {
		// This case should ideally not be hit if NewResolverPool ensures at least one resolver.
		return net.DefaultResolver
	}
	// Atomically increment counter and pick a resolver.
	index := atomic.AddUint64(&rp.counter, 1) % uint64(len(rp.Resolvers))
	return rp.Resolvers[index]
}

// TrackingResolver is a wrapper around a net.Resolver that counts the number of lookups.
// This is used by the SPF checking mechanism to count DNS lookups.
type TrackingResolver struct {
	BaseResolver SPFResolver // The underlying resolver to use for lookups.
	Count        *int        // Pointer to an integer to increment for each lookup.
}

// SPFResolver defines the interface for DNS lookups needed by the SPF library and TrackingResolver.
// net.Resolver satisfies this interface.
type SPFResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)       // For PTR lookups
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) // For A/AAAA lookups
}

// NewTrackingResolver creates a new TrackingResolver.
func NewTrackingResolver(baseResolver SPFResolver, count *int) *TrackingResolver {
	return &TrackingResolver{
		BaseResolver: baseResolver,
		Count:        count,
	}
}

// LookupTXT performs a TXT lookup using the underlying resolver and increments the count.
func (tr *TrackingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	atomic.AddInt32((*int32)(unsafe.Pointer(tr.Count)), 1) // Ensure atomic increment if Count is shared, though typically not.
	return tr.BaseResolver.LookupTXT(ctx, name)
}

// LookupMX performs an MX lookup using the underlying resolver and increments the count.
func (tr *TrackingResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	atomic.AddInt32((*int32)(unsafe.Pointer(tr.Count)), 1)
	return tr.BaseResolver.LookupMX(ctx, name)
}

// LookupAddr performs a PTR lookup using the underlying resolver and increments the count.
func (tr *TrackingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	atomic.AddInt32((*int32)(unsafe.Pointer(tr.Count)), 1)
	return tr.BaseResolver.LookupAddr(ctx, addr)
}

// LookupIPAddr performs an A/AAAA lookup using the underlying resolver and increments the count.
func (tr *TrackingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	atomic.AddInt32((*int32)(unsafe.Pointer(tr.Count)), 1)
	return tr.BaseResolver.LookupIPAddr(ctx, host)
}

// Note: The comment about unsafe import and potential review of Count type (int vs int32/int64)
// is still relevant but the import statement itself should only be at the top.
// unsafe is imported here only for atomic operations on *int via *int32.
// This is generally safe for counters but shows a place where `int` type for counter might be reviewed.
// Consider using int32 or int64 for Count if it's directly manipulated atomically often from different goroutines.
// For this specific SPF library usage, the count is typically local to one SPF check operation.
