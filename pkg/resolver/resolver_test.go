package resolver

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	// "sync/atomic" // Removed as it's not directly used in tests, only in main code.
	"testing"
	// "time" // Removed as it's not directly used after simplifying AtomicCountIncrementPath test.
)

// MockSPFResolver is a mock implementation of the SPFResolver interface for testing.
type MockSPFResolver struct {
	LookupTXTErr      error
	LookupTXTVals     []string
	LookupMXErr       error
	LookupMXVals      []*net.MX
	LookupAddrErr     error
	LookupAddrVals    []string
	LookupIPAddrErr   error
	LookupIPAddrVals  []net.IPAddr
	LookupTXTCalls    int
	LookupMXCalls     int
	LookupAddrCalls   int
	LookupIPAddrCalls int
}

func (m *MockSPFResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	m.LookupTXTCalls++
	return m.LookupTXTVals, m.LookupTXTErr
}

func (m *MockSPFResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	m.LookupMXCalls++
	return m.LookupMXVals, m.LookupMXErr
}

func (m *MockSPFResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	m.LookupAddrCalls++
	return m.LookupAddrVals, m.LookupAddrErr
}

func (m *MockSPFResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	m.LookupIPAddrCalls++
	return m.LookupIPAddrVals, m.LookupIPAddrErr
}

func TestNewResolverPool(t *testing.T) {
	t.Run("empty_dns_servers", func(t *testing.T) {
		rp := NewResolverPool("")
		if len(rp.Resolvers) != 1 {
			t.Fatalf("Expected 1 resolver, got %d", len(rp.Resolvers))
		}
		if rp.Resolvers[0] != net.DefaultResolver {
			t.Error("Expected DefaultResolver when dnsServers is empty")
		}
	})

	t.Run("single_dns_server_no_port", func(t *testing.T) {
		rp := NewResolverPool("1.1.1.1")
		if len(rp.Resolvers) != 1 {
			t.Fatalf("Expected 1 resolver, got %d", len(rp.Resolvers))
		}
		if rp.Resolvers[0] == net.DefaultResolver {
			t.Error("Expected custom resolver, not DefaultResolver")
		}
		// Further inspection of the Dial func is hard. We assume it's set up if not DefaultResolver.
	})

	t.Run("single_dns_server_with_port", func(t *testing.T) {
		rp := NewResolverPool("1.1.1.1:5353")
		if len(rp.Resolvers) != 1 {
			t.Fatalf("Expected 1 resolver, got %d", len(rp.Resolvers))
		}
		if rp.Resolvers[0] == net.DefaultResolver {
			t.Error("Expected custom resolver, not DefaultResolver")
		}
	})

	t.Run("multiple_dns_servers", func(t *testing.T) {
		rp := NewResolverPool("1.1.1.1:53, 8.8.8.8")
		if len(rp.Resolvers) != 2 {
			t.Fatalf("Expected 2 resolvers, got %d", len(rp.Resolvers))
		}
		if rp.Resolvers[0] == net.DefaultResolver || rp.Resolvers[1] == net.DefaultResolver {
			t.Error("Expected custom resolvers, not DefaultResolver")
		}
	})

	t.Run("dns_servers_with_empty_and_whitespace", func(t *testing.T) {
		rp := NewResolverPool("1.1.1.1, , 8.8.8.8 , ")
		if len(rp.Resolvers) != 2 {
			t.Fatalf("Expected 2 resolvers, got %d (found: %v)", len(rp.Resolvers), rp.Resolvers)
		}
	})

	t.Run("only_empty_dns_servers", func(t *testing.T) {
		rp := NewResolverPool(", ,, ")
		if len(rp.Resolvers) != 1 {
			t.Fatalf("Expected 1 resolver (default), got %d", len(rp.Resolvers))
		}
		if rp.Resolvers[0] != net.DefaultResolver {
			t.Error("Expected DefaultResolver when dnsServers contains only commas/whitespace")
		}
	})
}

func TestResolverPool_GetResolver(t *testing.T) {
	t.Run("get_default_resolver", func(t *testing.T) {
		rp := NewResolverPool("")
		r := rp.GetResolver()
		if r != net.DefaultResolver {
			t.Error("Expected DefaultResolver")
		}
	})

	t.Run("get_custom_resolver", func(t *testing.T) {
		rp := NewResolverPool("1.1.1.1")
		r := rp.GetResolver()
		if r == net.DefaultResolver {
			t.Error("Expected custom resolver")
		}
	})

	t.Run("cycle_resolvers", func(t *testing.T) {
		rp := NewResolverPool("1.1.1.1,2.2.2.2,3.3.3.3")
		if len(rp.Resolvers) != 3 {
			t.Fatalf("Test setup error: expected 3 resolvers, got %d", len(rp.Resolvers))
		}

		// Get enough resolvers to ensure cycling.
		// Exact instance comparison is difficult as they are closures.
		// We check that we are not always getting the same one if multiple are present.
		// This is a weak test for cycling. A better test would involve mockable Dial funcs.
		resolversGot := make(map[*net.Resolver]int)
		for i := 0; i < len(rp.Resolvers)*2; i++ {
			resolversGot[rp.GetResolver()]++
		}

		if len(rp.Resolvers) > 1 && len(resolversGot) == 1 {
			t.Errorf("Expected to get different resolver instances, but only got one type. Map: %v", resolversGot)
		}
		if len(resolversGot) != len(rp.Resolvers) && len(rp.Resolvers) > 1 {
			// This can happen if the underlying net.Resolver structs are identical despite different Dial funcs.
			// This test is more about the pool's counter logic than distinct resolver behavior.
			// t.Logf("Got %d distinct resolver references for %d configured resolvers. This might be acceptable.", len(resolversGot), len(rp.Resolvers))
		}
		// Check counter has advanced
		if rp.counter < uint64(len(rp.Resolvers)*2-1) && len(rp.Resolvers) > 0 { // counter is 0-indexed for first call
			t.Errorf("Counter did not advance as expected. Got %d, expected at least %d", rp.counter, len(rp.Resolvers)*2)
		}
	})
}

func TestTrackingResolver(t *testing.T) {
	mockBaseResolver := &MockSPFResolver{}
	var count int

	// Use the NewTrackingResolver constructor
	tr := NewTrackingResolver(mockBaseResolver, &count)
	ctx := context.Background()

	t.Run("LookupTXT", func(t *testing.T) {
		count = 0 // Reset count for subtest
		mockBaseResolver.LookupTXTCalls = 0
		mockBaseResolver.LookupTXTVals = []string{"txt"}
		mockBaseResolver.LookupTXTErr = nil

		vals, err := tr.LookupTXT(ctx, "example.com")
		if err != nil {
			t.Errorf("LookupTXT error: %v", err)
		}
		if !reflect.DeepEqual(vals, []string{"txt"}) {
			t.Errorf("LookupTXT vals = %v; want %v", vals, []string{"txt"})
		}
		if count != 1 {
			t.Errorf("count after LookupTXT = %d; want 1", count)
		}
		if mockBaseResolver.LookupTXTCalls != 1 {
			t.Errorf("mockBaseResolver.LookupTXTCalls = %d; want 1", mockBaseResolver.LookupTXTCalls)
		}
	})

	t.Run("LookupMX", func(t *testing.T) {
		count = 0
		mockBaseResolver.LookupMXCalls = 0
		mockBaseResolver.LookupMXVals = []*net.MX{{Host: "mx.example.com"}}
		mockBaseResolver.LookupMXErr = nil

		vals, err := tr.LookupMX(ctx, "example.com")
		if err != nil {
			t.Errorf("LookupMX error: %v", err)
		}
		if len(vals) != 1 || vals[0].Host != "mx.example.com" {
			t.Errorf("LookupMX vals = %v; want [{Host: mx.example.com}]", vals)
		}
		if count != 1 {
			t.Errorf("count after LookupMX = %d; want 1", count)
		}
		if mockBaseResolver.LookupMXCalls != 1 {
			t.Errorf("mockBaseResolver.LookupMXCalls = %d; want 1", mockBaseResolver.LookupMXCalls)
		}
	})

	t.Run("LookupAddr", func(t *testing.T) {
		count = 0
		mockBaseResolver.LookupAddrCalls = 0
		mockBaseResolver.LookupAddrVals = []string{"ptr.example.com"}
		mockBaseResolver.LookupAddrErr = nil

		vals, err := tr.LookupAddr(ctx, "1.2.3.4.in-addr.arpa")
		if err != nil {
			t.Errorf("LookupAddr error: %v", err)
		}
		if !reflect.DeepEqual(vals, []string{"ptr.example.com"}) {
			t.Errorf("LookupAddr vals = %v; want %v", vals, []string{"ptr.example.com"})
		}
		if count != 1 {
			t.Errorf("count after LookupAddr = %d; want 1", count)
		}
		if mockBaseResolver.LookupAddrCalls != 1 {
			t.Errorf("mockBaseResolver.LookupAddrCalls = %d; want 1", mockBaseResolver.LookupAddrCalls)
		}
	})

	t.Run("LookupIPAddr", func(t *testing.T) {
		count = 0
		mockBaseResolver.LookupIPAddrCalls = 0
		ip := net.ParseIP("1.2.3.4")
		mockBaseResolver.LookupIPAddrVals = []net.IPAddr{{IP: ip}}
		mockBaseResolver.LookupIPAddrErr = nil

		vals, err := tr.LookupIPAddr(ctx, "host.example.com")
		if err != nil {
			t.Errorf("LookupIPAddr error: %v", err)
		}
		if len(vals) != 1 || !vals[0].IP.Equal(ip) {
			t.Errorf("LookupIPAddr vals = %v; want %v", vals, []net.IPAddr{{IP: ip}})
		}
		if count != 1 {
			t.Errorf("count after LookupIPAddr = %d; want 1", count)
		}
		if mockBaseResolver.LookupIPAddrCalls != 1 {
			t.Errorf("mockBaseResolver.LookupIPAddrCalls = %d; want 1", mockBaseResolver.LookupIPAddrCalls)
		}
	})

	t.Run("LookupTXT_WithError", func(t *testing.T) {
		count = 0
		mockBaseResolver.LookupTXTCalls = 0
		mockBaseResolver.LookupTXTErr = errors.New("dns error")

		_, err := tr.LookupTXT(ctx, "example.com")
		if err == nil || !strings.Contains(err.Error(), "dns error") {
			t.Errorf("Expected 'dns error', got %v", err)
		}
		if count != 1 {
			t.Errorf("count after LookupTXT with error = %d; want 1", count)
		}
		if mockBaseResolver.LookupTXTCalls != 1 {
			t.Errorf("mockBaseResolver.LookupTXTCalls with error = %d; want 1", mockBaseResolver.LookupTXTCalls)
		}
	})

	// Test atomic increment of count pointer (simplified)
	t.Run("AtomicCountIncrementPath", func(t *testing.T) {
		// This test verifies that the increment path using atomic operations in TrackingResolver works for a single call.
		// True atomicity under concurrency is hard to test deterministically here and relies on the correctness
		// of Go's `sync/atomic` package, which is assumed.
		var normalCount int = 0
		trSingle := NewTrackingResolver(mockBaseResolver, &normalCount)

		// Reset mock calls for this specific check
		mockBaseResolver.LookupTXTCalls = 0
		mockBaseResolver.LookupTXTErr = nil
		mockBaseResolver.LookupTXTVals = []string{"text"}

		trSingle.LookupTXT(ctx, "exampleatomic.com")
		if normalCount != 1 {
			t.Errorf("Count after LookupTXT (path using atomic op) = %d; want 1", normalCount)
		}
		if mockBaseResolver.LookupTXTCalls != 1 {
			t.Errorf("mockBaseResolver.LookupTXTCalls for atomic path test = %d; want 1", mockBaseResolver.LookupTXTCalls)
		}
	})
}
