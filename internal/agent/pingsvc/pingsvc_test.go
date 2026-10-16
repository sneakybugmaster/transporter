package pingsvc

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lo := netip.MustParseAddr("127.0.0.1")
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, lo) }()
	time.Sleep(50 * time.Millisecond)

	var results []Result
	if err := Ping(ctx, lo, 3, 10*time.Millisecond, time.Second, func(r Result) { results = append(results, r) }); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %v", results)
	}
	for i, r := range results {
		if r.Err != nil || r.Seq != uint32(i+1) || r.RTT <= 0 {
			t.Errorf("result %d = %+v", i, r)
		}
	}

	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Serve returned %v", err)
	}
}

func TestPingTimeout(t *testing.T) {
	// Nothing listens on 127.0.0.2:Port.
	var got Result
	err := Ping(context.Background(), netip.MustParseAddr("127.0.0.2"), 1, 0, 100*time.Millisecond, func(r Result) { got = r })
	if err != nil {
		t.Fatal(err)
	}
	// Linux may report "connection refused" (ICMP) instead of a timeout.
	if got.Err == nil {
		t.Fatalf("expected error, got %+v", got)
	}
}
