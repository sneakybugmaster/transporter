package pingsvc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func listen(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

func TestPing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := listen(t, "127.0.0.1")
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, srv) }()

	conn, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var results []Result
	if err := Ping(ctx, conn, 3, 10*time.Millisecond, time.Second, func(r Result) { results = append(results, r) }); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %v", results)
	}
	for i, r := range results {
		if r.Err != nil || r.Seq != uint32(i+1) || r.RTT < 0 { // loopback can measure 0 with a coarse clock (Windows)
			t.Errorf("result %d = %+v", i, r)
		}
	}

	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Serve returned %v", err)
	}
}

func TestPingTimeout(t *testing.T) {
	// A socket that never answers.
	silent := listen(t, "127.0.0.1")
	defer silent.Close()
	conn, err := net.DialUDP("udp4", nil, silent.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var got Result
	if err := Ping(context.Background(), conn, 1, 0, 100*time.Millisecond, func(r Result) { got = r }); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(got.Err, ErrTimeout) {
		t.Fatalf("got %+v, want timeout", got)
	}
}
