// Command load simulates many nodes against a coordinator to measure how the
// control plane scales. Each simulated node registers with a fresh key,
// keeps a netmap stream open and reports endpoints, like a real agent but
// without WireGuard. It reports how long the mesh takes to converge and how
// quickly a change reaches every node.
//
//	go run ./test/load -coordinator http://127.0.0.1:8080 -authkey trk_... -nodes 1000
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
	"github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1/controlv1connect"
)

type node struct {
	id, token string
	endpoint  string
	// peers is the size of the latest netmap; marker the endpoint the
	// latest netmap lists for the churn node.
	peers  atomic.Int64
	marker atomic.Value // string
	msgs   atomic.Int64
	bytes  atomic.Int64
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	coordinator := flag.String("coordinator", "http://127.0.0.1:8080", "coordinator URL")
	authKey := flag.String("authkey", os.Getenv("TRANSPORTER_AUTHKEY"), "reusable auth key")
	n := flag.Int("nodes", 1000, "simulated nodes")
	parallel := flag.Int("parallel", 50, "concurrent registrations")
	timeout := flag.Duration("timeout", 5*time.Minute, "give up after")
	flag.Parse()
	if *authKey == "" {
		return errors.New("-authkey is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{
		MaxIdleConnsPerHost: 1024,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
	}}
	rpc := controlv1connect.NewControlServiceClient(hc, *coordinator)

	nodes := make([]*node, *n)
	start := time.Now()
	sem := make(chan struct{}, *parallel)
	var wg sync.WaitGroup
	var failed atomic.Int64
	for i := range nodes {
		nodes[i] = &node{endpoint: fmt.Sprintf("198.51.%d.%d:41641", i/250, i%250+1)}
		nodes[i].marker.Store("")
		wg.Add(1)
		sem <- struct{}{}
		go func(nd *node, i int) {
			defer wg.Done()
			defer func() { <-sem }()
			key := make([]byte, 32)
			_, _ = rand.Read(key)
			resp, err := rpc.Register(ctx, connect.NewRequest(&controlv1.RegisterRequest{
				AuthKey: *authKey, WireguardPublicKey: key, Hostname: fmt.Sprintf("load-%04d", i), Os: "linux",
			}))
			if err != nil {
				failed.Add(1)
				log.Printf("register %d: %v", i, err)
				return
			}
			nd.id, nd.token = resp.Msg.GetNode().GetId(), resp.Msg.GetNodeToken()
		}(nodes[i], i)
	}
	wg.Wait()
	if failed.Load() > 0 {
		return fmt.Errorf("%d registrations failed", failed.Load())
	}
	fmt.Printf("registered %d nodes in %v\n", *n, time.Since(start).Round(time.Millisecond))

	churn := nodes[0]
	start = time.Now()
	for _, nd := range nodes {
		go watch(ctx, rpc, nd, churn.id)
	}
	if err := waitAll(ctx, nodes, func(nd *node) bool { return nd.peers.Load() == int64(*n-1) }); err != nil {
		return fmt.Errorf("convergence: %w", err)
	}
	fmt.Printf("all %d streams open, every node sees all %d peers after %v\n", *n, *n-1, time.Since(start).Round(time.Millisecond))
	report(nodes)

	// Churn: one node changes its endpoints; measure the fan-out.
	for round := 1; round <= 3; round++ {
		ep := fmt.Sprintf("203.0.113.%d:41641", round)
		start = time.Now()
		req := connect.NewRequest(&controlv1.UpdateEndpointsRequest{Endpoints: []string{ep}})
		req.Header().Set("Authorization", "Bearer "+churn.token)
		if _, err := rpc.UpdateEndpoints(ctx, req); err != nil {
			return fmt.Errorf("update endpoints: %w", err)
		}
		others := slices.DeleteFunc(slices.Clone(nodes), func(nd *node) bool { return nd == churn })
		if err := waitAll(ctx, others, func(nd *node) bool { return nd.marker.Load() == ep }); err != nil {
			return fmt.Errorf("fan-out: %w", err)
		}
		fmt.Printf("endpoint change %d reached all %d nodes in %v\n", round, len(others), time.Since(start).Round(time.Millisecond))
	}
	report(nodes)
	return nil
}

func watch(ctx context.Context, rpc controlv1connect.ControlServiceClient, nd *node, churnID string) {
	for ctx.Err() == nil {
		req := connect.NewRequest(&controlv1.WatchNetmapRequest{Endpoints: []string{nd.endpoint}})
		req.Header().Set("Authorization", "Bearer "+nd.token)
		stream, err := rpc.WatchNetmap(ctx, req)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		for stream.Receive() {
			nm := stream.Msg()
			nd.msgs.Add(1)
			nd.bytes.Add(int64(proto.Size(nm)))
			nd.peers.Store(int64(len(nm.GetPeers())))
			for _, p := range nm.GetPeers() {
				if p.GetId() == churnID && len(p.GetEndpoints()) > 0 {
					nd.marker.Store(p.GetEndpoints()[0])
				}
			}
		}
		_ = stream.Close()
		if err := stream.Err(); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("stream %s: %v", nd.id, err)
		}
	}
}

func waitAll(ctx context.Context, nodes []*node, ok func(*node) bool) error {
	for {
		done := 0
		for _, nd := range nodes {
			if ok(nd) {
				done++
			}
		}
		if done == len(nodes) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%d of %d nodes done: %w", done, len(nodes), ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func report(nodes []*node) {
	var msgs, bytes int64
	for _, nd := range nodes {
		msgs += nd.msgs.Load()
		bytes += nd.bytes.Load()
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Printf("  netmaps received: %d (%.1f MiB total); load tool heap %.0f MiB\n", msgs, float64(bytes)/(1<<20), float64(ms.HeapAlloc)/(1<<20))
}
