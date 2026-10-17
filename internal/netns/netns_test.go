package netns

import (
	"context"
	"net"
	"testing"
)

// Marking must never make ordinary sockets fail, privileged or not.
func TestSocketsWork(t *testing.T) {
	ln, err := ListenConfig().Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	pc, err := ListenConfig().ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	if _, err := net.ResolveTCPAddr("tcp", "localhost:1"); err != nil {
		t.Skip("no resolver in this environment")
	}
}
