//go:build !linux

package netns

import (
	"net"
	"syscall"
)

func control(string, string, syscall.RawConn) error { return nil }

var resolver = net.DefaultResolver
