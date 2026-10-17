package netns

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func control(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, Mark) //nolint:gosec // fds fit in int
	}); err != nil {
		return err
	}
	if errors.Is(serr, unix.EPERM) {
		return nil // unprivileged (userspace mode): no policy routing to escape
	}
	return serr
}

// resolver sends DNS queries from marked sockets, so names still resolve
// while an exit node carries all other traffic.
var resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 10 * time.Second, Control: control}
		return d.DialContext(ctx, network, address)
	},
}
