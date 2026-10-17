// Package tundev wraps the TUN device between the OS (or netstack) and
// WireGuard. Packets arriving from the mesh pass the packet filter before
// they are delivered; packets leaving are recorded so replies get back in,
// and DNS queries to the MagicDNS address are answered in-process.
package tundev

import (
	"context"
	"encoding/binary"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/sneakybugmaster/transporter/internal/filter"
)

// maxDNSInFlight bounds concurrent DNS answers (forwarded queries can take
// seconds).
const maxDNSInFlight = 64

// Device is a filtering tun.Device.
type Device struct {
	tun.Device
	filter  *filter.Filter
	dnsAddr netip.Addr
	// dns answers a DNS message; nil passes queries through to WireGuard.
	dns  func(ctx context.Context, query []byte) []byte
	ctx  context.Context
	sema chan struct{}
}

// Options configures a Device.
type Options struct {
	Filter *filter.Filter
	// DNSAddr and DNS enable answering DNS queries sent to DNSAddr:53.
	DNSAddr netip.Addr
	DNS     func(ctx context.Context, query []byte) []byte
}

// Wrap returns a filtering device around dev. ctx bounds DNS work.
func Wrap(ctx context.Context, dev tun.Device, opts Options) *Device {
	return &Device{
		Device:  dev,
		filter:  opts.Filter,
		dnsAddr: opts.DNSAddr,
		dns:     opts.DNS,
		ctx:     ctx,
		sema:    make(chan struct{}, maxDNSInFlight),
	}
}

// Read reads packets the OS sends into the mesh. Packets that are handled
// here are given size 0, which WireGuard skips.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	for i := range n {
		pkt := bufs[i][offset : offset+sizes[i]]
		if d.dns != nil && d.dnsAddr.IsValid() {
			if q, src, ok := dnsQuery(pkt, d.dnsAddr); ok {
				d.answer(q, src)
				sizes[i] = 0
				continue
			}
		}
		d.filter.Outbound(pkt)
	}
	return n, err
}

// Write delivers packets that arrived from the mesh, dropping those the
// filter refuses. It reports every packet as written.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	keep := bufs
	for i, b := range bufs {
		if d.filter.Inbound(b[offset:]) {
			if len(keep) < len(bufs) {
				keep = append(keep, b)
			}
			continue
		}
		if len(keep) == len(bufs) {
			keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	if _, err := d.Device.Write(keep, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

// answer resolves a query in the background and writes the response back to
// the OS as if it came from the DNS address.
func (d *Device) answer(query []byte, client netip.AddrPort) {
	select {
	case d.sema <- struct{}{}:
	default:
		return // overloaded: the client will retry
	}
	q := append([]byte(nil), query...) // the read buffer is reused
	go func() {
		defer func() { <-d.sema }()
		resp := d.dns(d.ctx, q)
		if resp == nil {
			return
		}
		const headroom = device.MessageTransportHeaderSize
		pkt := udpPacket(netip.AddrPortFrom(d.dnsAddr, 53), client, resp, headroom)
		_, _ = d.Device.Write([][]byte{pkt}, headroom)
	}()
}

// dnsQuery returns the payload and source of an IPv4 UDP packet to addr:53.
func dnsQuery(b []byte, addr netip.Addr) ([]byte, netip.AddrPort, bool) {
	if len(b) < 28 || b[0]>>4 != 4 || b[9] != filter.ProtoUDP {
		return nil, netip.AddrPort{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+8 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 { // fragmented
		return nil, netip.AddrPort{}, false
	}
	if netip.AddrFrom4([4]byte(b[16:20])) != addr || binary.BigEndian.Uint16(b[ihl+2:ihl+4]) != 53 {
		return nil, netip.AddrPort{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	udpLen := int(binary.BigEndian.Uint16(b[ihl+4 : ihl+6]))
	if total > len(b) || udpLen < 8 || ihl+udpLen > total {
		return nil, netip.AddrPort{}, false
	}
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[12:16])), binary.BigEndian.Uint16(b[ihl:ihl+2]))
	return b[ihl+8 : ihl+udpLen], src, true
}

// udpPacket builds an IPv4 UDP packet preceded by headroom spare bytes.
func udpPacket(src, dst netip.AddrPort, payload []byte, headroom int) []byte {
	buf := make([]byte, headroom+28+len(payload))
	b := buf[headroom:]
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b))) //nolint:gosec // DNS answers are far below 64 KiB
	binary.BigEndian.PutUint16(b[6:8], 0x4000)         // don't fragment
	b[8] = 64
	b[9] = filter.ProtoUDP
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:20], 0))

	u := b[20:]
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u))) //nolint:gosec // see above
	copy(u[8:], payload)
	// Pseudo-header: addresses, protocol, UDP length.
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(s[0:2])) + uint32(binary.BigEndian.Uint16(s[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d[0:2])) + uint32(binary.BigEndian.Uint16(d[2:4]))
	sum += uint32(filter.ProtoUDP) + uint32(len(u)) //nolint:gosec // DNS answers are far below 4 GiB
	c := checksum(u, sum)
	if c == 0 {
		c = 0xffff // 0 means "no checksum" in UDP
	}
	binary.BigEndian.PutUint16(u[6:8], c)
	return buf
}

// checksum is the Internet checksum of b, starting from sum.
func checksum(b []byte, sum uint32) uint16 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum) //nolint:gosec // folded to 16 bits above
}
