package engine

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/wgkey"
)

// persistentKeepalive keeps NAT mappings open and lets peers notice liveness.
const persistentKeepalive = 25

// peerConfig renders the UAPI "set" stanza that adds or updates a peer.
// A zero endpoint leaves the peer's current endpoint untouched.
func peerConfig(key wgkey.Key, allowed []netip.Prefix, endpoint netip.AddrPort) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", key.Hex())
	if endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", persistentKeepalive)
	b.WriteString("replace_allowed_ips=true\n")
	for _, p := range allowed {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p)
	}
	return b.String()
}

// removePeerConfig renders the UAPI stanza that removes a peer.
func removePeerConfig(key wgkey.Key) string {
	return fmt.Sprintf("public_key=%s\nremove=true\n", key.Hex())
}

// endpointConfig renders the UAPI stanza that changes only a peer's endpoint.
func endpointConfig(key wgkey.Key, endpoint netip.AddrPort) string {
	return fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", key.Hex(), endpoint)
}

// deviceStats is the subset of UAPI "get" output the engine uses.
type deviceStats struct {
	listenPort uint16
	peers      map[wgkey.Key]peerStats
}

type peerStats struct {
	endpoint      netip.AddrPort
	lastHandshake time.Time
	rxBytes       uint64
	txBytes       uint64
}

func parseStats(s string) (deviceStats, error) {
	st := deviceStats{peers: map[wgkey.Key]peerStats{}}
	var (
		cur     wgkey.Key
		ps      peerStats
		inPeer  bool
		hsSec   int64
		hsNsec  int64
		flushFn = func() {
			if inPeer {
				if hsSec != 0 || hsNsec != 0 {
					ps.lastHandshake = time.Unix(hsSec, hsNsec)
				}
				st.peers[cur] = ps
			}
		}
	)
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		var err error
		switch k {
		case "listen_port":
			var p uint64
			p, err = strconv.ParseUint(v, 10, 16)
			st.listenPort = uint16(p)
		case "public_key":
			flushFn()
			cur, err = wgkey.ParseHex(v)
			ps, inPeer, hsSec, hsNsec = peerStats{}, true, 0, 0
		case "endpoint":
			ps.endpoint, err = netip.ParseAddrPort(v)
		case "last_handshake_time_sec":
			hsSec, err = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, err = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			ps.rxBytes, err = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			ps.txBytes, err = strconv.ParseUint(v, 10, 64)
		}
		if err != nil {
			return deviceStats{}, fmt.Errorf("uapi %s: %w", k, err)
		}
	}
	flushFn()
	return st, sc.Err()
}
