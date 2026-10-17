package magicsock

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/netcfg"
	"github.com/sneakybugmaster/transporter/internal/stun"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// maxAdvertised leaves room under the coordinator's limit of 16.
const maxAdvertised = 15

type outPacket struct {
	b  []byte
	to netip.AddrPort
}

// handleDisco processes a disco packet that arrived directly from src, or
// through the relay from relayFrom.
func (c *Conn) handleDisco(b []byte, src netip.AddrPort, relayFrom *wgkey.Key) {
	sender := discoSender(b)
	if relayFrom != nil && *relayFrom != sender {
		return // the relay vouches for who sent it; the claims must agree
	}
	c.mu.Lock()
	p := c.peers[sender]
	c.mu.Unlock()
	if p == nil {
		return
	}
	m, err := openDisco(p.shared, b)
	if err != nil {
		return
	}
	now := time.Now()

	switch m.typ {
	case msgPing:
		if relayFrom != nil {
			return // pings probe direct paths only
		}
		c.mu.Lock()
		c.byAddr[src] = p // the peer proved it sends from src
		cd := c.addCandidateLocked(p, src, now)
		var out []outPacket
		out = append(out, outPacket{sealDisco(p.shared, c.pub, discoMsg{typ: msgPong, tx: m.tx, observed: src}), src})
		if cd != nil && now.Sub(cd.lastPong) > pingInterval {
			// Probe back: for a peer behind a symmetric NAT, src is the
			// only address that works and no one else could tell us.
			out = append(out, c.pingLocked(p, src, now))
		}
		c.mu.Unlock()
		c.write(out)

	case msgPong:
		c.mu.Lock()
		defer c.mu.Unlock()
		pp, ok := c.pings[m.tx]
		if !ok || pp.peer != p || pp.addr != src || relayFrom != nil {
			return
		}
		delete(c.pings, m.tx)
		cd := c.addCandidateLocked(p, src, now)
		if cd == nil {
			return
		}
		cd.lastPong, cd.latency = now, now.Sub(pp.sent)
		c.byAddr[src] = p
		c.updateBestLocked(p, now)

	case msgCallMeMaybe:
		if relayFrom == nil {
			return // only accepted through the relay
		}
		c.mu.Lock()
		if now.Sub(p.lastCMMIn) < time.Second {
			c.mu.Unlock()
			return
		}
		p.lastCMMIn = now
		for _, ep := range m.endpoints {
			if ep.Addr().Is4() {
				c.addCandidateLocked(p, ep, now)
			}
		}
		out := c.pingPeerLocked(p, now)
		c.mu.Unlock()
		c.write(out)
	}
}

// addCandidateLocked returns p's candidate for addr, adding a discovered one
// if there is room.
func (c *Conn) addCandidateLocked(p *peer, addr netip.AddrPort, now time.Time) *candidate {
	if cd := p.candidates[addr]; cd != nil {
		if !cd.fromNetmap {
			cd.added = now // still in use: keep it alive
		}
		return cd
	}
	if len(p.candidates) >= maxCandidates {
		return nil
	}
	cd := &candidate{added: now}
	p.candidates[addr] = cd
	return cd
}

// updateBestLocked picks the lowest-latency trusted direct path, sticking
// with the current one unless the new one is clearly better.
func (c *Conn) updateBestLocked(p *peer, now time.Time) {
	var best netip.AddrPort
	var bestLat time.Duration
	for addr, cd := range p.candidates {
		if now.Sub(cd.lastPong) > trustDuration {
			continue
		}
		if !best.IsValid() || cd.latency < bestLat {
			best, bestLat = addr, cd.latency
		}
	}
	cur := c.directPathLocked(p, now)
	if cur.IsValid() && cur != best {
		curLat := p.candidates[cur].latency
		if float64(bestLat) > switchFactor*float64(curLat) {
			return
		}
	}
	if best != p.best {
		c.log.Info("direct path", "peer", p.cfg.Name, "addr", best, "latency", bestLat.Round(time.Microsecond))
		p.best = best
	}
}

// pingLocked records and returns a disco ping to addr.
func (c *Conn) pingLocked(p *peer, addr netip.AddrPort, now time.Time) outPacket {
	tx := newTxID()
	c.pings[tx] = pendingPing{peer: p, addr: addr, sent: now}
	return outPacket{sealDisco(p.shared, c.pub, discoMsg{typ: msgPing, tx: tx}), addr}
}

func (c *Conn) pingPeerLocked(p *peer, now time.Time) []outPacket {
	p.lastPing = now
	out := make([]outPacket, 0, len(p.candidates))
	for addr := range p.candidates {
		out = append(out, c.pingLocked(p, addr, now))
	}
	return out
}

func (c *Conn) write(out []outPacket) {
	c.mu.Lock()
	pc := c.pc
	c.mu.Unlock()
	if pc == nil {
		return
	}
	for _, o := range out {
		if _, err := pc.WriteToUDPAddrPort(o.b, o.to); err != nil {
			c.log.Debug("disco send", "to", o.to, "err", err)
		}
	}
}

func (c *Conn) handleSTUN(b []byte) {
	tx, addr, err := stun.ParseResponse(b)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.stunTx[tx]; !ok {
		return
	}
	delete(c.stunTx, tx)
	if addr != c.reflexive {
		c.log.Info("public address", "addr", addr)
		c.reflexive = addr
	}
}

// loop runs discovery until closed is closed.
func (c *Conn) loop(closed chan struct{}) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	c.tick(time.Now())
	for {
		select {
		case <-closed:
			return
		case now := <-t.C:
			c.tick(now)
		}
	}
}

func (c *Conn) tick(now time.Time) {
	var (
		out       []outPacket
		relayOut  []relayMsg
		changedTo []netip.AddrPort
	)
	c.mu.Lock()
	if c.pc == nil {
		c.mu.Unlock()
		return
	}
	for tx, pp := range c.pings {
		if now.Sub(pp.sent) > pingTimeout {
			delete(c.pings, tx)
		}
	}
	for tx, sent := range c.stunTx {
		if now.Sub(sent) > pingTimeout {
			delete(c.stunTx, tx)
		}
	}

	if now.Sub(c.lastLocal) >= localAddrsEvery {
		c.lastLocal = now
		c.local = nil
		if !c.opts.DisableLocalEndpoints {
			eps, err := netcfg.LocalEndpoints(c.port, c.meshPrefix, c.opts.ExcludeInterfaces...)
			if err != nil {
				c.log.Warn("local endpoints", "err", err)
			}
			for _, ep := range eps {
				if ep.Addr().Is4() { // the socket is IPv4-only for now
					c.local = append(c.local, ep)
				}
			}
		}
	}
	if c.stunServer.IsValid() && now.Sub(c.lastSTUN) >= stunInterval {
		c.lastSTUN = now
		tx := stun.NewTxID()
		c.stunTx[tx] = now
		out = append(out, outPacket{stun.Request(tx), c.stunServer})
	}
	if adv := c.advertisedLocked(); !slices.Equal(adv, c.advertised) {
		c.advertised = adv
		changedTo = slices.Clone(adv)
	}

	relayUp := c.relay != nil && c.relay.Connected()
	for _, p := range c.peers {
		for addr, cd := range p.candidates {
			if !cd.fromNetmap && now.Sub(cd.added) > discoveredTTL && now.Sub(cd.lastPong) > discoveredTTL {
				c.dropCandidateLocked(p, addr)
			}
		}
		direct := c.directPathLocked(p, now)
		if !direct.IsValid() && p.best.IsValid() {
			c.log.Info("direct path lost", "peer", p.cfg.Name, "addr", p.best)
			p.best = netip.AddrPort{}
		}
		if len(p.candidates) > 0 && now.Sub(p.lastPing) >= pingInterval {
			out = append(out, c.pingPeerLocked(p, now)...)
		}
		if !direct.IsValid() && relayUp && len(c.advertised) > 0 && now.Sub(p.lastCMM) >= callMeMaybeEvery {
			// Ask the peer to probe us while we probe it, so both NATs
			// see outbound traffic and let the other side's pings in.
			p.lastCMM = now
			relayOut = append(relayOut, relayMsg{p.cfg.Key, sealDisco(p.shared, c.pub, discoMsg{typ: msgCallMeMaybe, endpoints: c.advertised})})
			out = append(out, c.pingPeerLocked(p, now)...)
		}
	}
	rc := c.relay
	c.mu.Unlock()

	c.write(out)
	for _, m := range relayOut {
		_ = rc.Send(context.Background(), m.to, m.b)
	}
	if changedTo != nil && c.opts.OnEndpoints != nil {
		go c.opts.OnEndpoints(changedTo)
	}
}

type relayMsg struct {
	to wgkey.Key
	b  []byte
}

// advertisedLocked is the endpoint list to publish: manual extras, the STUN
// reflexive address, then interface addresses.
func (c *Conn) advertisedLocked() []netip.AddrPort {
	var out []netip.AddrPort
	add := func(ep netip.AddrPort) {
		if ep.IsValid() && !slices.Contains(out, ep) && len(out) < maxAdvertised {
			out = append(out, ep)
		}
	}
	for _, ep := range c.opts.ExtraEndpoints {
		add(ep)
	}
	add(c.reflexive)
	for _, ep := range c.local {
		add(ep)
	}
	return out
}

// Endpoints returns the endpoints this node currently advertises.
func (c *Conn) Endpoints() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.advertisedLocked())
}

// PeerPath describes how traffic to a peer currently flows.
type PeerPath struct {
	Key wgkey.Key
	// Kind is "direct", "relay" or "" (no path).
	Kind    string
	Addr    netip.AddrPort
	Latency time.Duration
}

// Paths reports the current path to every peer.
func (c *Conn) Paths() map[wgkey.Key]PeerPath {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	relayUp := c.relay != nil && c.relay.Connected()
	out := make(map[wgkey.Key]PeerPath, len(c.peers))
	for k, p := range c.peers {
		pp := PeerPath{Key: k}
		if d := c.directPathLocked(p, now); d.IsValid() {
			pp.Kind, pp.Addr, pp.Latency = "direct", d, p.candidates[d].latency
		} else if relayUp {
			pp.Kind = "relay"
		}
		out[k] = pp
	}
	return out
}
