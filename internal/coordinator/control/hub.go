package control

import "sync"

// hub tracks open WatchNetmap streams so that changes can be fanned out and
// nodes with at least one open stream count as online.
type hub struct {
	mu       sync.Mutex
	watchers map[string]map[*watcher]struct{} // node ID -> streams
	subs     map[chan struct{}]struct{}       // admin event listeners
}

type watcher struct {
	nodeID string
	notify chan struct{} // buffered(1): pending notifications coalesce
}

func newHub() *hub {
	return &hub{watchers: map[string]map[*watcher]struct{}{}, subs: map[chan struct{}]struct{}{}}
}

func (h *hub) add(nodeID string) *watcher {
	w := &watcher{nodeID: nodeID, notify: make(chan struct{}, 1)}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.watchers[nodeID] == nil {
		h.watchers[nodeID] = map[*watcher]struct{}{}
	}
	h.watchers[nodeID][w] = struct{}{}
	return w
}

func (h *hub) remove(w *watcher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.watchers[w.nodeID], w)
	if len(h.watchers[w.nodeID]) == 0 {
		delete(h.watchers, w.nodeID)
	}
}

func (h *hub) online(nodeID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.watchers[nodeID]) > 0
}

// broadcast wakes every open stream so it recomputes and resends its netmap.
func (h *hub) broadcast() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ws := range h.watchers {
		for w := range ws {
			select {
			case w.notify <- struct{}{}:
			default: // a notification is already pending
			}
		}
	}
	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (h *hub) subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}
