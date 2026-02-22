package traffic

import "sync"

type LiveTraceEvent struct {
	Timestamp  string `json:"ts"`
	HostID     int64  `json:"hostId"`
	DomainID   int64  `json:"domainId"`
	FQDN       string `json:"fqdn"`
	Country    string `json:"country"`
	Class      string `json:"class"`
	Scanner    bool   `json:"scanner"`
	Status     int    `json:"status"`
	Path       string `json:"path"`
	SourceIP   string `json:"sourceIp,omitempty"`
	SourceType string `json:"sourceType"`
}

type LiveHub struct {
	mu     sync.RWMutex
	nextID int
	subs   map[int]chan LiveTraceEvent
}

func NewLiveHub() *LiveHub {
	return &LiveHub{
		subs: map[int]chan LiveTraceEvent{},
	}
}

func (h *LiveHub) SubscriberCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

func (h *LiveHub) Subscribe(buffer int) (int, <-chan LiveTraceEvent, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan LiveTraceEvent, buffer)
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	h.subs[id] = ch
	h.mu.Unlock()
	cancel := func() {
		h.mu.Lock()
		if existing, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(existing)
		}
		h.mu.Unlock()
	}
	return id, ch, cancel
}

func (h *LiveHub) Publish(ev LiveTraceEvent) {
	h.mu.RLock()
	if len(h.subs) == 0 {
		h.mu.RUnlock()
		return
	}
	chs := make([]chan LiveTraceEvent, 0, len(h.subs))
	for _, ch := range h.subs {
		chs = append(chs, ch)
	}
	h.mu.RUnlock()
	for _, ch := range chs {
		select {
		case ch <- ev:
		default:
		}
	}
}
