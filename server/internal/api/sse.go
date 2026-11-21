package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type sseMessage struct {
	Event string
	Data  []byte
}

type Hub struct {
	mu          sync.RWMutex
	clients     map[chan sseMessage]struct{}
	OnSubscribe func() []sseMessage
}

func NewHub() *Hub {
	return &Hub{clients: make(map[chan sseMessage]struct{})}
}

func NewSSEMessage(event string, payload any) (sseMessage, bool) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return sseMessage{}, false
	}
	return sseMessage{Event: event, Data: raw}, true
}

func (h *Hub) Publish(event string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := sseMessage{Event: event, Data: raw}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	if h.OnSubscribe != nil {
		for _, msg := range h.OnSubscribe() {
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, string(msg.Data))
		}
	}
	flusher.Flush()

	ch := make(chan sseMessage, 32)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case msg := <-ch:
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, string(msg.Data))
			flusher.Flush()
		}
	}
}
