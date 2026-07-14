package api

import (
	"fmt"
	"sync"
	"time"
)

type EventBroker struct {
	mu          sync.Mutex
	events      []Event
	nextID      int64
	epoch       string
	maxEvents   int
	maxStreams  int
	subscribers map[chan Event]struct{}
}

func NewEventBroker(maxEvents int) *EventBroker {
	if maxEvents <= 0 {
		maxEvents = 512
	}
	b := &EventBroker{epoch: randomHex(16), maxEvents: maxEvents, maxStreams: 16, subscribers: map[chan Event]struct{}{}}
	b.Publish(Event{Type: "system.start", Severity: "info", ReasonCode: "api_started", Details: map[string]any{"plane": "control"}})
	return b
}

func (b *EventBroker) Publish(ev Event) Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	ev.ID = b.nextID
	ev.StreamEpoch = b.epoch
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if ev.Details == nil {
		ev.Details = map[string]any{}
	}
	b.events = append(b.events, ev)
	if len(b.events) > b.maxEvents {
		b.events = b.events[len(b.events)-b.maxEvents:]
	}
	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			close(ch)
			delete(b.subscribers, ch)
		}
	}
	return ev
}

func (b *EventBroker) Epoch() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.epoch
}

func (b *EventBroker) Recent(afterID int64, limit int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if limit <= 0 || limit > len(b.events) {
		limit = len(b.events)
	}
	var out []Event
	for _, ev := range b.events {
		if ev.ID > afterID {
			out = append(out, ev)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return append([]Event(nil), out...)
}

func (b *EventBroker) Subscribe() (chan Event, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.subscribers) >= b.maxStreams {
		return nil, false
	}
	ch := make(chan Event, 32)
	b.subscribers[ch] = struct{}{}
	return ch, true
}

func (b *EventBroker) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

func (s *Server) publishEvent(event Event) Event {
	published := s.broker.Publish(event)
	_ = s.persistEvent(published)
	return published
}

func (s *Server) persistEvent(event Event) error {
	if event.StreamEpoch == "" || event.ID <= 0 {
		return fmt.Errorf("event identity is incomplete")
	}
	return s.store.SaveJSON("events", fmt.Sprintf("%s:%020d", event.StreamEpoch, event.ID), event)
}
