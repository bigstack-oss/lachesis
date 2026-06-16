package kafka

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	kafkago "github.com/segmentio/kafka-go"
)

// oslo builds an oslo.messaging envelope (doubly-encoded) for the given
// event_type and publisher_id, matching the wire format observed on
// dev-cmp's notifications.info.
func oslo(eventType, publisherID string) []byte {
	inner, _ := json.Marshal(map[string]any{
		"event_type":   eventType,
		"publisher_id": publisherID,
		"payload":      map[string]any{"ignored": true},
	})
	env, _ := json.Marshal(map[string]string{
		"oslo.version": "2.0",
		"oslo.message": string(inner),
	})
	return env
}

func TestDecodeEvent(t *testing.T) {
	et, pub, ok := decodeEvent(oslo("port.create.end", "network.dev-cmp"))
	if !ok || et != "port.create.end" || pub != "network.dev-cmp" {
		t.Fatalf("decodeEvent = (%q, %q, %v), want (port.create.end, network.dev-cmp, true)", et, pub, ok)
	}
	if _, _, ok := decodeEvent([]byte("not json")); ok {
		t.Error("decodeEvent accepted malformed outer JSON")
	}
	if _, _, ok := decodeEvent([]byte(`{"oslo.version":"2.0"}`)); ok {
		t.Error("decodeEvent accepted envelope with no oslo.message")
	}
	if _, _, ok := decodeEvent([]byte(`{"oslo.message":"not json"}`)); ok {
		t.Error("decodeEvent accepted malformed inner JSON")
	}
}

func TestIsNeutronChange(t *testing.T) {
	cases := []struct {
		event, publisher string
		want             bool
	}{
		{"port.create.end", "network.dev-cmp", true},
		{"subnet.delete.end", "network.dev-cmp", true},
		{"router.update.end", "network.cc1", true},
		{"network.create.end", "network.dev-cmp", true},
		{"port.create.start", "network.dev-cmp", false},         // pre-commit
		{"port.create.end", "compute.dev-cmp", false},           // Nova, not Neutron
		{"security_group.create.end", "network.dev-cmp", false}, // not modelled
		{"volume.create.end", "cinder-volume.dev-cmp", false},   // Cinder
	}
	for _, c := range cases {
		if got := isNeutronChange(c.event, c.publisher); got != c.want {
			t.Errorf("isNeutronChange(%q, %q) = %v, want %v", c.event, c.publisher, got, c.want)
		}
	}
}

type fakeTrigger struct {
	mu    sync.Mutex
	kicks int
}

func (f *fakeTrigger) Kick() {
	f.mu.Lock()
	f.kicks++
	f.mu.Unlock()
}

func (f *fakeTrigger) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.kicks
}

func TestHandle_KicksOnlyOnNeutronChange(t *testing.T) {
	ft := &fakeTrigger{}
	c := New(Options{Trigger: ft, Metrics: NewMetrics("notifications.info"), Topic: "notifications.info"})

	c.handle(oslo("port.create.end", "network.dev-cmp"))   // kick
	c.handle(oslo("volume.create.end", "cinder.dev-cmp"))  // ignore (Cinder)
	c.handle(oslo("port.create.start", "network.dev-cmp")) // ignore (pre-commit)
	c.handle([]byte("garbage"))                            // ignore (malformed)
	c.handle(oslo("router.update.end", "network.dev-cmp")) // kick

	if ft.count() != 2 {
		t.Errorf("kicks = %d, want 2 (the two committed Neutron changes)", ft.count())
	}
}

// fakeReader delivers canned messages then blocks until ctx is cancelled,
// modelling a quiet topic that the consumer shuts down on.
type fakeReader struct {
	msgs   []kafkago.Message
	i      int
	closed bool
}

func (f *fakeReader) ReadMessage(ctx context.Context) (kafkago.Message, error) {
	if f.i < len(f.msgs) {
		m := f.msgs[f.i]
		f.i++
		return m, nil
	}
	<-ctx.Done()
	return kafkago.Message{}, ctx.Err()
}
func (f *fakeReader) Stats() kafkago.ReaderStats { return kafkago.ReaderStats{} }
func (f *fakeReader) Close() error               { f.closed = true; return nil }

// TestRun_ConsumesKicksAndShutsDown drives the full loop: a Neutron event
// in the stream triggers a kick, and Run exits cleanly on cancel, closing
// the reader.
func TestRun_ConsumesKicksAndShutsDown(t *testing.T) {
	ft := &fakeTrigger{}
	fr := &fakeReader{msgs: []kafkago.Message{
		{Value: oslo("port.create.end", "network.dev-cmp")},
	}}
	c := New(Options{Reader: fr, Trigger: ft, Metrics: NewMetrics("t"), Topic: "t"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for ft.count() == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("consumer did not kick on a Neutron event")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
	if !fr.closed {
		t.Error("Run did not close the reader on exit")
	}
}
