// Package kafka consumes OpenStack oslo.messaging notifications and kicks
// a Neutron reconcile on every committed metadata change, so the trie and
// mac_tenant_map refresh within one pass instead of waiting for the
// periodic safety net (docs/DESIGN.md §5.7, §9). It is a Service in the
// package-anatomy sense (docs/DESIGN.md §13.4): the [Consumer] owns a
// long-running loop started by the agent's worker table.
//
// # Why kick instead of apply
//
// The consumer deliberately does NOT parse event payloads or touch the
// kernel maps. A committed Neutron event means "metadata changed"; the
// reconciler then re-reads authoritative state from Neutron and applies
// the delta. Routing every update through the single reconciler goroutine
// keeps one applier for both the timer and Kafka — no lock, no parallel
// apply path — and guarantees the post-event trie matches a cold-start at
// the same point in time. The cost is one Neutron Sync per debounced
// burst, the same operation the 5-minute reconcile already runs.
package kafka

import (
	"context"
	"log/slog"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"github.com/bigstack-oss/lachesis/internal/boot"
)

// Trigger is the reconcile kick the consumer fires on a Neutron change.
// *reconcile.Reconciler satisfies it via its Kick method; tests wire a
// recording fake.
type Trigger interface {
	Kick()
}

// messageReader is the slice of *kafkago.Reader the consumer depends on,
// declared as the minimal seam so tests drive the loop without a broker.
type messageReader interface {
	ReadMessage(ctx context.Context) (kafkago.Message, error)
	Stats() kafkago.ReaderStats
	Close() error
}

// Consumer reads notifications from Kafka and kicks a reconcile on every
// committed Neutron metadata change. Construct with [New], then run
// [Consumer.Run] on a long-lived goroutine.
type Consumer struct {
	reader  messageReader
	trigger Trigger
	seq     *boot.Sequencer
	mx      *Metrics
	topic   string
}

// Options bundles the inputs to [New]. Reader, Trigger, and Metrics are
// required; Seq is optional (nil skips the boot barrier, used by tests);
// Topic labels the metrics.
type Options struct {
	Reader  messageReader
	Trigger Trigger
	Seq     *boot.Sequencer
	Metrics *Metrics
	Topic   string
}

// New constructs a Consumer from opts.
func New(opts Options) *Consumer {
	return &Consumer{
		reader:  opts.Reader,
		trigger: opts.Trigger,
		seq:     opts.Seq,
		mx:      opts.Metrics,
		topic:   opts.Topic,
	}
}

// Run consumes until ctx is cancelled. It first blocks on
// [boot.PhaseStateRestored] so a kick can't fire before the reconciler is
// ready to apply; if the boot aborts (or ctx is cancelled) before that
// phase, Run returns without consuming. The reader is closed on exit.
func (c *Consumer) Run(ctx context.Context) {
	if c.seq != nil {
		if err := c.seq.Await(ctx, boot.PhaseStateRestored); err != nil {
			slog.Info("kafka consumer stopping before first read",
				"component", component, "err", err)
			return
		}
	}
	defer func() { _ = c.reader.Close() }()
	for {
		msg, err := c.reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // cancelled — normal shutdown
			}
			c.mx.RecordConsumeError(c.topic)
			slog.Warn("kafka read failed; retrying",
				"component", component, "topic", c.topic, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(consumeErrorBackoff):
			}
			continue
		}
		c.handle(msg.Value)
		c.mx.SetLag(c.topic, c.reader.Stats().Lag)
	}
}

// handle decodes one message and kicks a reconcile if it is a committed
// Neutron metadata change. Non-Neutron events (Nova, Cinder, …) on the
// shared topic and malformed messages are ignored — the former are
// expected, the latter unexpected and logged.
func (c *Consumer) handle(value []byte) {
	eventType, publisherID, ok := decodeEvent(value)
	if !ok {
		slog.Warn("kafka: undecodable notification; skipped", "component", component)
		return
	}
	if isNeutronChange(eventType, publisherID) {
		c.trigger.Kick()
	}
}
