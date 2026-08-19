// Package kafka consumes oslo.messaging notifications and kicks a
// Neutron reconcile on each committed metadata change, so metadata
// refreshes within a pass instead of waiting for the periodic net.
//
// It deliberately does NOT parse payloads or touch kernel maps. An
// event means only "metadata changed"; the reconciler re-reads
// authoritative state and applies the delta. Routing everything through
// that one goroutine keeps a single applier for both timer and Kafka —
// no lock, no parallel apply path — and makes the post-event trie
// identical to a cold start at the same instant.
//
// docs/architecture/trie-construction.md#incremental-updates
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
