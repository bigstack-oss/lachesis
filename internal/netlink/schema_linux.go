//go:build linux

// schema_linux.go gathers package netlink's Linux-only package-level
// constants and data types: the slog component label, the
// event-channel depth, and the re-subscribe backoff schedule.
// Cross-platform constants (the iface_kind metric label values, which
// [NewMetrics] seeds on every platform) live in schema.go.

package netlink

import "time"

const component = "netlink"

// eventChanDepth bounds the buffered link events between the netlink
// library's receive goroutine and our consume loop. The library runs
// its own goroutine that does the socket Receive and feeds this channel
// (see LinkSubscribeWithOptions), so while we are busy attaching one tap
// the library keeps draining the kernel socket into this buffer. The
// depth therefore sets how large a burst of NEWLINK events — e.g. a
// mass VM launch on one host — we absorb before backpressure reaches
// the socket. Sized for hundreds of simultaneous taps with headroom;
// 64 (the previous value) could overflow during a node-wide boot.
//
// If sustained churn does outrun attach throughput and the socket
// overflows, the library reports a fatal Receive error (ENOBUFS); the
// subscriber logs it, counts a restart and re-subscribes, opening the
// new stream with an attach-presence sweep for the events the overflow
// dropped.
const eventChanDepth = 512

// resubscribeBackoffMin and resubscribeBackoffMax bound the delay
// before re-subscribing after a lost subscription: it starts at the
// minimum, doubles per consecutive loss, and caps at the maximum. A
// stream that stayed up for at least the maximum resets it, so an
// isolated loss after a long healthy run retries quickly.
const (
	resubscribeBackoffMin = time.Second
	resubscribeBackoffMax = 30 * time.Second
)

// backoffPolicy is the re-subscribe delay schedule (see
// resubscribeBackoffMin / resubscribeBackoffMax).
type backoffPolicy struct {
	min, max time.Duration
}
