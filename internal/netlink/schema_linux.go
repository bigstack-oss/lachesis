//go:build linux

// schema_linux.go gathers package netlink's Linux-only package-level
// constants: the slog component label and the event-channel depth.
// Cross-platform constants (the iface_kind metric label values, which
// [NewMetrics] seeds on every platform) live in schema.go.

package netlink

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
// overflows, the library reports a fatal Receive error (ENOBUFS), which
// surfaces as a logged subscriber exit — never a silent miss.
const eventChanDepth = 512
