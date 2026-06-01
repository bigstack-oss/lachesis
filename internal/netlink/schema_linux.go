//go:build linux

// schema_linux.go gathers package netlink's Linux-only package-level
// constants: the slog component label, the event-channel depth, and the
// iface_kind metric label values. Every netlink source that declares
// constants is //go:build linux (subscriber_linux.go), so these live in a
// linux-tagged file rather than an untagged schema.go. The cross-platform
// Subscriber / Attacher seams (subscriber.go) and the Registry
// (registry.go) carry no package-level constants.

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

// iface_kind label values for cubecos_tc_attach_failures_total: "tap"
// for prefix-matched links, "other" for explicit-allowlist entries.
// [linuxSubscriber.kindFor] produces these; the Help string in
// metrics.go documents the same pair.
const (
	ifaceKindTap   = "tap"
	ifaceKindOther = "other"
)
