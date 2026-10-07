// schema.go gathers package netlink's cross-platform package-level
// constants. Linux-only constants (the slog component label, the
// event-channel depth) live in schema_linux.go.

package netlink

// iface_kind label values for lachesis_tc_attach_failures_total: "tap"
// for prefix-matched links, "other" for explicit-allowlist entries.
// [linuxSubscriber.kindFor] produces these; [NewMetrics] seeds both at
// zero so the counter is visible before any failure occurs. The Help
// string in metrics.go documents the same pair.
const (
	ifaceKindTap   = "tap"
	ifaceKindOther = "other"
)

// outcome label values for lachesis_tc_reattach_total: "healed" when
// the attach-presence sweep re-attached a link, "failed" when its
// attempt errored on a still-present link. [NewMetrics] seeds every
// (iface_kind, outcome) pair at zero.
const (
	outcomeHealed = "healed"
	outcomeFailed = "failed"
)

// linkTypeVeth is the netlink.Link Type() of a veth pair end — the
// link kind [ShouldAttach] refuses on a prefix match.
const linkTypeVeth = "veth"

// reason label values for lachesis_netlink_skipped_interfaces_total.
// [ShouldAttach] returns these; [NewMetrics] seeds each at zero.
const skipReasonVeth = "veth"
