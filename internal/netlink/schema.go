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
