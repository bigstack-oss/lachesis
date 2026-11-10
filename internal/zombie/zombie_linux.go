//go:build linux

package zombie

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/lachesis/internal/tcattach"
)

// Hunt enumerates every TC filter the kernel knows about and deletes
// any whose name matches the agent's own telemetry filters (see
// [tcattach.Hooks]), except those it spares. It returns the count of
// filters successfully deleted.
//
// A filter is spared when attachable reports true for its link and the
// filter sits in the canonical slot ([tcattach.InCanonicalSlot]): the
// new agent's attach replaces it in place, atomically, and until then
// the old program keeps counting into the pinned telemetry_map instead
// of leaving the link uncounted across boot.
//
// Hunt is best-effort. Per-link netlink errors during enumeration
// are expected — most links have no clsact qdisc — and are silently
// skipped (see [tcattach.TelemetryFilters]). Per-filter
// FilterDel failures are logged at warn and aggregated into the
// returned error, but do not abort the scan: a partial cleanup is
// still safer than no cleanup. Callers should treat the returned
// error as a hygiene warning, not a fatal startup condition.
func Hunt(attachable func(netlink.Link) bool) (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, fmt.Errorf("zombie: list links: %w", err)
	}

	var (
		cleaned int
		spared  int
		delErrs []error
	)
	for _, link := range links {
		spare := attachable(link)
		// Scan by name only, not the exact attach slot: an orphan from
		// an older build may sit at a different priority, and the
		// attach's FilterReplace never replaces it.
		for _, f := range tcattach.TelemetryFilters(link) {
			if spare && tcattach.InCanonicalSlot(f) {
				spared++
				slog.Debug("spared filter for in-place replace",
					"component", component,
					"link", link.Attrs().Name,
					"handle", f.Attrs().Handle)
				continue
			}
			if derr := netlink.FilterDel(f); derr != nil {
				slog.Warn("delete orphan filter failed",
					"component", component,
					"link", link.Attrs().Name,
					"handle", f.Attrs().Handle,
					"err", derr)
				delErrs = append(delErrs, derr)
				continue
			}
			cleaned++
			slog.Info("deleted orphan filter",
				"component", component,
				"link", link.Attrs().Name,
				"handle", f.Attrs().Handle)
		}
	}
	if spared > 0 {
		slog.Info("spared canonical filters on attachable links",
			"component", component, "spared", spared)
	}

	if len(delErrs) > 0 {
		return cleaned, fmt.Errorf("zombie: %d filter deletes failed: %w", len(delErrs), errors.Join(delErrs...))
	}
	return cleaned, nil
}
