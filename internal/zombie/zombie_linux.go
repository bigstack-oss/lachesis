//go:build linux

package zombie

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/lachesis/internal/tcattach"
)

// Hunt enumerates every TC filter the kernel knows about and
// deletes any whose name matches the agent's own telemetry filters
// (see [tcattach.Hooks]). It returns the count of filters
// successfully deleted.
//
// Hunt is best-effort. Per-link netlink errors during enumeration
// are expected — most links have no clsact qdisc — and are silently
// skipped (see [tcattach.TelemetryFilters]). Per-filter
// FilterDel failures are logged at warn and aggregated into the
// returned error, but do not abort the scan: a partial cleanup is
// still safer than no cleanup. Callers should treat the returned
// error as a hygiene warning, not a fatal startup condition.
func Hunt() (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, fmt.Errorf("zombie: list links: %w", err)
	}

	var (
		cleaned int
		delErrs []error
	)
	for _, link := range links {
		// Scan by name only, not the exact attach slot: an orphan from
		// an older build may sit at a different priority, and every
		// telemetry-named filter at boot is an orphan.
		for _, f := range tcattach.TelemetryFilters(link) {
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

	if len(delErrs) > 0 {
		return cleaned, fmt.Errorf("zombie: %d filter deletes failed: %w", len(delErrs), errors.Join(delErrs...))
	}
	return cleaned, nil
}
