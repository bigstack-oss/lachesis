//go:build linux

package zombie

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/tcattach"
)

// Hunt enumerates every TC filter the kernel knows about and
// deletes any whose name matches the agent's own telemetry filters
// (see [tcattach.Hooks]). It returns the count of filters
// successfully deleted.
//
// Hunt is best-effort. Per-link netlink errors during enumeration
// are expected — most links have no clsact qdisc and FilterList
// returns an error for them — and are silently skipped. Per-filter
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
		// Iterate the agent's own (name, parent) hook table so the
		// hunt scans exactly the clsact slots tcattach attaches to —
		// a hook-location change is then a single edit in tcattach.
		for _, hook := range tcattach.Hooks {
			filters, ferr := netlink.FilterList(link, hook.Parent)
			if ferr != nil {
				// No clsact on this link/parent — most links are
				// in this state. Move on without noise.
				continue
			}
			for _, f := range filters {
				if !isTelemetryOrphan(f) {
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
	}

	if len(delErrs) > 0 {
		return cleaned, fmt.Errorf("zombie: %d filter deletes failed: %w", len(delErrs), errors.Join(delErrs...))
	}
	return cleaned, nil
}

// isTelemetryOrphan reports whether f was installed by a previous
// agent run. Only BPF filters whose name matches one of the agent's
// two telemetry slots qualify; any other filter (u32, generic, BPF
// installed by a different program) is left alone.
func isTelemetryOrphan(f netlink.Filter) bool {
	bf, ok := f.(*netlink.BpfFilter)
	if !ok {
		return false
	}
	return tcattach.IsTelemetryFilterName(bf.Name)
}
