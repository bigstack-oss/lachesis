package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// BPFConfig groups settings for the eBPF subsystem.
type BPFConfig struct {
	// PinPath is the BPF FS directory under which maps and programs are
	// pinned. Must be absolute.
	PinPath string `yaml:"pin_path"`
	// AttachPrefixes is the list of interface-name prefixes the
	// netlink subscriber treats as eligible for attach. A new
	// interface matches when its name starts with any prefix here.
	// Default: ["tap"] — the OVN/Neutron convention for VM ports.
	AttachPrefixes []string `yaml:"attach_prefixes"`
	// AttachInterfaces is an explicit allowlist of interface names
	// the netlink subscriber will attach to even when they do not
	// match a prefix. Empty by default. Use for outliers such as a
	// dedicated test interface.
	AttachInterfaces []string `yaml:"attach_interfaces"`
	// UnsafeAllowUnpinnedMaps, when true, lets the agent boot even
	// when the counter-bearing maps cannot be pinned under PinPath
	// (e.g. /sys/fs/bpf is not a mounted bpf filesystem). It then
	// runs with unpinned maps, degrading agent-crash recovery from
	// zero-loss back to the ≤60s WAL-bounded path
	// (docs/architecture/boot-and-recovery.md#agent-crash-process-killed-kernel-intact).
	// The default (false) is strict mode: if pinning cannot be
	// established the agent refuses to start.
	//
	// This toggle only ever permits UNPINNED operation. It never
	// permits adopting an incompatible (wrong-sized) pin — a stale
	// pin is always removed and recreated fresh, never silently
	// reused (docs/architecture/contracts.md#deferred-work item 7).
	UnsafeAllowUnpinnedMaps bool `yaml:"unsafe_allow_unpinned_maps"`
}

func bpfDefaults() BPFConfig {
	return BPFConfig{
		PinPath:        "/sys/fs/bpf/lachesis",
		AttachPrefixes: []string{"tap"},
		// Explicit empty (not nil) so the shipped example YAML, which
		// lists `attach_interfaces: []`, round-trips equal to Defaults
		// under the drift test's reflect.DeepEqual.
		AttachInterfaces: []string{},
	}
}

// Validate checks the pin path is absolute and rejects empty entries
// in the attach allowlists. None of the three attach knobs is checked
// against the host's interface list — the agent's attach step does that
// and reports a more precise error. An entirely empty allowlist is
// allowed on purpose: it is the "attach managed out-of-band" mode the
// integration tests and some hosts rely on, and the agent logs that no
// attach source is configured at boot.
func (c BPFConfig) Validate() error {
	if c.PinPath == "" {
		return errors.New("pin_path is empty")
	}
	if !filepath.IsAbs(c.PinPath) {
		return fmt.Errorf("pin_path %q must be absolute", c.PinPath)
	}
	// An empty prefix is a silent footgun: it reads like a wildcard but
	// the subscriber's prefix match skips empty strings, so it matches
	// nothing. Reject it so a typo'd allowlist fails loudly at boot
	// rather than capturing zero telemetry.
	for i, p := range c.AttachPrefixes {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("attach_prefixes[%d] is empty; remove it or give a real prefix (an empty prefix matches nothing, not everything)", i)
		}
	}
	for i, name := range c.AttachInterfaces {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("attach_interfaces[%d] is empty", i)
		}
	}
	return nil
}
