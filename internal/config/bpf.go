package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
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
	// A prefix match on a veth is refused (OVN metadata-proxy veths
	// share the tap naming).
	AttachPrefixes []string `yaml:"attach_prefixes"`
	// AttachInterfaces is an explicit allowlist of interface names
	// the netlink subscriber will attach to even when they do not
	// match a prefix, whatever their link type. Empty by default. Use
	// for outliers such as a dedicated test interface.
	AttachInterfaces []string `yaml:"attach_interfaces"`
	// AttachResyncInterval is the cadence of the netlink subscriber's
	// attach-presence sweep, which re-attaches any allowlisted
	// interface the kernel shows without the telemetry filters (a
	// missed netlink event, a filter removed out-of-band). Zero
	// disables the sweep; otherwise at least minAttachResyncInterval.
	// Load-time: a change takes effect at the next restart.
	//
	// docs/architecture/boot-and-recovery.md#attach-presence-resync
	AttachResyncInterval time.Duration `yaml:"attach_resync_interval"`
	// UnsafeAllowUnpinnedMaps lets the agent boot when the
	// counter-bearing maps cannot be pinned, degrading crash recovery
	// from zero-loss to the ≤60s WAL-bounded path. Default false is
	// strict: no pinning, no start.
	//
	// It only ever permits UNPINNED operation. An incompatible pin is
	// never adopted — it is removed and recreated fresh.
	//
	// docs/architecture/boot-and-recovery.md#agent-crash-process-killed-kernel-intact
	UnsafeAllowUnpinnedMaps bool `yaml:"unsafe_allow_unpinned_maps"`
}

func bpfDefaults() BPFConfig {
	return BPFConfig{
		PinPath:        "/sys/fs/bpf/lachesis",
		AttachPrefixes: []string{"tap"},
		// Explicit empty (not nil) so the shipped example YAML, which
		// lists `attach_interfaces: []`, round-trips equal to Defaults
		// under the drift test's reflect.DeepEqual.
		AttachInterfaces:     []string{},
		AttachResyncInterval: 60 * time.Second,
	}
}

// Validate checks the pin path is absolute, rejects empty entries
// in the attach allowlists, and bounds the resync interval. None of the three attach knobs is checked
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
	if c.AttachResyncInterval < 0 || (c.AttachResyncInterval > 0 && c.AttachResyncInterval < minAttachResyncInterval) {
		return fmt.Errorf("attach_resync_interval %v must be 0 (disabled) or >= %v", c.AttachResyncInterval, minAttachResyncInterval)
	}
	return nil
}
