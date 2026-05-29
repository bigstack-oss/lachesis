package config

import (
	"errors"
	"fmt"
	"path/filepath"
)

// BPFConfig groups settings for the eBPF subsystem.
type BPFConfig struct {
	// PinPath is the BPF FS directory under which maps and programs are
	// pinned. Must be absolute.
	PinPath string `yaml:"pin_path"`
	// AttachInterface is a single-interface static attach kept for
	// backwards compatibility with pre-Sprint-5 deployments. Empty
	// disables it. When set, the agent logs a deprecation warning at
	// boot — production deployments should rely on the netlink
	// subscriber's allowlist instead. Slated for removal in a
	// follow-up sprint.
	//
	// Deprecated: use AttachPrefixes / AttachInterfaces.
	AttachInterface string `yaml:"attach_interface"`
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
}

func bpfDefaults() BPFConfig {
	return BPFConfig{
		PinPath:        "/sys/fs/bpf/telemetry",
		AttachPrefixes: []string{"tap"},
	}
}

// Validate checks the pin path is absolute. AttachInterface, when set,
// is not validated against the host's interface list — the agent's
// attach step does that and reports a more precise error.
func (c BPFConfig) Validate() error {
	if c.PinPath == "" {
		return errors.New("pin_path is empty")
	}
	if !filepath.IsAbs(c.PinPath) {
		return fmt.Errorf("pin_path %q must be absolute", c.PinPath)
	}
	return nil
}
