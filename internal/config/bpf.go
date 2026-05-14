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
	// AttachInterface is the name of the host interface the telemetry
	// programs are attached to via TC clsact. Empty disables attach —
	// useful for tests that perform their own attach and for hosts
	// where attach is managed out-of-band. Multi-interface attach and
	// netlink-driven auto-attach land in a later sprint.
	AttachInterface string `yaml:"attach_interface"`
}

func bpfDefaults() BPFConfig {
	return BPFConfig{
		PinPath: "/sys/fs/bpf/telemetry",
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
