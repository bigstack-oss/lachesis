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
}

func bpfDefaults() BPFConfig {
	return BPFConfig{
		PinPath: "/sys/fs/bpf/telemetry",
	}
}

// Validate checks the pin path is absolute.
func (c BPFConfig) Validate() error {
	if c.PinPath == "" {
		return errors.New("pin_path is empty")
	}
	if !filepath.IsAbs(c.PinPath) {
		return fmt.Errorf("pin_path %q must be absolute", c.PinPath)
	}
	return nil
}
