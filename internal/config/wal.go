package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// WALConfig groups settings for the write-ahead log.
//
// Enabled=false disables both the boot-time restore and the
// periodic flush goroutine; intended for ephemeral test runs and
// for hosts where the BPF map is the only state of record.
type WALConfig struct {
	Path          string        `yaml:"path"`
	FlushInterval time.Duration `yaml:"flush_interval"`
	Enabled       bool          `yaml:"enabled"`
}

func walDefaults() WALConfig {
	return WALConfig{
		Path:          "/var/lib/lachesis/network_agent_state.json",
		FlushInterval: 60 * time.Second,
		Enabled:       true,
	}
}

// Validate skips path / interval checks when the WAL is disabled —
// a disabled WAL is intentionally a no-op subsystem.
func (c WALConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Path == "" {
		return errors.New("path is empty")
	}
	if !filepath.IsAbs(c.Path) {
		return fmt.Errorf("path %q must be absolute", c.Path)
	}
	if c.FlushInterval < time.Second {
		return fmt.Errorf("flush_interval %v is too small (minimum 1s)", c.FlushInterval)
	}
	return nil
}
