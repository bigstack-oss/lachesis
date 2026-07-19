package config

import (
	"fmt"
	"time"
)

// UnresolvedConfig bounds the late-binding buffer for flows whose VM
// MAC the metadata layer hasn't learned yet (docs/architecture/data-structures.md#lingering-ghost).
// Both fields are hot-reloadable on SIGHUP; a cap shrink simply
// triggers the buffer's normal LRU eviction on the next admission.
type UnresolvedConfig struct {
	// Cap is the buffer's entry bound. Its EXISTENCE is Contract 1
	// (docs/architecture/contracts.md#required-contracts — an unbounded
	// buffer OOMs under a Kafka outage); only the value is tunable.
	Cap int `yaml:"cap"`
	// TTL is the late-binding window: how long a buffered flow waits
	// for its MAC to resolve before folding to the "unknown" tenant.
	TTL time.Duration `yaml:"ttl"`
}

// unresolvedDefaults returns the docs/architecture/data-structures.md#lingering-ghost baseline: 10k entries, 60s.
func unresolvedDefaults() UnresolvedConfig {
	return UnresolvedConfig{Cap: 10_000, TTL: 60 * time.Second}
}

// Validate enforces Contract 1's floor — the cap must exist — and a
// non-degenerate window.
func (c UnresolvedConfig) Validate() error {
	if c.Cap < 1 {
		return fmt.Errorf("unresolved cap %d must be >= 1 (Contract 1: the buffer must stay bounded)", c.Cap)
	}
	if c.TTL <= 0 {
		return fmt.Errorf("unresolved ttl %v must be > 0", c.TTL)
	}
	return nil
}
