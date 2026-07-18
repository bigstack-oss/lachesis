package config_test

import (
	"testing"

	"github.com/bigstack-oss/lachesis/internal/config"
)

func TestKafkaEffectiveGroupID(t *testing.T) {
	c := config.KafkaConfig{GroupID: "lachesis"}

	// Hostname is preferred and suffixed verbatim.
	if got := c.EffectiveGroupID("p4", "rand"); got != "lachesis-p4" {
		t.Errorf("EffectiveGroupID(p4) = %q, want lachesis-p4", got)
	}
	// Distinct hosts must get distinct groups — otherwise Kafka
	// load-balances the fanout stream and only one agent gets each event.
	if a, b := c.EffectiveGroupID("p4", "x"), c.EffectiveGroupID("p5", "x"); a == b {
		t.Fatalf("distinct hosts must get distinct groups; both = %q", a)
	}
	// Stable for the same host regardless of the fallback, so offset
	// tracking survives a restart.
	if a, b := c.EffectiveGroupID("p4", "x"), c.EffectiveGroupID("p4", "y"); a != b {
		t.Errorf("same host must be stable: %q != %q", a, b)
	}
	// Empty hostname (lookup failed) falls back to the random token, and
	// must NOT collapse to the bare shared GroupID — that would starve
	// peers of reconcile kicks and reintroduce the fanout bug.
	got := c.EffectiveGroupID("", "a3f9c2")
	if got != "lachesis-a3f9c2" {
		t.Errorf("empty host = %q, want lachesis-a3f9c2 (random fallback)", got)
	}
	if got == c.GroupID {
		t.Errorf("empty host must not collapse to the shared group %q", c.GroupID)
	}
}
