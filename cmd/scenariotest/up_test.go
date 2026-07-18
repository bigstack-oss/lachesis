package main

import (
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

func TestRefuseLiveState(t *testing.T) {
	dir := t.TempDir()
	save := func(name string, torn bool) string {
		rs := scenariotest.NewRunState("abc123", "twovms-same-tenant", "p")
		rs.TornDown = torn
		path := dir + "/" + name
		if err := rs.Save(path); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if err := refuseLiveState(dir + "/missing.json"); err != nil {
		t.Errorf("missing file must be fine: %v", err)
	}
	if err := refuseLiveState(save("torn.json", true)); err != nil {
		t.Errorf("torn-down leftover must be overwritable: %v", err)
	}
	if err := refuseLiveState(save("live.json", false)); err == nil || !strings.Contains(err.Error(), "live topology") {
		t.Errorf("live run-state must refuse with the down hint, got %v", err)
	}
	// A directory (any non-ENOENT read error) must surface, not pass.
	if err := refuseLiveState(dir); err == nil {
		t.Error("unreadable state path must error, not proceed to overwrite")
	}
}
