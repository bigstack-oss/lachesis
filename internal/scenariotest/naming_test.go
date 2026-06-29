package scenariotest

import (
	"regexp"
	"testing"
)

func TestMangle(t *testing.T) {
	if got := Mangle("scenariotest", "a1b2c3", "net-T1"); got != "scenariotest-a1b2c3-net-T1" {
		t.Errorf("Mangle = %q", got)
	}
	if got := MangleProject("scenariotest", "T1"); got != "scenariotest-T1" {
		t.Errorf("MangleProject = %q", got)
	}
}

func TestNewRunID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{6}$`)
	a, err := NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString(a) {
		t.Errorf("run id %q is not 6 hex chars", a)
	}
	b, _ := NewRunID()
	if a == b {
		t.Errorf("two run ids collided: %q", a)
	}
}
