package scenariotest

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSetDotted_TypesAndNesting(t *testing.T) {
	// A blanket string would be rejected by the agent's strict config
	// decoding, so each value must land with its natural YAML type.
	cases := []struct {
		name, path, value string
		want              any
	}{
		{"float", "gc.pressure_high_watermark", "0.0001", 0.0001},
		{"bool", "kafka.enabled", "false", false},
		{"duration stays a string", "reconcile.interval", "60s", "60s"},
		{"int", "gc.pressure_max_per_pass", "1000", 1000},
		{"top-level key", "version", "1", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := map[string]any{}
			if err := setDotted(doc, tc.path, tc.value); err != nil {
				t.Fatalf("setDotted: %v", err)
			}
			got := doc
			parts := strings.Split(tc.path, ".")
			for _, p := range parts[:len(parts)-1] {
				next, ok := got[p].(map[string]any)
				if !ok {
					t.Fatalf("section %q missing, doc=%v", p, doc)
				}
				got = next
			}
			if v := got[parts[len(parts)-1]]; v != tc.want {
				t.Errorf("value = %#v (%T), want %#v (%T)", v, v, tc.want, tc.want)
			}
		})
	}
}

func TestSetDotted_PreservesSiblingsAndRejectsBadPaths(t *testing.T) {
	doc := map[string]any{
		"gc":     map[string]any{"ghost_grace": "120s"},
		"scrape": map[string]any{"interval": "10s"},
	}
	if err := setDotted(doc, "gc.pressure_high_watermark", "0.0001"); err != nil {
		t.Fatalf("setDotted: %v", err)
	}
	gc := doc["gc"].(map[string]any)
	if gc["ghost_grace"] != "120s" {
		t.Errorf("sibling key clobbered: %v", gc)
	}
	if doc["scrape"].(map[string]any)["interval"] != "10s" {
		t.Errorf("sibling section clobbered: %v", doc)
	}

	// Descending through a scalar is a config mistake, not a silent overwrite.
	if err := setDotted(doc, "scrape.interval.nope", "1"); err == nil {
		t.Error("descending into a scalar should error")
	}
	if err := setDotted(doc, "gc..x", "1"); err == nil {
		t.Error("empty path segment should error")
	}
}

// The end-to-end shape: read the node's own config, override only the
// named keys, back up, and write the patched YAML back base64-encoded.
func TestApplySetConfig_DerivesFromNodeConfig(t *testing.T) {
	const nodeConfig = `version: "1"
kafka:
  brokers:
    - 10.32.36.10:9095
gc:
  ghost_grace: 120s
scrape:
  interval: 10s
`
	exec := &restartExec{catOut: nodeConfig}
	err := applySetConfig(context.Background(), exec, "10.0.0.1", "/root/agent.yaml",
		map[string]string{
			"gc.pressure_high_watermark": "0.0001",
			"gc.pressure_low_watermark":  "0.00005",
		})
	if err != nil {
		t.Fatalf("applySetConfig: %v", err)
	}

	if !exec.has("sudo cat /root/agent.yaml") {
		t.Error("did not read the node's existing config")
	}
	if !exec.has("sudo cp -f /root/agent.yaml /root/agent.yaml.scenariotest.bak") {
		t.Error("did not back up the original (RestoreConfig would have nothing to restore)")
	}

	// Recover what was written and check it is the node's config plus the
	// two overrides — cluster-specific values must survive.
	var written string
	for _, c := range exec.calls {
		if m := regexp.MustCompile(`printf %s ([A-Za-z0-9+/=]+) \| base64 -d`).FindStringSubmatch(c.command); m != nil {
			b, err := base64.StdEncoding.DecodeString(m[1])
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			written = string(b)
		}
	}
	if written == "" {
		t.Fatal("no base64 write command issued")
	}
	var got map[string]any
	if err := yaml.Unmarshal([]byte(written), &got); err != nil {
		t.Fatalf("written config is not valid YAML: %v\n%s", err, written)
	}
	gc, _ := got["gc"].(map[string]any)
	if gc["pressure_high_watermark"] != 0.0001 || gc["pressure_low_watermark"] != 0.00005 {
		t.Errorf("overrides not applied: %v", gc)
	}
	if gc["ghost_grace"] != "120s" {
		t.Errorf("untouched key in the same section was lost: %v", gc)
	}
	// The cluster-specific bits are exactly why this derives instead of
	// shipping a static file.
	kafka, _ := got["kafka"].(map[string]any)
	brokers, _ := kafka["brokers"].([]any)
	if len(brokers) != 1 || brokers[0] != "10.32.36.10:9095" {
		t.Errorf("cluster-specific kafka.brokers lost: %v", kafka)
	}
	if got["scrape"].(map[string]any)["interval"] != "10s" {
		t.Errorf("unrelated section lost: %v", got)
	}
}
