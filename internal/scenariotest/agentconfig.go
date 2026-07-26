// agentconfig.go derives a modified agent config from the one already on
// the node, for [RestartAgentStep.SetConfig].
//
// Deriving is the whole point. An agent config carries cluster-specific
// values — broker list, WAL path, credentials file — so a checked-in
// alternate config could never be dropped onto an arbitrary host, and a
// hand-staged one (the older AltConfig convention) is an undocumented
// manual prerequisite that makes a scenario unrunnable on a fresh
// cluster. SetConfig instead reads what the node already has, overrides
// only the named keys, and writes it back.

package scenariotest

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// applySetConfig reads the agent config at path on host, overrides the
// dotted keys in set, and writes the result back.
//
// With backup set it first copies the original to <path>.scenariotest.bak,
// so a later [RestartAgentStep.RestoreConfig] puts it back untouched. A
// mid-scenario reload passes false: its source is a config an earlier
// restart already patched, and backing up again would overwrite that
// restart's copy of the REAL config with the patched one — leaving the
// scenario no way home.
//
// Comments and key order in the rewritten file are NOT preserved (it is
// a YAML round-trip through a map). That is acceptable because the file
// is a scenario-scoped temporary and the pristine original is the backup
// that gets restored.
func applySetConfig(ctx context.Context, exec VMExec, host, path string, set map[string]string, backup bool) error {
	raw, err := exec.Run(ctx, host, "sudo cat "+path)
	if err != nil {
		return fmt.Errorf("read agent config %s on %s: %w (output: %s)", path, host, err, raw)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("parse agent config %s on %s: %w", path, host, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	// Sorted so overlapping paths resolve the same way on every run.
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := setDotted(doc, k, set[k]); err != nil {
			return err
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("re-marshal agent config: %w", err)
	}
	// base64 so arbitrary YAML (quotes, newlines, $, backticks) crosses the
	// SSH command line untouched — the encoded form is alphanumeric, + / =
	// only, so nothing in the config can break out of the command.
	cmd := fmt.Sprintf("printf %%s %s | base64 -d | sudo tee %s >/dev/null",
		base64.StdEncoding.EncodeToString(out), path)
	if backup {
		cmd = fmt.Sprintf("sudo cp -f %s %s.scenariotest.bak && %s", path, path, cmd)
	}
	if o, err := exec.Run(ctx, host, cmd); err != nil {
		return fmt.Errorf("write agent config %s on %s: %w (output: %s)", path, host, err, o)
	}
	return nil
}

// setDotted assigns value at the dotted key path in doc, creating
// intermediate sections as needed.
//
// The value is decoded as a YAML scalar rather than stored as a string,
// so it lands with its natural type: "0.0001" becomes a float, "false" a
// bool, "60s" a string — exactly as if it had been typed into the file.
// Writing everything as a string would be rejected by the agent's strict
// config decoding.
func setDotted(doc map[string]any, dotted, value string) error {
	parts := strings.Split(dotted, ".")
	var scalar any
	if err := yaml.Unmarshal([]byte(value), &scalar); err != nil {
		return fmt.Errorf("set_config %q: value %q is not a YAML scalar: %w", dotted, value, err)
	}
	cur := doc
	for i, p := range parts {
		if p == "" {
			return fmt.Errorf("set_config %q: empty path segment", dotted)
		}
		if i == len(parts)-1 {
			cur[p] = scalar
			return nil
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			if cur[p] != nil {
				return fmt.Errorf("set_config %q: %q is a value, not a section",
					dotted, strings.Join(parts[:i+1], "."))
			}
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	return nil
}
