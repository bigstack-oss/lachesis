// Agent-log assertions: reading what the agent itself wrote, for
// behaviour that has no /metrics series.

package steps

import (
	"context"
	"fmt"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/agentctl"
)

// DefaultAgentLogTimeout bounds [AssertAgentLogStep]'s wait for the
// record to appear in the log after the agent's (re)start.
const DefaultAgentLogTimeout = 30 * time.Second

// AssertAgentLogStep asserts that the newest log record with message Msg,
// written by the agent's current run, carries attribute Attr equal to
// Want. Place it after a [RestartAgentStep], so the record read is the
// restarted agent's own. A wrong value is recorded as a FAILING ROW (the
// defect itself); a record that never appears is a mechanical error.
type AssertAgentLogStep struct {
	// Node selects the agent: a placement slot or literal host; empty
	// means the sole agent.
	Node string
	// Msg is the record's message, e.g. "serving". Shell-safe.
	Msg string
	// Attr is the top-level JSON key to check, e.g. "scrape_interval".
	Attr string
	// Want is the attribute's expected value, as a string.
	Want string
	// Timeout overrides [DefaultAgentLogTimeout].
	Timeout time.Duration
}

func (AssertAgentLogStep) Kind() string { return "assert-agent-log" }

func (AssertAgentLogStep) HostNeeds() scenariotest.HostNeeds {
	return scenariotest.HostNeeds{AgentSSH: true}
}

func (s AssertAgentLogStep) Run(ctx context.Context, env *scenariotest.StepEnv) error {
	ctl, err := agentctl.For(env, s.Node)
	if err != nil {
		return fmt.Errorf("assert-agent-log: %w", err)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultAgentLogTimeout
	}
	rec, err := ctl.AwaitLog(ctx, s.Msg, timeout)
	if err != nil {
		return fmt.Errorf("assert-agent-log: %w", err)
	}
	got, ok := rec[s.Attr].(string)
	pass := ok && got == s.Want
	row := scenariotest.AssertRow{Tenant: "-", Zone: "-", Direction: "-", Pass: pass,
		Note: fmt.Sprintf("%s log %s=%q", s.Msg, s.Attr, s.Want)}
	if pass {
		env.Log.Info("agent log attr as expected", "msg", s.Msg, "attr", s.Attr, "value", got)
	} else {
		env.Log.Warn("agent log attr mismatch", "msg", s.Msg, "attr", s.Attr,
			"got", fmt.Sprintf("%v (%T)", rec[s.Attr], rec[s.Attr]), "want", s.Want)
		row.Delta = -1
	}
	env.AddRow(row)
	return nil
}
