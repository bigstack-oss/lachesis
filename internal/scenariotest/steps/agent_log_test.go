package steps

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
	"github.com/bigstack-oss/lachesis/internal/scenariotest/fake"
)

// logExec models the agent host's log: the unit started at epoch 1000
// and `tac | grep` returns line for the requested msg.
type logExec struct {
	Calls []fake.ExecCall
	line  string
}

func (e *logExec) Run(_ context.Context, addr, command string) (string, error) {
	e.Calls = append(e.Calls, fake.ExecCall{Addr: addr, Command: command})
	switch {
	case strings.Contains(command, "ActiveEnterTimestamp"):
		return "1000\n", nil
	case strings.Contains(command, "tac "):
		return e.line, nil
	}
	return "", fmt.Errorf("unexpected command %q", command)
}

func logLine(ts, interval string) string {
	return fmt.Sprintf(`{"time":%q,"level":"INFO","msg":"serving","scrape_interval":%s}`+"\n", ts, interval)
}

func TestAssertAgentLog(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k"}
	// 1970-01-01T00:20:00Z is epoch 1200, after the unit's start at 1000.
	fresh := "1970-01-01T00:20:00Z"
	stale := "1970-01-01T00:10:00Z"

	cases := []struct {
		name     string
		line     string
		wantErr  string
		wantPass bool
	}{
		{"human duration", logLine(fresh, `"10s"`), "", true},
		{"integer nanoseconds", logLine(fresh, `10000000000`), "", false},
		{"wrong value", logLine(fresh, `"5s"`), "", false},
		{"record from a previous run", logLine(stale, `"10s"`), "within", false},
		{"no record yet", "", "within", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exec := &logExec{line: c.line}
			step := AssertAgentLogStep{Msg: "serving", Attr: "scrape_interval", Want: "10s", Timeout: 50 * time.Millisecond}
			env := restartEnv(t, agents, ac, exec, nil)
			err := step.Run(context.Background(), env)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("error = %v, want it to contain %q", err, c.wantErr)
			case c.wantErr != "":
				return
			}
			rows := env.Report.Rows
			if len(rows) != 1 || rows[0].Pass != c.wantPass {
				t.Fatalf("rows = %+v, want one row with Pass=%v", rows, c.wantPass)
			}
		})
	}
}

func TestAssertAgentLog_ReadsConfiguredLogPath(t *testing.T) {
	agents := []scenariotest.AgentConfig{{Host: "compute-0", MetricsURL: "http://c0/m"}}
	ac := scenariotest.AgentControlConfig{User: "root", KeyPath: "/k", LogPath: "/tmp/x.log"}
	exec := &logExec{line: logLine("1970-01-01T00:20:00Z", `"10s"`)}
	step := AssertAgentLogStep{Msg: "serving", Attr: "scrape_interval", Want: "10s"}
	if err := step.Run(context.Background(), restartEnv(t, agents, ac, exec, nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exec.Calls[len(exec.Calls)-1].Command, "/tmp/x.log") {
		t.Errorf("did not read the configured log_path: %+v", exec.Calls)
	}
}
