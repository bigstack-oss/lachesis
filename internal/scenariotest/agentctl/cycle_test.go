package agentctl

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// TestRemoveStateCmd pins the cold-restart removal command: WAL always
// (with its .bak), pins only on request, missing paths and the
// pins-without-WAL shape refused, shell-unsafe paths rejected.
func TestRemoveStateCmd(t *testing.T) {
	cases := []struct {
		name    string
		cycle   Cycle
		ac      scenariotest.AgentControlConfig
		want    string
		wantErr string
	}{
		{
			name:  "wal only",
			cycle: Cycle{RemoveWAL: true},
			ac:    scenariotest.AgentControlConfig{WALPath: "/var/lib/lachesis/wal.json"},
			want:  "sudo rm -f /var/lib/lachesis/wal.json /var/lib/lachesis/wal.json.bak",
		},
		{
			name:  "wal and pins",
			cycle: Cycle{RemoveWAL: true, RemovePins: true},
			ac:    scenariotest.AgentControlConfig{WALPath: "/var/lib/lachesis/wal.json", PinPath: "/sys/fs/bpf/lachesis"},
			want:  "sudo rm -f /var/lib/lachesis/wal.json /var/lib/lachesis/wal.json.bak && sudo rm -rf /sys/fs/bpf/lachesis",
		},
		{
			name:    "pins without wal refused",
			cycle:   Cycle{RemovePins: true},
			ac:      scenariotest.AgentControlConfig{PinPath: "/sys/fs/bpf/lachesis"},
			wantErr: "not a modeled failure shape",
		},
		{
			name:    "missing wal_path",
			cycle:   Cycle{RemoveWAL: true},
			ac:      scenariotest.AgentControlConfig{},
			wantErr: "agent_control.wal_path is empty",
		},
		{
			name:    "missing pin_path",
			cycle:   Cycle{RemoveWAL: true, RemovePins: true},
			ac:      scenariotest.AgentControlConfig{WALPath: "/w.json"},
			wantErr: "agent_control.pin_path is empty",
		},
		{
			name:    "shell-unsafe wal_path",
			cycle:   Cycle{RemoveWAL: true},
			ac:      scenariotest.AgentControlConfig{WALPath: "/tmp/wal; rm -rf /"},
			wantErr: "agent_control.wal_path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctl := &Controller{control: tc.ac, log: slog.New(slog.DiscardHandler)}
			got, err := ctl.removeStateCmd(tc.cycle)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("cmd = %q, want %q", got, tc.want)
			}
		})
	}
}
