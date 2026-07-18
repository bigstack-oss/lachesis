package scenariotest

import (
	"strings"
	"testing"
)

func TestRequiredNodes(t *testing.T) {
	tests := []struct {
		name string
		p    Placement
		want int
	}{
		{name: "no placement", p: nil, want: 0},
		{name: "literals only", p: Placement{"vm-a": "compute-7"}, want: 0},
		{name: "single slot", p: Placement{"vm-a": "node:0"}, want: 1},
		{name: "count is max index plus one", p: Placement{"vm-a": "node:0", "vm-b": "node:2"}, want: 3},
		{name: "malformed slot ignored", p: Placement{"vm-a": "node:one"}, want: 0},
		{name: "mixed literal and slot", p: Placement{"vm-a": "node:1", "vm-b": "compute-7"}, want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RequiredNodes(&Scenario{Placement: tt.p}); got != tt.want {
				t.Errorf("RequiredNodes = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestResolvePlacement(t *testing.T) {
	agents := []AgentConfig{
		{Host: "cc1", MetricsURL: "http://cc1:9100/metrics"},
		{Host: "cc2", MetricsURL: "http://cc2:9100/metrics"},
	}
	tests := []struct {
		name    string
		in      Placement
		want    Placement
		wantErr string
	}{
		{name: "empty passes through", in: nil, want: nil},
		{
			name: "literal hostnames untouched",
			in:   Placement{"vm-a": "compute-7"},
			want: Placement{"vm-a": "compute-7"},
		},
		{
			name: "slots resolve by agent index",
			in:   Placement{"vm-a": "node:0", "vm-b": "node:1"},
			want: Placement{"vm-a": "cc1", "vm-b": "cc2"},
		},
		{
			name: "same slot twice co-locates",
			in:   Placement{"vm-a": "node:1", "vm-b": "node:1"},
			want: Placement{"vm-a": "cc2", "vm-b": "cc2"},
		},
		{
			name: "mixed literal and slot",
			in:   Placement{"vm-a": "node:0", "vm-b": "compute-7", "vm-c": ""},
			want: Placement{"vm-a": "cc1", "vm-b": "compute-7", "vm-c": ""},
		},
		{
			name:    "slot beyond configured agents",
			in:      Placement{"vm-a": "node:2"},
			wantErr: "config lists 2 agent(s)",
		},
		{
			name:    "malformed index",
			in:      Placement{"vm-a": "node:one"},
			wantErr: "want node:<index>",
		},
		{
			name:    "negative index",
			in:      Placement{"vm-a": "node:-1"},
			wantErr: "want node:<index>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePlacement(tt.in, agents)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("resolved = %v, want %v", got, tt.want)
			}
			for vm, host := range tt.want {
				if got[vm] != host {
					t.Errorf("resolved[%q] = %q, want %q", vm, got[vm], host)
				}
			}
		})
	}
}
