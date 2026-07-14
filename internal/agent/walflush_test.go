// walflush_test.go covers the boot-time restore error classes
// (schema-newer is fatal and leaves the file untouched; corruption
// quarantines the primary and starts empty) and the agent_build
// extraction. The flush-loop and final-flush behaviour is covered in
// agent_test.go.

package agent_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bigstack-oss/lachesis/internal/agent"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/wal"
)

// newIdleAgent constructs an agent without starting Run — the WAL
// restore executes between New and Run, so these tests drive it
// directly via RestoreFromWALForTest.
func newIdleAgent(t *testing.T) *agent.Agent {
	t.Helper()
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	log, err := logging.Init(cfg.Logging, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("logging.Init: %v", err)
	}
	ag, err := agent.New(agent.Options{
		Config: cfg,
		Reader: &staticReader{},
		Log:    log,
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	t.Cleanup(func() { _ = ag.CloseListenerForTest() })
	return ag
}

// seedSnapshots writes two generations of a valid snapshot so both
// the primary and the .bak at path are readable.
func seedSnapshots(t *testing.T, path string) {
	t.Helper()
	records := []state.Record{{
		Key: bpf.FlowKey{
			SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
			DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
			EthProto:  0x0800,
			Direction: bpf.DirectionEgress,
			DstZone:   bpf.ZoneExternal,
		},
		Counter: state.Counter{
			Total:       bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1},
			LastEbpfRaw: bpf.FlowMetrics{Bytes: 100, Packets: 1, LastSeenNs: 1},
		},
	}}
	for i := 0; i < 2; i++ {
		if err := wal.Save(path, "", records, nil, nil); err != nil {
			t.Fatalf("seed save %d: %v", i+1, err)
		}
	}
}

// loadFallbackCount gathers cubecos_wal_load_fallback_total{from=...}
// from the agent's WAL metrics bundle.
func loadFallbackCount(t *testing.T, ag *agent.Agent, from string) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	for _, c := range ag.WALMetrics().Collectors() {
		reg.MustRegister(c)
	}
	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, fam := range mf {
		if fam.GetName() != "cubecos_wal_load_fallback_total" {
			continue
		}
		for _, metric := range fam.GetMetric() {
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == "from" && lbl.GetValue() == from {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestRestoreFromWAL_SchemaNewerIsFatalAndLeavesFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	body := map[string]any{
		"schema_version": wal.SchemaVersion + 1,
		"agent_build":    "from-the-future",
		"written_at_ns":  "1700000000000000000",
		"global_state":   []any{},
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	ag := newIdleAgent(t)
	err = agent.RestoreFromWALForTest(ag, config.WALConfig{Enabled: true, Path: path})
	if !errors.Is(err, wal.ErrSchemaNewer) {
		t.Fatalf("restore = %v, want error wrapping ErrSchemaNewer", err)
	}

	// The forward snapshot must survive the refusal byte-for-byte,
	// in place — not quarantined.
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile after restore: %v", readErr)
	}
	if string(after) != string(data) {
		t.Error("restore modified the newer-schema snapshot")
	}
	if _, err := os.Stat(path + wal.QuarantineSuffix); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("unexpected quarantine of a newer-schema snapshot: %v", err)
	}
}

func TestRestoreFromWAL_CorruptPrimaryQuarantinedAndBackupRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	seedSnapshots(t, path)
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("corrupt primary: %v", err)
	}

	ag := newIdleAgent(t)
	if err := agent.RestoreFromWALForTest(ag, config.WALConfig{Enabled: true, Path: path}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if got := loadFallbackCount(t, ag, wal.LoadFallbackBak); got != 1 {
		t.Errorf("load_fallback_total{from=bak} = %v, want 1 (backup restore)", got)
	}

	// The corrupt primary must be out of the flush rotation's reach:
	// moved to the quarantine slot, content preserved.
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("corrupt primary still in rotation position: %v", err)
	}
	got, err := os.ReadFile(path + wal.QuarantineSuffix)
	if err != nil {
		t.Fatalf("quarantine slot: %v", err)
	}
	if string(got) != "{not-json" {
		t.Errorf("quarantine content = %q, want the corrupt primary", got)
	}
	if _, err := os.Stat(path + wal.BackupSuffix); err != nil {
		t.Errorf(".bak missing after restore: %v", err)
	}
}

func TestRestoreFromWAL_BothCorruptStartsEmptyAndQuarantinesPrimary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatalf("seed primary: %v", err)
	}
	if err := os.WriteFile(path+wal.BackupSuffix, []byte("{also-bad"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	ag := newIdleAgent(t)
	if err := agent.RestoreFromWALForTest(ag, config.WALConfig{Enabled: true, Path: path}); err != nil {
		t.Fatalf("restore should start empty, got: %v", err)
	}

	got, err := os.ReadFile(path + wal.QuarantineSuffix)
	if err != nil {
		t.Fatalf("quarantine slot: %v", err)
	}
	if string(got) != "{bad" {
		t.Errorf("quarantine content = %q, want the corrupt primary", got)
	}
}

func TestBuildIDFrom_ExtractsShortVCSRevision(t *testing.T) {
	cases := []struct {
		name     string
		settings []debug.BuildSetting
		want     string
	}{
		{
			name: "long revision truncated to 12",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			},
			want: "0123456789ab",
		},
		{
			name: "short revision kept as-is",
			settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc123"},
			},
			want: "abc123",
		},
		{
			name:     "no vcs stamping falls back to empty",
			settings: nil,
			want:     "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bi := &debug.BuildInfo{Settings: tc.settings}
			if got := agent.BuildIDFromForTest(bi); got != tc.want {
				t.Errorf("buildIDFrom = %q, want %q", got, tc.want)
			}
		})
	}
}
