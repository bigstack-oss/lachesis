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
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/bigstack-oss/lachesis/internal/agent"
	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/logging"
	"github.com/bigstack-oss/lachesis/internal/metadata"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/wal"
)

// newIdleAgent constructs an agent without starting Run — the WAL
// restore executes between New and Run, so these tests drive it
// directly via RestoreFromWALForTest.
func newIdleAgent(t *testing.T, walCfg config.WALConfig) *agent.Agent {
	t.Helper()
	cfg := config.Defaults()
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.WAL = walCfg
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
		if err := wal.Save(path, "", records, nil, nil, nil, 1753400000, nil); err != nil {
			t.Fatalf("seed save %d: %v", i+1, err)
		}
	}
}

// loadFallbackCount gathers lachesis_wal_load_fallback_total{from=...}
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
		if fam.GetName() != "lachesis_wal_load_fallback_total" {
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

	ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
	err = agent.RestoreFromWALForTest(ag)
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

	ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
	if err := agent.RestoreFromWALForTest(ag); err != nil {
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

	ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
	if err := agent.RestoreFromWALForTest(ag); err != nil {
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

// countersResetGauge reads lachesis_agent_counters_reset_timestamp_seconds
// off the agent's WAL metrics bundle.
func countersResetGauge(t *testing.T, ag *agent.Agent) float64 {
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
		if fam.GetName() == "lachesis_agent_counters_reset_timestamp_seconds" {
			return fam.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("lachesis_agent_counters_reset_timestamp_seconds not found")
	return 0
}

// TestRestoreFromWAL_CountersResetDecision drives the epoch decision
// matrix (docs/architecture/boot-and-recovery.md#counters-reset-epoch):
// a warm boot carries the stored epoch; an empty start stamps now and
// persists it IMMEDIATELY (a crash before the first periodic flush
// must not forget the reset); a pre-v6 snapshot (stored epoch 0 =
// unknown) re-stamps once.
func TestRestoreFromWAL_CountersResetDecision(t *testing.T) {
	t.Run("empty start stamps now and persists immediately", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal.json")
		ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
		before := time.Now().Unix()
		if err := agent.RestoreFromWALForTest(ag); err != nil {
			t.Fatalf("restore: %v", err)
		}
		got := int64(countersResetGauge(t, ag))
		if got < before || got > time.Now().Unix() {
			t.Fatalf("gauge = %d, want a now-ish stamp (≥ %d)", got, before)
		}
		// The immediate flush persisted it: a second agent warm-boots
		// off the file and carries the SAME epoch.
		res, err := wal.Load(path)
		if err != nil {
			t.Fatalf("Load after stamp: %v", err)
		}
		if res.CountersResetAt != got {
			t.Fatalf("persisted epoch = %d, want the stamped %d", res.CountersResetAt, got)
		}
	})

	t.Run("warm boot carries the stored epoch", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal.json")
		if err := wal.Save(path, "", nil, nil, nil, nil, 1753400000, nil); err != nil {
			t.Fatalf("seed: %v", err)
		}
		ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
		if err := agent.RestoreFromWALForTest(ag); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if got := int64(countersResetGauge(t, ag)); got != 1753400000 {
			t.Fatalf("gauge = %d, want the carried 1753400000", got)
		}
	})

	t.Run("pre-epoch snapshot re-stamps once", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal.json")
		if err := wal.Save(path, "", nil, nil, nil, nil, 0, nil); err != nil {
			t.Fatalf("seed: %v", err)
		}
		ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
		before := time.Now().Unix()
		if err := agent.RestoreFromWALForTest(ag); err != nil {
			t.Fatalf("restore: %v", err)
		}
		got := int64(countersResetGauge(t, ag))
		if got < before {
			t.Fatalf("gauge = %d, want a fresh stamp for the unknown epoch", got)
		}
		res, err := wal.Load(path)
		if err != nil {
			t.Fatalf("Load after re-stamp: %v", err)
		}
		if res.CountersResetAt != got {
			t.Fatalf("persisted epoch = %d, want %d", res.CountersResetAt, got)
		}
	})

	t.Run("unreadable snapshots quarantine then stamp", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal.json")
		if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
			t.Fatalf("write corrupt: %v", err)
		}
		ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path})
		before := time.Now().Unix()
		if err := agent.RestoreFromWALForTest(ag); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if got := int64(countersResetGauge(t, ag)); got < before {
			t.Fatalf("gauge = %d, want a now-ish stamp after quarantine", got)
		}
	})

	t.Run("disabled WAL stamps every boot", func(t *testing.T) {
		ag := newIdleAgent(t, config.WALConfig{Enabled: false})
		before := time.Now().Unix()
		if err := agent.RestoreFromWALForTest(ag); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if got := int64(countersResetGauge(t, ag)); got < before {
			t.Fatalf("gauge = %d, want a now-ish stamp with WAL disabled", got)
		}
	})
}

// TestRestoreFromWAL_SettlesRowsWhoseOwnerChanged pins the boot-time
// fold: a restored row whose owner no longer resolves the way the WAL
// recorded it (port deleted or reassigned while the agent was down) is
// settled under the RECORDED owner, so that tenant's series keeps the
// bytes instead of them late-binding to "unknown" or the new owner.
func TestRestoreFromWAL_SettlesRowsWhoseOwnerChanged(t *testing.T) {
	key := func(last uint8) bpf.FlowKey {
		return bpf.FlowKey{
			SrcMac: [6]uint8{0xaa, 0, 0, 0, 0, last}, DstMac: [6]uint8{0xbb, 0, 0, 0, 0, 1},
			EthProto: 0x0800, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant,
		}
	}
	owner := func(tenant, server string) state.Owner {
		return state.Owner{Tenant: tenant, ExtNet: metadata.NoExternalNetwork, Server: server}
	}
	cases := []struct {
		name        string
		recorded    state.Owner          // what the WAL says
		live        *metadata.TenantMeta // what metadata says at boot (nil = port gone)
		wantSettled map[string]uint64    // tenant-settled bytes after restore
		wantTotal   uint64               // the row's live Total after restore
		prior       uint64               // bytes the WAL already holds under the recorded owner's tuple
	}{
		{"port deleted while down", owner("gone", "srv-1"), nil, map[string]uint64{"gone": 5000}, 0, 0},
		// The WAL's own settled buckets restore too; the fold must add
		// to them, not be overwritten by them.
		{"port deleted, owner already has settled bytes", owner("gone", "srv-1"), nil, map[string]uint64{"gone": 5700}, 0, 700},
		{"port reassigned while down", owner("old", "srv-1"),
			&metadata.TenantMeta{ProjectID: "new", ServerID: "srv-2"}, map[string]uint64{"old": 5000}, 0, 0},
		{"owner unchanged", owner("same", "srv-1"),
			&metadata.TenantMeta{ProjectID: "same", ServerID: "srv-1"}, map[string]uint64{}, 5000, 0},
		{"pre-v8 row, no owner", state.Owner{}, nil, map[string]uint64{}, 5000, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal.json")
			rec := state.Record{
				Key: key(1),
				Counter: state.Counter{
					Total:       bpf.FlowMetrics{Bytes: 5000, Packets: 5, LastSeenNs: 1},
					LastEbpfRaw: bpf.FlowMetrics{Bytes: 5000, Packets: 5, LastSeenNs: 1},
				},
				Owner: tc.recorded,
			}
			var prior []state.TenantSettledRecord
			if tc.prior > 0 {
				prior = []state.TenantSettledRecord{{
					Key:   state.TenantSettledKey{Tenant: tc.recorded.Tenant, ExtNet: tc.recorded.ExtNet, Zone: rec.Key.DstZone, Dir: rec.Key.Direction},
					Bytes: tc.prior,
				}}
			}
			if err := wal.Save(path, "", []state.Record{rec}, prior, nil, nil, 1753400000, nil); err != nil {
				t.Fatalf("seed save: %v", err)
			}
			ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path, FlushInterval: time.Minute})
			if tc.live != nil {
				agent.MetadataForTest(ag).Insert(metadata.VMMAC(rec.Key), tc.live)
			}
			if err := agent.RestoreFromWALForTest(ag); err != nil {
				t.Fatalf("restore: %v", err)
			}
			if err := agent.FlushWALForTest(ag); err != nil {
				t.Fatalf("flush: %v", err)
			}
			res, err := wal.Load(path)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if len(res.Records) != 1 {
				t.Fatalf("records = %+v, want the row kept", res.Records)
			}
			if got := res.Records[0].Counter.Total.Bytes; got != tc.wantTotal {
				t.Errorf("row Total = %d, want %d", got, tc.wantTotal)
			}
			if got := res.Records[0].Counter.LastEbpfRaw.Bytes; got != 5000 {
				t.Errorf("row LastEbpfRaw = %d, want 5000 kept (no re-count of a surviving kernel entry)", got)
			}
			settled := map[string]uint64{}
			for _, s := range res.TenantSettled {
				settled[s.Key.Tenant] += s.Bytes
			}
			if len(settled) != len(tc.wantSettled) {
				t.Errorf("tenant-settled = %v, want %v", settled, tc.wantSettled)
			}
			for tenant, want := range tc.wantSettled {
				if settled[tenant] != want {
					t.Errorf("tenant-settled[%q] = %d, want %d", tenant, settled[tenant], want)
				}
			}
		})
	}
}

// TestFlushWAL_RecordsEachRowsOwner: the flush stamps every row with the
// owner it resolves to now, and leaves an unresolved row ownerless.
func TestFlushWAL_RecordsEachRowsOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	ag := newIdleAgent(t, config.WALConfig{Enabled: true, Path: path, FlushInterval: time.Minute})
	known := bpf.FlowKey{SrcMac: [6]uint8{0xaa, 0, 0, 0, 0, 1}, EthProto: 0x0800, Direction: bpf.DirectionIngress, DstZone: bpf.ZoneSameTenant}
	stray := known
	stray.SrcMac = [6]uint8{0xaa, 0, 0, 0, 0, 2}
	agent.MetadataForTest(ag).Insert(metadata.VMMAC(known), &metadata.TenantMeta{ProjectID: "p", ServerID: "s"})
	ag.SeedState([]state.Record{
		{Key: known, Counter: state.Counter{Total: bpf.FlowMetrics{Bytes: 1}}},
		{Key: stray, Counter: state.Counter{Total: bpf.FlowMetrics{Bytes: 1}}},
	})
	if err := agent.FlushWALForTest(ag); err != nil {
		t.Fatalf("flush: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := map[bpf.FlowKey]state.Owner{}
	for _, r := range res.Records {
		got[r.Key] = r.Owner
	}
	if want := (state.Owner{Tenant: "p", ExtNet: metadata.NoExternalNetwork, Server: "s"}); got[known] != want {
		t.Errorf("known row Owner = %+v, want %+v", got[known], want)
	}
	if got[stray] != (state.Owner{}) {
		t.Errorf("unresolved row Owner = %+v, want zero", got[stray])
	}
}
