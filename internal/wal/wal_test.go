package wal_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/state"
	"github.com/bigstack-oss/lachesis/internal/wal"
)

func sampleRecords() []state.Record {
	return []state.Record{
		{
			Key: bpf.FlowKey{
				SrcMac:    [6]uint8{0xaa, 0, 0, 0, 0, 1},
				DstMac:    [6]uint8{0xaa, 0, 0, 0, 0, 2},
				EthProto:  0x0800,
				Direction: bpf.DirectionEgress,
				DstZone:   bpf.ZoneExternal,
			},
			Counter: state.Counter{
				Total:       bpf.FlowMetrics{Bytes: 1_000_000, Packets: 42, LastSeenNs: 1_700_000_000},
				LastEbpfRaw: bpf.FlowMetrics{Bytes: 900_000, Packets: 40, LastSeenNs: 1_699_999_900},
			},
		},
		{
			Key: bpf.FlowKey{
				SrcMac:    [6]uint8{0xbb, 0, 0, 0, 0, 1},
				DstMac:    [6]uint8{0xbb, 0, 0, 0, 0, 2},
				EthProto:  0x0800,
				Direction: bpf.DirectionIngress,
				DstZone:   bpf.ZoneSameTenant,
			},
			Counter: state.Counter{
				Total:       bpf.FlowMetrics{Bytes: 2_000_000, Packets: 100, LastSeenNs: 1_700_000_001},
				LastEbpfRaw: bpf.FlowMetrics{Bytes: 1_900_000, Packets: 98, LastSeenNs: 1_699_999_950},
			},
		},
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	want := sampleRecords()

	if err := wal.Save(path, "test-build", want, nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}

	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Source != wal.LoadFromPrimary {
		t.Errorf("Source = %v, want LoadFromPrimary", res.Source)
	}
	if len(res.Records) != len(want) {
		t.Fatalf("Records len = %d, want %d", len(res.Records), len(want))
	}

	gotByKey := map[bpf.FlowKey]state.Record{}
	for _, r := range res.Records {
		gotByKey[r.Key] = r
	}
	for _, w := range want {
		g, ok := gotByKey[w.Key]
		if !ok {
			t.Fatalf("Restored set missing key %v", w.Key)
		}
		if g.Counter != w.Counter {
			t.Errorf("Counter[%v] = %+v, want %+v", w.Key, g.Counter, w.Counter)
		}
	}
}

func TestSave_UsesStringEncodingForU64(t *testing.T) {
	// 2^60 is well above the IEEE 754 safe integer range (2^53);
	// without the ,string tag this would silently lose precision
	// on the round trip.
	const big = uint64(1) << 60
	path := filepath.Join(t.TempDir(), "wal.json")
	in := []state.Record{{
		Key: bpf.FlowKey{Direction: bpf.DirectionEgress},
		Counter: state.Counter{
			Total: bpf.FlowMetrics{Bytes: big, Packets: big, LastSeenNs: big},
		},
	}}
	if err := wal.Save(path, "", in, nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Sanity: the on-disk JSON should contain the value as a quoted
	// string, not a bare number.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(raw), `"`+u64Decimal(big)+`"`) {
		t.Errorf("on-disk JSON did not encode %d as a quoted string", big)
	}

	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := res.Records[0].Counter.Total.Bytes; got != big {
		t.Errorf("round-trip lost precision: got %d, want %d", got, big)
	}
}

func TestSave_RotatesPriorToBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")

	// First Save: no prior file, no .bak should appear yet.
	if err := wal.Save(path, "", sampleRecords()[:1], nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if _, err := os.Stat(path + wal.BackupSuffix); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf(".bak unexpectedly present after first save: %v", err)
	}

	// Second Save: previous file should rotate to .bak.
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if _, err := os.Stat(path + wal.BackupSuffix); err != nil {
		t.Errorf(".bak missing after second save: %v", err)
	}

	// Both files must be consistent snapshots: the primary carries
	// the second save, the .bak the first.
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load primary: %v", err)
	}
	if res.Source != wal.LoadFromPrimary || len(res.Records) != 2 {
		t.Errorf("primary: Source=%v Records=%d, want LoadFromPrimary with 2", res.Source, len(res.Records))
	}
	bakRes, err := wal.Load(path + wal.BackupSuffix)
	if err != nil {
		t.Fatalf("Load backup: %v", err)
	}
	if len(bakRes.Records) != 1 {
		t.Errorf(".bak Records=%d, want 1 (the first save)", len(bakRes.Records))
	}
}

func TestLoad_FallsBackToBackupOnBadPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")

	// Land a good snapshot on .bak by saving twice; the first
	// save's content rotates into .bak on the second save.
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("seed save 1: %v", err)
	}
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("seed save 2: %v", err)
	}

	// Corrupt the primary.
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("corrupt primary: %v", err)
	}

	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Source != wal.LoadFromBackup {
		t.Errorf("Source = %v, want LoadFromBackup", res.Source)
	}
	if len(res.Records) != 2 {
		t.Errorf("Records len = %d, want 2", len(res.Records))
	}
}

func TestLoad_BothMissingReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Source != wal.LoadEmpty {
		t.Errorf("Source = %v, want LoadEmpty", res.Source)
	}
	if len(res.Records) != 0 {
		t.Errorf("Records len = %d, want 0", len(res.Records))
	}
}

// futureSnapshot returns a hand-crafted envelope with a
// schema_version one above what this build understands.
func futureSnapshot(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{
		"schema_version": wal.SchemaVersion + 1,
		"agent_build":    "from-the-future",
		"written_at_ns":  "1700000000000000000",
		"global_state":   []any{},
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal future snapshot: %v", err)
	}
	return data
}

func TestLoad_RefusesNewerSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	data := futureSnapshot(t)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := wal.Load(path)
	if err == nil {
		t.Fatal("Load: expected error for newer schema_version, got nil")
	}
	if !errors.Is(err, wal.ErrSchemaNewer) {
		t.Errorf("errors.Is(err, ErrSchemaNewer) = false, got: %v", err)
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should mention schema_version, got: %v", err)
	}

	// The refusal must leave the forward snapshot untouched.
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile after Load: %v", readErr)
	}
	if string(after) != string(data) {
		t.Error("Load modified the newer-schema snapshot")
	}
}

func TestLoad_NewerSchemaDoesNotFallBackToBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")

	// Land a perfectly good v1 snapshot on .bak ...
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("seed save 1: %v", err)
	}
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("seed save 2: %v", err)
	}
	// ... then overwrite the primary with a future-schema snapshot,
	// as a rollback-after-upgrade leaves it.
	if err := os.WriteFile(path, futureSnapshot(t), 0o600); err != nil {
		t.Fatalf("write future primary: %v", err)
	}

	_, err := wal.Load(path)
	if !errors.Is(err, wal.ErrSchemaNewer) {
		t.Fatalf("Load = %v, want ErrSchemaNewer despite a readable .bak", err)
	}
}

func TestLoad_NewerSchemaOnBackupSurfacesBehindCorruptPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")

	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatalf("seed primary: %v", err)
	}
	if err := os.WriteFile(path+wal.BackupSuffix, futureSnapshot(t), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	_, err := wal.Load(path)
	if !errors.Is(err, wal.ErrSchemaNewer) {
		t.Fatalf("Load = %v, want error wrapping ErrSchemaNewer for the newer .bak", err)
	}
}

func TestQuarantine_MovesFileIntoSingleSlot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")
	qpath := path + wal.QuarantineSuffix

	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	moved, err := wal.Quarantine(path)
	if err != nil || !moved {
		t.Fatalf("Quarantine = (%v, %v), want (true, nil)", moved, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("primary still present after quarantine: %v", err)
	}
	got, err := os.ReadFile(qpath)
	if err != nil || string(got) != "first" {
		t.Fatalf("quarantine slot = (%q, %v), want (\"first\", nil)", got, err)
	}

	// One slot: a later quarantine overwrites the earlier one.
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("seed again: %v", err)
	}
	if moved, err := wal.Quarantine(path); err != nil || !moved {
		t.Fatalf("second Quarantine = (%v, %v), want (true, nil)", moved, err)
	}
	got, err = os.ReadFile(qpath)
	if err != nil || string(got) != "second" {
		t.Fatalf("quarantine slot after overwrite = (%q, %v), want (\"second\", nil)", got, err)
	}
}

func TestQuarantine_MissingFileIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	moved, err := wal.Quarantine(path)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	if moved {
		t.Error("Quarantine reported moved=true for a missing file")
	}
}

func TestLoad_BothCorruptReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")
	bak := path + wal.BackupSuffix

	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatalf("seed primary: %v", err)
	}
	if err := os.WriteFile(bak, []byte("{also-bad"), 0o600); err != nil {
		t.Fatalf("seed backup: %v", err)
	}

	_, err := wal.Load(path)
	if err == nil {
		t.Fatal("Load: expected error when both files corrupt, got nil")
	}
}

func TestSave_RecordsMarshalAndFlushOnMetrics(t *testing.T) {
	m := wal.NewMetrics()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}

	path := filepath.Join(t.TempDir(), "wal.json")
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, m); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Each histogram must have observed exactly one sample.
	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	wantNonEmpty := map[string]bool{
		"lachesis_wal_marshal_seconds":       false,
		"lachesis_wal_flush_latency_seconds": false,
	}
	for _, fam := range mf {
		if _, ok := wantNonEmpty[fam.GetName()]; !ok {
			continue
		}
		for _, metric := range fam.GetMetric() {
			if metric.GetHistogram().GetSampleCount() > 0 {
				wantNonEmpty[fam.GetName()] = true
			}
		}
	}
	for name, observed := range wantNonEmpty {
		if !observed {
			t.Errorf("%s histogram has no observations after Save", name)
		}
	}
}

func TestSave_RecordsFailureStageOnBadDir(t *testing.T) {
	m := wal.NewMetrics()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}

	// Target a directory that does not exist — the open in
	// writeAndFsync will fail at the StageWrite stage.
	path := filepath.Join(t.TempDir(), "no", "such", "dir", "wal.json")
	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, m); err == nil {
		t.Fatal("Save: expected error for bad dir, got nil")
	}

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var stageSeen string
	for _, fam := range mf {
		if fam.GetName() != "lachesis_wal_flush_failures_total" {
			continue
		}
		for _, metric := range fam.GetMetric() {
			if metric.GetCounter().GetValue() < 1 {
				continue
			}
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == "stage" {
					stageSeen = lbl.GetValue()
				}
			}
		}
	}
	if stageSeen != wal.StageWrite {
		t.Errorf("expected stage=%s failure, got %q", wal.StageWrite, stageSeen)
	}
}

func TestNewMetrics_SeedsFlushFailureStages(t *testing.T) {
	m := wal.NewMetrics()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}

	expected := `
# HELP lachesis_wal_flush_failures_total Failed WAL flush attempts, labelled by which sub-stage tripped.
# TYPE lachesis_wal_flush_failures_total counter
lachesis_wal_flush_failures_total{stage="dir_sync"} 0
lachesis_wal_flush_failures_total{stage="fsync"} 0
lachesis_wal_flush_failures_total{stage="rename_bak"} 0
lachesis_wal_flush_failures_total{stage="rename_current"} 0
lachesis_wal_flush_failures_total{stage="write"} 0
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"lachesis_wal_flush_failures_total"); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}

// TestEnsureDir_CreatesMissingDir pins the boot policy for a missing
// WAL directory: EnsureDir creates it (rather than erroring), and a
// subsequent Save round-trips.
func TestEnsureDir_CreatesMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "lib", "wal.json")

	if err := wal.EnsureDir(path); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil || !info.IsDir() {
		t.Fatalf("Stat dir after EnsureDir: info=%v err=%v", info, err)
	}

	if err := wal.Save(path, "", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save after EnsureDir: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Source != wal.LoadFromPrimary {
		t.Errorf("Source = %v, want LoadFromPrimary", res.Source)
	}
}

func TestEnsureDir_ErrorsWhenParentIsFile(t *testing.T) {
	// A regular file where a directory component should be makes
	// MkdirAll fail with ENOTDIR — for root and non-root alike
	// (permission-bit tests are useless under root).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	if err := wal.EnsureDir(filepath.Join(blocker, "sub", "wal.json")); err == nil {
		t.Fatal("EnsureDir: expected error when a path component is a file, got nil")
	}
}

func TestRecordLoadFallback_IncrementsLabel(t *testing.T) {
	m := wal.NewMetrics()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}
	m.RecordLoadFallback(wal.LoadFallbackBak)
	m.RecordLoadFallback(wal.LoadFallbackBak)
	m.RecordLoadFallback(wal.LoadFallbackEmpty)

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	counts := map[string]float64{}
	for _, fam := range mf {
		if fam.GetName() != "lachesis_wal_load_fallback_total" {
			continue
		}
		for _, metric := range fam.GetMetric() {
			var from string
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == "from" {
					from = lbl.GetValue()
				}
			}
			counts[from] = metric.GetCounter().GetValue()
		}
	}
	if counts[wal.LoadFallbackBak] != 2 {
		t.Errorf("%s count = %v, want 2", wal.LoadFallbackBak, counts[wal.LoadFallbackBak])
	}
	if counts[wal.LoadFallbackEmpty] != 1 {
		t.Errorf("%s count = %v, want 1", wal.LoadFallbackEmpty, counts[wal.LoadFallbackEmpty])
	}
}

// u64Decimal stringifies n the same way encoding/json's ,string tag
// does — used by TestSave_UsesStringEncodingForU64 to grep for the
// quoted value on disk.
func u64Decimal(n uint64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return string(b[i:])
}

func sampleSettled() []state.TenantSettledRecord {
	return []state.TenantSettledRecord{
		{
			Key:   state.TenantSettledKey{Tenant: "d1a509ba00000000000000000000aaaa", ExtNet: "public-1", Zone: bpf.ZoneExternal, Dir: bpf.DirectionIngress},
			Bytes: 5_360_000, Packets: 3_600,
		},
		{
			Key:   state.TenantSettledKey{Tenant: "d1a509ba00000000000000000000aaaa", ExtNet: "none", Zone: bpf.ZoneInfra, Dir: bpf.DirectionEgress},
			Bytes: 7_408, Packets: 12,
		},
	}
}

// TestSaveLoad_RoundTripsSettled: the v2 settled section survives a
// Save/Load cycle bit-exact — the restart-safety half of the
// settled-bytes fold (docs/architecture/data-structures.md#settled-bytes).
func TestSaveLoad_RoundTripsSettled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	want := sampleSettled()

	if err := wal.Save(path, "test-build", sampleRecords(), want, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(res.TenantSettled) != len(want) {
		t.Fatalf("TenantSettled len = %d, want %d", len(res.TenantSettled), len(want))
	}
	for i := range want {
		if res.TenantSettled[i] != want[i] {
			t.Errorf("TenantSettled[%d] = %+v, want %+v", i, res.TenantSettled[i], want[i])
		}
	}
}

// TestLoad_V1SnapshotAccepted: a v1 file (pre-settled schema) still
// loads — the v2 change is additive, so a post-upgrade boot restores
// the flow records and starts with an empty settled accumulator.
func TestLoad_V1SnapshotAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	v1 := `{
  "schema_version": 1,
  "agent_build": "pre-settled",
  "written_at_ns": "1",
  "global_state": [
    {
      "key": {"src_mac": [170,0,0,0,0,1], "dst_mac": [170,0,0,0,0,2], "eth_proto": 2048, "direction": 0, "dst_zone": 2},
      "total": {"bytes": "1000", "packets": "10", "last_seen_ns": "1"},
      "last_raw": {"bytes": "900", "packets": "9", "last_seen_ns": "1"}
    }
  ]
}`
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Source != wal.LoadFromPrimary {
		t.Errorf("Source = %v, want LoadFromPrimary", res.Source)
	}
	if len(res.Records) != 1 || res.Records[0].Counter.Total.Bytes != 1000 {
		t.Errorf("Records = %+v, want the one v1 flow record", res.Records)
	}
	if res.TenantSettled != nil {
		t.Errorf("TenantSettled = %+v, want nil for a v1 snapshot", res.TenantSettled)
	}
}

// TestLoad_V2SettledMapsAbsentExternalNetworkToNone: a v2 snapshot's
// settled entries predate the external_network dimension; Load maps the
// absent field to the "none" sentinel (schema v3 note) — a
// pre-external-network bucket IS a "none" bucket.
func TestLoad_V2SettledMapsAbsentExternalNetworkToNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	v2 := `{
  "schema_version": 2,
  "agent_build": "pre-extnet",
  "written_at_ns": "1",
  "global_state": [],
  "settled": [
    {"tenant_id": "t-legacy", "zone": 1, "direction": 0, "bytes": "77", "packets": "3"}
  ]
}`
	if err := os.WriteFile(path, []byte(v2), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(res.TenantSettled) != 1 {
		t.Fatalf("TenantSettled len = %d, want 1", len(res.TenantSettled))
	}
	if got := res.TenantSettled[0].Key.ExtNet; got != "none" {
		t.Errorf("legacy settled ExtNet = %q, want \"none\"", got)
	}
	if res.TenantSettled[0].Bytes != 77 || res.TenantSettled[0].Packets != 3 {
		t.Errorf("legacy settled totals = %+v, want 77/3", res.TenantSettled[0])
	}
}

// sampleServerSettled is a representative v4 server-settled section.
func sampleServerSettled() []state.ServerSettledRecord {
	return []state.ServerSettledRecord{
		{
			Key:   state.ServerSettledKey{ServerID: "11111111-2222-3333-4444-555555555555", Tenant: "d1a509ba00000000000000000000aaaa", ExtNet: "public-1", Zone: bpf.ZoneExternal, Dir: bpf.DirectionIngress},
			Bytes: 9_000_000, Packets: 6_000,
		},
		{
			Key:   state.ServerSettledKey{ServerID: "66666666-7777-8888-9999-000000000000", Tenant: "d1a509ba00000000000000000000aaaa", ExtNet: "none", Zone: bpf.ZoneInfra, Dir: bpf.DirectionEgress},
			Bytes: 12_800, Packets: 20,
		},
	}
}

// TestSaveLoad_RoundTripsServerSettled: the v4 server-settled section
// survives a Save/Load cycle bit-exact — the restart-safety of the
// server layer's fold absorber (docs/architecture/data-structures.md#settled-bytes).
func TestSaveLoad_RoundTripsServerSettled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	want := sampleServerSettled()

	if err := wal.Save(path, "test-build", sampleRecords(), sampleSettled(), want, nil, 0, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(res.ServerSettled) != len(want) {
		t.Fatalf("ServerSettled len = %d, want %d", len(res.ServerSettled), len(want))
	}
	for i := range want {
		if res.ServerSettled[i] != want[i] {
			t.Errorf("ServerSettled[%d] = %+v, want %+v", i, res.ServerSettled[i], want[i])
		}
	}
}

// TestLoad_V3SnapshotAccepted: a v3 file (pre-server-settled schema)
// still loads — the v4 change is additive, so a post-upgrade boot
// restores flows + settled and starts with an empty server-settled
// accumulator.
func TestLoad_V3SnapshotAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	v3 := `{
  "schema_version": 3,
  "agent_build": "pre-server-settled",
  "written_at_ns": "1",
  "global_state": [],
  "settled": [{"tenant_id":"t1","external_network":"public-1","zone":1,"direction":0,"bytes":"500","packets":"5"}]
}`
	if err := os.WriteFile(path, []byte(v3), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load v3: %v", err)
	}
	if len(res.TenantSettled) != 1 {
		t.Errorf("TenantSettled len = %d, want 1", len(res.TenantSettled))
	}
	if res.ServerSettled != nil {
		t.Errorf("ServerSettled = %+v, want nil (absent in a v3 file)", res.ServerSettled)
	}
}

// TestSaveLoad_RoundTripsTotalSettled: the v5 total_settled section
// survives a Save/Load cycle bit-exact, and a snapshot saved without it
// (a v4-shaped file — no project had died) restores a nil absorber.
func TestSaveLoad_RoundTripsTotalSettled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	want := []state.TotalSettledRecord{
		{Key: state.TotalSettledKey{ExtNet: "net-ext", Zone: bpf.ZoneExternal, Dir: bpf.DirectionEgress},
			Bytes: 1 << 40, Packets: 1 << 20},
		{Key: state.TotalSettledKey{ExtNet: "none", Zone: bpf.ZoneSameTenant, Dir: bpf.DirectionIngress},
			Bytes: 7, Packets: 3},
	}
	if err := wal.Save(path, "test-build", sampleRecords(), nil, nil, want, 0, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(res.TotalSettled) != len(want) {
		t.Fatalf("TotalSettled len = %d, want %d", len(res.TotalSettled), len(want))
	}
	for i := range want {
		if res.TotalSettled[i] != want[i] {
			t.Errorf("TotalSettled[%d] = %+v, want %+v", i, res.TotalSettled[i], want[i])
		}
	}

	// No total-settled section → nil on load (pre-v5 files and v5
	// writers with an empty absorber are byte-identical here).
	if err := wal.Save(path, "test-build", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save without totals: %v", err)
	}
	res, err = wal.Load(path)
	if err != nil {
		t.Fatalf("Load without totals: %v", err)
	}
	if res.TotalSettled != nil {
		t.Fatalf("TotalSettled = %+v, want nil for a snapshot without the section", res.TotalSettled)
	}
}

// TestSaveLoad_RoundTripsCountersReset: the v6 counters-reset epoch
// survives a Save/Load cycle, and a snapshot saved with epoch 0 (the
// v5-shaped file — field absent via omitempty) loads back as 0, the
// "epoch unknown" sentinel the boot restore re-stamps.
func TestSaveLoad_RoundTripsCountersReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")

	if err := wal.Save(path, "test-build", sampleRecords(), nil, nil, nil, 1753400000, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.CountersResetAt != 1753400000 {
		t.Fatalf("CountersResetAt = %d, want 1753400000", res.CountersResetAt)
	}

	if err := wal.Save(path, "test-build", sampleRecords(), nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save without epoch: %v", err)
	}
	res, err = wal.Load(path)
	if err != nil {
		t.Fatalf("Load without epoch: %v", err)
	}
	if res.CountersResetAt != 0 {
		t.Fatalf("CountersResetAt = %d, want 0 for a snapshot without the field", res.CountersResetAt)
	}
}

// TestLoad_V6SnapshotHasNoEntryIdentity: a v6 file predates the
// created_ns entry-identity stamp (schema v7,
// docs/adr/0014-in-band-entry-identity-over-inferred-resets.md). It must
// load clean with the field zero — which state.ApplyDelta reads as
// "identity unknown" and resolves with the value guard.
//
// Zero must NOT be read as "different entry": on a pinned map that
// survived the restart, that would re-count the whole restored
// cumulative on the first scrape.
func TestLoad_V6SnapshotHasNoEntryIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	v6 := `{
  "schema_version": 6,
  "agent_build": "pre-entry-identity",
  "written_at_ns": "1",
  "counters_reset_at_s": 1700000000,
  "global_state": [
    {
      "key": {"src_mac": [170,0,0,0,0,1], "dst_mac": [170,0,0,0,0,2], "eth_proto": 2048, "direction": 0, "dst_zone": 2},
      "total": {"bytes": "5000000000", "packets": "10", "last_seen_ns": "1"},
      "last_raw": {"bytes": "5000000000", "packets": "10", "last_seen_ns": "1"}
    }
  ]
}`
	if err := os.WriteFile(path, []byte(v6), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("Records = %+v, want one", res.Records)
	}
	if got := res.Records[0].Counter.LastEbpfRaw.CreatedNs; got != 0 {
		t.Errorf("LastEbpfRaw.CreatedNs = %d, want 0 — a v6 file carries no stamp", got)
	}
	if got := res.Records[0].Counter.Total.Bytes; got != 5_000_000_000 {
		t.Errorf("Total.Bytes = %d, want the restored cumulative intact", got)
	}
}

// TestSaveLoad_EntryIdentityRoundTrips: v7 persists the stamp, so a
// restart with a pinned map compares identity on its very first scrape
// instead of falling back to the guard.
func TestSaveLoad_EntryIdentityRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	recs := []state.Record{{
		Key: bpf.FlowKey{SrcMac: [6]uint8{0xaa, 0, 0, 0, 0, 1}, DstMac: [6]uint8{0xaa, 0, 0, 0, 0, 2}, EthProto: 0x0800},
		Counter: state.Counter{
			Total:       bpf.FlowMetrics{Bytes: 4096, Packets: 4, LastSeenNs: 9, CreatedNs: 777},
			LastEbpfRaw: bpf.FlowMetrics{Bytes: 4096, Packets: 4, LastSeenNs: 9, CreatedNs: 777},
		},
	}}
	if err := wal.Save(path, "test", recs, nil, nil, nil, 0, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}
	res, err := wal.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := res.Records[0].Counter.LastEbpfRaw.CreatedNs; got != 777 {
		t.Errorf("LastEbpfRaw.CreatedNs = %d, want 777 round-tripped", got)
	}
}
