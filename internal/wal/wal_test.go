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

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/wal"
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

	if err := wal.Save(path, "test-build", want, nil); err != nil {
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
	if err := wal.Save(path, "", in, nil); err != nil {
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
	if err := wal.Save(path, "", sampleRecords()[:1], nil); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if _, err := os.Stat(path + wal.BackupSuffix); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf(".bak unexpectedly present after first save: %v", err)
	}

	// Second Save: previous file should rotate to .bak.
	if err := wal.Save(path, "", sampleRecords(), nil); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	if _, err := os.Stat(path + wal.BackupSuffix); err != nil {
		t.Errorf(".bak missing after second save: %v", err)
	}
}

func TestLoad_FallsBackToBackupOnBadPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.json")

	// Land a good snapshot on .bak by saving twice; the first
	// save's content rotates into .bak on the second save.
	if err := wal.Save(path, "", sampleRecords(), nil); err != nil {
		t.Fatalf("seed save 1: %v", err)
	}
	if err := wal.Save(path, "", sampleRecords(), nil); err != nil {
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

func TestLoad_RefusesNewerSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.json")
	// Hand-craft an envelope with a future schema_version.
	body := map[string]any{
		"schema_version": wal.SchemaVersion + 1,
		"agent_build":    "from-the-future",
		"written_at_ns":  "1700000000000000000",
		"global_state":   []any{},
	}
	data, _ := json.Marshal(body)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := wal.Load(path)
	if err == nil {
		t.Fatal("Load: expected error for newer schema_version, got nil")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should mention schema_version, got: %v", err)
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
	if err := wal.Save(path, "", sampleRecords(), m); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Each histogram must have observed exactly one sample.
	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	wantNonEmpty := map[string]bool{
		"cubecos_wal_marshal_seconds":       false,
		"cubecos_wal_flush_latency_seconds": false,
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
	// writeAndFsync will fail at the "write" stage.
	path := filepath.Join(t.TempDir(), "no", "such", "dir", "wal.json")
	if err := wal.Save(path, "", sampleRecords(), m); err == nil {
		t.Fatal("Save: expected error for bad dir, got nil")
	}

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var stageSeen string
	for _, fam := range mf {
		if fam.GetName() != "cubecos_wal_flush_failures_total" {
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
	if stageSeen != "write" {
		t.Errorf("expected stage=write failure, got %q", stageSeen)
	}
}

func TestRecordLoadFallback_IncrementsLabel(t *testing.T) {
	m := wal.NewMetrics()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		reg.MustRegister(c)
	}
	m.RecordLoadFallback("bak")
	m.RecordLoadFallback("bak")
	m.RecordLoadFallback("empty")

	mf, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	counts := map[string]float64{}
	for _, fam := range mf {
		if fam.GetName() != "cubecos_wal_load_fallback_total" {
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
	if counts["bak"] != 2 {
		t.Errorf("bak count = %v, want 2", counts["bak"])
	}
	if counts["empty"] != 1 {
		t.Errorf("empty count = %v, want 1", counts["empty"])
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
