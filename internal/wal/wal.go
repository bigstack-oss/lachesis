// Package wal is the agent's write-ahead log: a single JSON snapshot
// of [state.GlobalState] flushed to disk every 60 s, retained as a
// .bak copy on rotation, and read back on boot to seed the state
// before the scraper starts.
//
// The on-disk format is JSON rather than an append-only log; the
// trade-off (≤60 s data loss on hard reboot for a 1–2 MB single-
// file write) is the design choice in docs/DESIGN.md §B.11. JSON
// numbers can't represent uint64 above 2^53 without precision loss,
// so byte counters and timestamps cross the wire as decimal strings
// via the encoding/json `,string` tag.
//
// # Atomic write protocol
//
//  1. Write payload to path+".tmp"; fsync the file.
//  2. Rename path → path+".bak" (best-effort; ENOENT on first run is fine).
//  3. Rename path+".tmp" → path.
//  4. Open the parent directory; fsync; close. Without this the
//     renames are not journaled — a power loss after Save returns
//     could roll the directory back to the previous snapshot.
//
// Readers therefore see either the previous snapshot (if a crash
// happens between steps 2 and 3) or the new one (after step 3) —
// never a partial write.
//
// # Boot read protocol
//
//  1. Try path. On parse failure, fall back to path+".bak" and
//     return LoadResult.Source = LoadFromBackup. A schema version
//     newer than this build never falls back: Load returns
//     [ErrSchemaNewer] immediately so boot can refuse to start
//     before the flush rotation destroys the forward snapshot.
//  2. If both fail with ENOENT, return LoadResult with Source =
//     LoadEmpty and no records — first boot.
//  3. Otherwise return the underlying error wrapped with both
//     read attempts' context.
package wal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/bigstack-oss/lachesis/internal/bpf"
	"github.com/bigstack-oss/lachesis/internal/state"
)

// ErrSchemaNewer reports a snapshot whose schema_version this build
// does not understand — typically a downgrade after a crash
// mid-upgrade. [Load] wraps it with the file and version details.
// Callers must treat it as fatal rather than starting empty: each
// flush overwrites one rotation generation, so a started agent
// destroys the only forward snapshot within two flushes.
var ErrSchemaNewer = errors.New("wal: snapshot schema newer than this build")

// stageErr attributes a Save failure to one of the labelled stages
// in lachesis_wal_flush_failures_total — see the Stage* consts above.
// Save returns errors wrapped this way so the caller can decide
// which counter to bump without parsing error messages.
type stageErr struct {
	Stage string
	Err   error
}

func (e *stageErr) Error() string { return fmt.Sprintf("wal %s: %v", e.Stage, e.Err) }
func (e *stageErr) Unwrap() error { return e.Err }

// Save writes records and settled to path via the atomic
// tmp+fsync+rename rotation described in the package doc. The two
// slices must come from one [state.GlobalState.SnapshotForWAL] call —
// a pair snapshotted separately can tear across a concurrent settle
// fold and persist the folded bytes twice or not at all. agentBuild is
// informational (correlation with build logs); empty is acceptable. m
// may be nil when phase timings and failure stages are not needed.
func Save(path, agentBuild string, records []state.Record, settled []state.SettledRecord, m *Metrics) error {
	snap := snapshotWire{
		SchemaVersion: SchemaVersion,
		AgentBuild:    agentBuild,
		WrittenAtNs:   uint64(time.Now().UnixNano()),
		GlobalState:   make([]entryWire, len(records)),
	}
	for i := range records {
		snap.GlobalState[i] = toWire(records[i])
	}
	if len(settled) > 0 {
		snap.Settled = make([]settledWire, len(settled))
		for i, s := range settled {
			snap.Settled[i] = settledWire{
				TenantID:  s.Key.Tenant,
				Zone:      uint8(s.Key.Zone),
				Direction: uint8(s.Key.Dir),
				Bytes:     s.Bytes,
				Packets:   s.Packets,
			}
		}
	}

	marshalStart := time.Now()
	data, err := json.Marshal(snap)
	m.observeMarshal(time.Since(marshalStart))
	if err != nil {
		m.observeFailure(StageMarshal)
		return &stageErr{Stage: StageMarshal, Err: err}
	}

	flushStart := time.Now()
	defer func() { m.observeFlush(time.Since(flushStart)) }()

	tmp := path + TempSuffix
	if err := writeAndFsync(tmp, data); err != nil {
		var se *stageErr
		if errors.As(err, &se) {
			m.observeFailure(se.Stage)
		}
		return err
	}

	// Rotate the previous snapshot aside. ENOENT on first run is
	// expected — there is no prior file.
	bak := path + BackupSuffix
	if err := os.Rename(path, bak); err != nil && !errors.Is(err, fs.ErrNotExist) {
		m.observeFailure(StageRenameBak)
		return &stageErr{Stage: StageRenameBak, Err: err}
	}

	if err := os.Rename(tmp, path); err != nil {
		m.observeFailure(StageRenameCurrent)
		return &stageErr{Stage: StageRenameCurrent, Err: err}
	}

	// Fsync the parent directory so the renames survive power loss
	// (the classic ext4/XFS gap: a renamed entry is durable only
	// once the directory itself is journaled).
	if err := syncDir(filepath.Dir(path)); err != nil {
		m.observeFailure(StageDirSync)
		return &stageErr{Stage: StageDirSync, Err: err}
	}
	return nil
}

// syncDir opens dir, fsyncs it, and closes — making previously
// renamed entries inside it durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("fsync dir: %w", err)
	}
	return d.Close()
}

// EnsureDir creates path's parent directory if missing and verifies
// it is writable with a probe file (created then removed). Intended
// for boot: a missing or read-only WAL directory otherwise surfaces
// only as flush-failure counters after Load mistook ENOENT for a
// first boot — the agent would run with zero crash durability while
// looking healthy.
func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("wal: create dir %s: %w", dir, err)
	}
	probe, err := os.CreateTemp(dir, ".wal-probe-*")
	if err != nil {
		return fmt.Errorf("wal: dir %s not writable: %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("wal: remove probe %s: %w", name, err)
	}
	return nil
}

// writeAndFsync writes data to path, fsyncs, and closes. Failures
// are returned as a *stageErr so the caller can bump the right
// flush-failure counter without string-matching.
func writeAndFsync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return &stageErr{Stage: StageWrite, Err: fmt.Errorf("open tmp: %w", err)}
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return &stageErr{Stage: StageWrite, Err: err}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return &stageErr{Stage: StageFsync, Err: err}
	}
	if err := f.Close(); err != nil {
		return &stageErr{Stage: StageWrite, Err: fmt.Errorf("close tmp: %w", err)}
	}
	return nil
}

// Load reads path, falling back to path+".bak" on parse failure.
// Both files missing returns a LoadResult with Source=LoadEmpty (no
// error — first boot is normal). A snapshot from a newer build is
// never a fallback case: Load returns an error wrapping
// [ErrSchemaNewer] without consulting the other file.
func Load(path string) (LoadResult, error) {
	primary, primaryErr := readAndParse(path)
	if primaryErr == nil {
		return LoadResult{Records: fromSnapshot(primary), Settled: fromSettled(primary), Source: LoadFromPrimary}, nil
	}

	// The .bak behind a newer-schema primary may well parse — it can
	// predate the upgrade — but restoring from it and flushing would
	// rotate the newer snapshot away. Surface the refusal instead.
	if errors.Is(primaryErr, ErrSchemaNewer) {
		return LoadResult{}, primaryErr
	}

	bakPath := path + BackupSuffix
	backup, backupErr := readAndParse(bakPath)
	if backupErr == nil {
		return LoadResult{Records: fromSnapshot(backup), Settled: fromSettled(backup), Source: LoadFromBackup}, nil
	}

	// Both missing is the first-boot path; report as empty.
	if errors.Is(primaryErr, fs.ErrNotExist) && errors.Is(backupErr, fs.ErrNotExist) {
		return LoadResult{Records: nil, Source: LoadEmpty}, nil
	}

	// Both attempts wrap with %w so errors.Is can spot a newer-schema
	// .bak hiding behind a corrupt primary.
	return LoadResult{}, fmt.Errorf(
		"wal: primary load %s failed: %w; backup load %s failed: %w",
		path, primaryErr, bakPath, backupErr,
	)
}

// Quarantine moves an unreadable snapshot at path aside to
// path+QuarantineSuffix, out of the Save rotation's reach — without
// the rename, the next flush rotates the unreadable file to .bak and
// the one after deletes it, destroying the forensic evidence. There
// is a single quarantine slot: a later quarantine overwrites the
// earlier one, which keeps disk usage bounded across crash loops
// while always preserving the most recent failure. Returns
// moved=false with no error when path does not exist (nothing to
// preserve).
func Quarantine(path string) (moved bool, err error) {
	if err := os.Rename(path, path+QuarantineSuffix); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("wal: quarantine %s: %w", path, err)
	}
	return true, nil
}

// readAndParse opens path, decodes the envelope, and validates the
// schema version. ENOENT and JSON / schema errors are returned
// verbatim so the caller can distinguish them; a schema version this
// build does not understand wraps [ErrSchemaNewer].
func readAndParse(path string) (snapshotWire, error) {
	var snap snapshotWire
	data, err := os.ReadFile(path)
	if err != nil {
		return snap, err
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		return snap, fmt.Errorf("wal: parse %s: %w", path, err)
	}
	if snap.SchemaVersion > SchemaVersion {
		return snap, fmt.Errorf("%w: %s schema_version=%d, this build understands up to %d",
			ErrSchemaNewer, path, snap.SchemaVersion, SchemaVersion)
	}
	// SchemaVersion < ours would normally trigger a migration step,
	// one per version. v1→v2 is purely additive (the settled section;
	// absent in a v1 file decodes as nil), so no migration exists.
	// Anything older than 1 is unrepresentable.
	if snap.SchemaVersion < 1 {
		return snap, fmt.Errorf("wal: %s schema_version=%d unsupported", path, snap.SchemaVersion)
	}
	return snap, nil
}

func toWire(r state.Record) entryWire {
	return entryWire{
		Key: flowKeyWire{
			SrcMac:    r.Key.SrcMac,
			DstMac:    r.Key.DstMac,
			EthProto:  r.Key.EthProto,
			Direction: uint8(r.Key.Direction),
			DstZone:   uint8(r.Key.DstZone),
		},
		Total:   toMetricsWire(r.Counter.Total),
		LastRaw: toMetricsWire(r.Counter.LastEbpfRaw),
	}
}

func toMetricsWire(m bpf.FlowMetrics) flowMetricsWire {
	return flowMetricsWire{Bytes: m.Bytes, Packets: m.Packets, LastSeenNs: m.LastSeenNs}
}

func fromSnapshot(snap snapshotWire) []state.Record {
	if len(snap.GlobalState) == 0 {
		return nil
	}
	out := make([]state.Record, len(snap.GlobalState))
	for i, e := range snap.GlobalState {
		out[i] = state.Record{
			Key: bpf.FlowKey{
				SrcMac:    e.Key.SrcMac,
				DstMac:    e.Key.DstMac,
				EthProto:  e.Key.EthProto,
				Direction: bpf.Direction(e.Key.Direction),
				DstZone:   bpf.ZoneCode(e.Key.DstZone),
			},
			Counter: state.Counter{
				Total:       fromMetricsWire(e.Total),
				LastEbpfRaw: fromMetricsWire(e.LastRaw),
			},
		}
	}
	return out
}

func fromMetricsWire(w flowMetricsWire) bpf.FlowMetrics {
	return bpf.FlowMetrics{Bytes: w.Bytes, Packets: w.Packets, LastSeenNs: w.LastSeenNs}
}

func fromSettled(snap snapshotWire) []state.SettledRecord {
	if len(snap.Settled) == 0 {
		return nil
	}
	out := make([]state.SettledRecord, len(snap.Settled))
	for i, s := range snap.Settled {
		out[i] = state.SettledRecord{
			Key: state.SettledKey{
				Tenant: s.TenantID,
				Zone:   bpf.ZoneCode(s.Zone),
				Dir:    bpf.Direction(s.Direction),
			},
			Bytes:   s.Bytes,
			Packets: s.Packets,
		}
	}
	return out
}
