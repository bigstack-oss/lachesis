// Package wal is the agent's write-ahead log: an atomic JSON snapshot of
// [state.GlobalState], flushed every 60s and read back on boot to seed
// state before the scraper starts.
//
// Two things a change here must preserve:
//
//   - u64 fields cross the wire as decimal strings. JSON numbers are
//     doubles and lose precision above 2^53, which is real byte counts.
//   - The write is tmp → fsync → rename → fsync the parent directory.
//     Skipping the directory fsync leaves the renames unjournaled, so a
//     power loss can roll back to the previous snapshot.
//
// docs/architecture/primer.md#write-ahead-log
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
	"github.com/bigstack-oss/lachesis/internal/metadata"
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

// Save writes one snapshot via the atomic rotation in the package doc.
// The slices MUST come from a single SnapshotForWAL call — separately
// taken ones tear across a concurrent fold and persist the folded bytes
// twice or not at all. agentBuild is informational; m may be nil.
func Save(path, agentBuild string, records []state.Record, settled []state.TenantSettledRecord, serverSettled []state.ServerSettledRecord, totalSettled []state.TotalSettledRecord, countersResetAt int64, m *Metrics) error {
	snap := snapshotWire{
		SchemaVersion:    SchemaVersion,
		AgentBuild:       agentBuild,
		WrittenAtNs:      uint64(time.Now().UnixNano()),
		GlobalState:      make([]entryWire, len(records)),
		CountersResetAtS: countersResetAt,
	}
	for i := range records {
		snap.GlobalState[i] = toWire(records[i])
	}
	if len(settled) > 0 {
		snap.TenantSettled = make([]tenantSettledWire, len(settled))
		for i, s := range settled {
			snap.TenantSettled[i] = tenantSettledWire{
				TenantID:        s.Key.Tenant,
				ExternalNetwork: s.Key.ExtNet,
				Zone:            uint8(s.Key.Zone),
				Direction:       uint8(s.Key.Dir),
				Bytes:           s.Bytes,
				Packets:         s.Packets,
			}
		}
	}
	if len(serverSettled) > 0 {
		snap.ServerSettled = make([]serverSettledWire, len(serverSettled))
		for i, s := range serverSettled {
			snap.ServerSettled[i] = serverSettledWire{
				ServerID:        s.Key.ServerID,
				TenantID:        s.Key.Tenant,
				ExternalNetwork: s.Key.ExtNet,
				Zone:            uint8(s.Key.Zone),
				Direction:       uint8(s.Key.Dir),
				Bytes:           s.Bytes,
				Packets:         s.Packets,
			}
		}
	}
	if len(totalSettled) > 0 {
		snap.TotalSettled = make([]totalSettledWire, len(totalSettled))
		for i, s := range totalSettled {
			snap.TotalSettled[i] = totalSettledWire{
				ExternalNetwork: s.Key.ExtNet,
				Zone:            uint8(s.Key.Zone),
				Direction:       uint8(s.Key.Dir),
				Bytes:           s.Bytes,
				Packets:         s.Packets,
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
		return LoadResult{Records: fromSnapshot(primary), TenantSettled: fromTenantSettled(primary), ServerSettled: fromServerSettled(primary), TotalSettled: fromTotalSettled(primary), CountersResetAt: primary.CountersResetAtS, Source: LoadFromPrimary}, nil
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
		return LoadResult{Records: fromSnapshot(backup), TenantSettled: fromTenantSettled(backup), ServerSettled: fromServerSettled(backup), TotalSettled: fromTotalSettled(backup), CountersResetAt: backup.CountersResetAtS, Source: LoadFromBackup}, nil
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

// Quarantine moves an unreadable snapshot out of the Save rotation's
// reach — without it the next two flushes destroy the evidence. One
// slot only: a later quarantine overwrites the earlier, bounding disk
// use across a crash loop while keeping the most recent failure.
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
	return flowMetricsWire{Bytes: m.Bytes, Packets: m.Packets, LastSeenNs: m.LastSeenNs, CreatedNs: m.CreatedNs}
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
	return bpf.FlowMetrics{Bytes: w.Bytes, Packets: w.Packets, LastSeenNs: w.LastSeenNs, CreatedNs: w.CreatedNs}
}

func fromTenantSettled(snap snapshotWire) []state.TenantSettledRecord {
	// ≤v3 files carry the tenant accumulator under the legacy `settled`
	// key (schema.go); v4+ writes `tenant_settled`. A file never has
	// both — Save writes only the new key — so merging is a plain pick.
	src := snap.TenantSettled
	if len(src) == 0 {
		src = snap.LegacySettled
	}
	if len(src) == 0 {
		return nil
	}
	out := make([]state.TenantSettledRecord, len(src))
	for i, s := range src {
		// v2 snapshots predate the external_network dimension; an
		// absent field decodes as "" and means exactly "no external
		// network" — the sentinel bucket (schema.go v3 note).
		ext := s.ExternalNetwork
		if ext == "" {
			ext = metadata.NoExternalNetwork
		}
		out[i] = state.TenantSettledRecord{
			Key: state.TenantSettledKey{
				Tenant: s.TenantID,
				ExtNet: ext,
				Zone:   bpf.ZoneCode(s.Zone),
				Dir:    bpf.Direction(s.Direction),
			},
			Bytes:   s.Bytes,
			Packets: s.Packets,
		}
	}
	return out
}

// fromTotalSettled converts the wire total-settled section (v5+) back
// to state records. Nil for pre-v5 snapshots — a file written before
// the section existed has, by definition, never pruned a tenant bucket,
// so an empty absorber is the correct restore.
func fromTotalSettled(snap snapshotWire) []state.TotalSettledRecord {
	if len(snap.TotalSettled) == 0 {
		return nil
	}
	out := make([]state.TotalSettledRecord, len(snap.TotalSettled))
	for i, s := range snap.TotalSettled {
		// Same absent-external_network→sentinel handling as
		// fromTenantSettled; a total-settled bucket always occupies a
		// real emitted series.
		ext := s.ExternalNetwork
		if ext == "" {
			ext = metadata.NoExternalNetwork
		}
		out[i] = state.TotalSettledRecord{
			Key: state.TotalSettledKey{
				ExtNet: ext,
				Zone:   bpf.ZoneCode(s.Zone),
				Dir:    bpf.Direction(s.Direction),
			},
			Bytes:   s.Bytes,
			Packets: s.Packets,
		}
	}
	return out
}

func fromServerSettled(snap snapshotWire) []state.ServerSettledRecord {
	if len(snap.ServerSettled) == 0 {
		return nil
	}
	out := make([]state.ServerSettledRecord, len(snap.ServerSettled))
	for i, s := range snap.ServerSettled {
		// Same absent-external_network→sentinel handling as fromTenantSettled;
		// a server-settled bucket always occupies a real emitted series.
		ext := s.ExternalNetwork
		if ext == "" {
			ext = metadata.NoExternalNetwork
		}
		out[i] = state.ServerSettledRecord{
			Key: state.ServerSettledKey{
				ServerID: s.ServerID,
				Tenant:   s.TenantID,
				ExtNet:   ext,
				Zone:     bpf.ZoneCode(s.Zone),
				Dir:      bpf.Direction(s.Direction),
			},
			Bytes:   s.Bytes,
			Packets: s.Packets,
		}
	}
	return out
}
