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
//
// Readers therefore see either the previous snapshot (if a crash
// happens between steps 2 and 3) or the new one (after step 3) —
// never a partial write.
//
// # Boot read protocol
//
//  1. Try path. On parse / schema-version mismatch, fall back to
//     path+".bak" and increment LoadResult.Source = LoadFromBackup.
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
	"time"

	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/bpf"
	"github.com/bigstack-oss/cube-cos-network-telemetry/internal/state"
)

// stageErr attributes a Save failure to one of the labelled stages
// in cubecos_wal_flush_failures_total — see the Stage* consts above.
// Save returns errors wrapped this way so the caller can decide
// which counter to bump without parsing error messages.
type stageErr struct {
	Stage string
	Err   error
}

func (e *stageErr) Error() string { return fmt.Sprintf("wal %s: %v", e.Stage, e.Err) }
func (e *stageErr) Unwrap() error { return e.Err }

// Save writes records to path via the atomic tmp+fsync+rename
// rotation described in the package doc. agentBuild is informational
// (correlation with build logs); empty is acceptable. m may be nil
// when phase timings and failure stages are not needed.
func Save(path, agentBuild string, records []state.Record, m *Metrics) error {
	snap := snapshotWire{
		SchemaVersion: SchemaVersion,
		AgentBuild:    agentBuild,
		WrittenAtNs:   uint64(time.Now().UnixNano()),
		GlobalState:   make([]entryWire, len(records)),
	}
	for i := range records {
		snap.GlobalState[i] = toWire(records[i])
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

// Load reads path, falling back to path+".bak" on parse failure or
// schema mismatch. Both files missing returns a LoadResult with
// Source=LoadEmpty (no error — first boot is normal).
func Load(path string) (LoadResult, error) {
	primary, primaryErr := readAndParse(path)
	if primaryErr == nil {
		return LoadResult{Records: fromSnapshot(primary), Source: LoadFromPrimary}, nil
	}

	bakPath := path + BackupSuffix
	backup, backupErr := readAndParse(bakPath)
	if backupErr == nil {
		return LoadResult{Records: fromSnapshot(backup), Source: LoadFromBackup}, nil
	}

	// Both missing is the first-boot path; report as empty.
	if errors.Is(primaryErr, fs.ErrNotExist) && errors.Is(backupErr, fs.ErrNotExist) {
		return LoadResult{Records: nil, Source: LoadEmpty}, nil
	}

	return LoadResult{}, fmt.Errorf(
		"wal: primary load %s failed: %w; backup load %s failed: %v",
		path, primaryErr, bakPath, backupErr,
	)
}

// readAndParse opens path, decodes the envelope, and validates the
// schema version. ENOENT and JSON / schema errors are returned
// verbatim so the caller can distinguish them.
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
		return snap, fmt.Errorf("wal: %s schema_version=%d, this build understands up to %d",
			path, snap.SchemaVersion, SchemaVersion)
	}
	// SchemaVersion < ours would normally trigger a migration step,
	// one per version. v1 is the first version; no migrations exist
	// yet, so anything older than 1 is also unrepresentable. Keep
	// the check open for future versions.
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
