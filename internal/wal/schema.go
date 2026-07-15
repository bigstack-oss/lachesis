// schema.go defines what a WAL file *is*: the on-disk schema version,
// the file-suffix constants, the metric stage/fallback label vocabularies,
// the Load outcome types, and the JSON wire structs. These declarations are
// the persisted-serialization contract and change together — a format bump
// touches the version constant, the wire structs it governs, and the
// toWire/fromSnapshot converters in wal.go that bridge them to
// [bpf.FlowKey] / [bpf.FlowMetrics].

package wal

import "github.com/bigstack-oss/lachesis/internal/state"

// SchemaVersion is the on-disk envelope version. Bumped only on a
// change to the wire types below; each bump needs a migration step (or
// an explicit additive-compatibility note) in Load. Newer-than-this on
// disk causes Load to refuse to start (we can't safely interpret a
// future schema).
//
// History:
//   - v1: global_state flow records only.
//   - v2: adds the settled section (docs/DESIGN.md §3.5). Purely
//     additive — a v1 file is a valid v2 file with no settled buckets,
//     so Load reads both without migration.
//   - v3: adds external_network to settled buckets (docs/DESIGN.md
//     §11.5). Purely additive — a v2 settled entry decodes with the
//     field absent, which Load maps to the metadata.NoExternalNetwork
//     sentinel; a pre-external-network bucket IS a "none" bucket, so no
//     migration is needed.
const SchemaVersion uint = 3

// BackupSuffix is appended to the WAL path for the rotated-aside
// previous snapshot. TempSuffix is the in-progress write target.
// QuarantineSuffix is where [Quarantine] preserves an unreadable
// snapshot out of the Save rotation's reach.
const (
	BackupSuffix     = ".bak"
	TempSuffix       = ".tmp"
	QuarantineSuffix = ".quarantine"
)

// Stage labels for lachesis_wal_flush_failures_total{stage=...}. The
// label value set is part of the package's wire contract — operators
// query and dashboard against these strings — so they live here as
// exported consts rather than open-coded at each call site.
const (
	StageMarshal       = "marshal"
	StageWrite         = "write"
	StageFsync         = "fsync"
	StageRenameBak     = "rename_bak"
	StageRenameCurrent = "rename_current"
	StageDirSync       = "dir_sync"
)

// Fallback labels for lachesis_wal_load_fallback_total{from=...}.
// Passed to [Metrics.RecordLoadFallback] from the boot loader.
// LoadFromPrimary is not a fallback and has no label.
const (
	LoadFallbackBak   = "bak"
	LoadFallbackEmpty = "empty"
)

// LoadSource indicates which file Load succeeded against, or that
// no WAL was present at all.
type LoadSource int

// LoadFromPrimary / LoadFromBackup / LoadEmpty are the possible
// outcomes of [Load]. Health metrics in the metrics package use
// LoadFromBackup and LoadEmpty as labels.
const (
	LoadFromPrimary LoadSource = iota
	LoadFromBackup
	LoadEmpty
)

// LoadResult bundles a successful Load. Records is nil when Source
// is LoadEmpty; Settled is nil for LoadEmpty and for v1 snapshots,
// which predate the settled section.
type LoadResult struct {
	Records []state.Record
	Settled []state.SettledRecord
	Source  LoadSource
}

// snapshotWire is the on-disk envelope. Field order and JSON tags
// are the wire format; do not reorder casually. Settled is omitempty
// so a v2 writer with nothing settled produces a byte-identical
// envelope to v1 apart from the version field.
type snapshotWire struct {
	SchemaVersion uint          `json:"schema_version"`
	AgentBuild    string        `json:"agent_build"`
	WrittenAtNs   uint64        `json:"written_at_ns,string"`
	GlobalState   []entryWire   `json:"global_state"`
	Settled       []settledWire `json:"settled,omitempty"`
}

// settledWire mirrors state.SettledRecord on the wire. The tenant is
// the Keystone project UUID string — the only tenant identifier stable
// across boots (see the state.Record invariant note); zone and
// direction reuse the flow-key enum encodings. ExternalNetwork is the
// already-gated label (v3+); omitempty keeps v2-era buckets and "none"
// buckets byte-compatible, and Load maps absence back to the sentinel.
type settledWire struct {
	TenantID        string `json:"tenant_id"`
	ExternalNetwork string `json:"external_network,omitempty"`
	Zone            uint8  `json:"zone"`
	Direction       uint8  `json:"direction"`
	Bytes           uint64 `json:"bytes,string"`
	Packets         uint64 `json:"packets,string"`
}

// entryWire mirrors state.Record on the wire. u64 fields use the
// ,string tag for the IEEE 754 reason in the package doc.
type entryWire struct {
	Key     flowKeyWire     `json:"key"`
	Total   flowMetricsWire `json:"total"`
	LastRaw flowMetricsWire `json:"last_raw"`
}

type flowKeyWire struct {
	SrcMac    [6]uint8 `json:"src_mac"`
	DstMac    [6]uint8 `json:"dst_mac"`
	EthProto  uint16   `json:"eth_proto"`
	Direction uint8    `json:"direction"`
	DstZone   uint8    `json:"dst_zone"`
}

type flowMetricsWire struct {
	Bytes      uint64 `json:"bytes,string"`
	Packets    uint64 `json:"packets,string"`
	LastSeenNs uint64 `json:"last_seen_ns,string"`
}
