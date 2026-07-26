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
//   - v2: adds the settled section (docs/architecture/data-structures.md#settled-bytes). Purely
//     additive — a v1 file is a valid v2 file with no settled buckets,
//     so Load reads both without migration.
//   - v3: adds external_network to settled buckets
//     (docs/architecture/billing.md). Purely additive — a v2 settled entry decodes with the
//     field absent, which Load maps to the metadata.NoExternalNetwork
//     sentinel; a pre-external-network bucket IS a "none" bucket, so no
//     migration is needed.
//   - v4: adds the server_settled section — the server tier's fold
//     absorber in the four-layer family hierarchy
//     (docs/architecture/data-structures.md#settled-bytes). Purely
//     additive — a v3 file is a valid v4 file with no server-settled
//     buckets, so Load reads it without migration. v4 also renames the
//     tenant accumulator's key settled → tenant_settled; Load accepts
//     both (LegacySettled), Save writes only the new key.
//   - v5: adds the total_settled section — the total tier's fold
//     absorber, credited when a dead project's tenant-settled bucket is
//     released ([state.GlobalState.PruneTenantSettled],
//     docs/architecture/data-structures.md#settled-bytes). Purely
//     additive — a v4 file is a valid v5 file with no total-settled
//     buckets (no project had died yet), so Load reads it without
//     migration.
//   - v6: adds counters_reset_at_s — the epoch behind
//     lachesis_agent_counters_reset_timestamp_seconds, carried across
//     warm restarts so the gauge keeps declaring the last true state
//     restart (docs/architecture/boot-and-recovery.md). Purely
//     additive — the field decodes as 0 from a v5 file, which the boot
//     restore treats as "epoch unknown" and re-stamps once (a spurious
//     discontinuity is billing-free under the ETL's per-segment
//     baseline subtraction; the one-time alert at upgrade is accepted).
const SchemaVersion uint = 6

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
// is LoadEmpty; TenantSettled is nil for LoadEmpty and for v1 snapshots,
// which predate the settled section; ServerSettled is nil for LoadEmpty
// and for v1–v3 snapshots, which predate the server-settled section;
// TotalSettled is nil for LoadEmpty and for v1–v4 snapshots, which
// predate the total-settled section. CountersResetAt is 0 for
// LoadEmpty and for v1–v5 snapshots, which predate the epoch field —
// the restore treats 0 as "unknown" and stamps a fresh epoch.
type LoadResult struct {
	Records         []state.Record
	TenantSettled   []state.TenantSettledRecord
	ServerSettled   []state.ServerSettledRecord
	TotalSettled    []state.TotalSettledRecord
	CountersResetAt int64
	Source          LoadSource
}

// snapshotWire is the on-disk envelope. Field order and JSON tags
// are the wire format; do not reorder casually. TenantSettled is omitempty
// so a v2 writer with nothing settled produces a byte-identical
// envelope to v1 apart from the version field.
type snapshotWire struct {
	SchemaVersion uint                `json:"schema_version"`
	AgentBuild    string              `json:"agent_build"`
	WrittenAtNs   uint64              `json:"written_at_ns,string"`
	GlobalState   []entryWire         `json:"global_state"`
	TenantSettled []tenantSettledWire `json:"tenant_settled,omitempty"`
	ServerSettled []serverSettledWire `json:"server_settled,omitempty"`
	TotalSettled  []totalSettledWire  `json:"total_settled,omitempty"`
	// CountersResetAtS is the unix-seconds epoch of the last state
	// restart (v6+): the moment counter baselines last became
	// incomparable with what preceded them. Written on every flush so
	// warm restarts carry the last true reset forward.
	CountersResetAtS int64 `json:"counters_reset_at_s,omitempty"`
	// LegacySettled reads the ≤v3 on-disk key `settled` (the tenant
	// accumulator's pre-four-layer name). Load merges it into
	// TenantSettled; Save never writes it (always nil + omitempty).
	LegacySettled []tenantSettledWire `json:"settled,omitempty"`
}

// tenantSettledWire mirrors state.TenantSettledRecord on the wire. The tenant is
// the Keystone project UUID string — the only tenant identifier stable
// across boots (see the state.Record invariant note); zone and
// direction reuse the flow-key enum encodings. ExternalNetwork is the
// already-gated label (v3+) — always "none" or a network name, never
// "", so Save writes it on every bucket; omitempty matters only on
// decode, where a v2-era entry's absent field reads as "" and Load
// maps it to the sentinel.
type tenantSettledWire struct {
	TenantID        string `json:"tenant_id"`
	ExternalNetwork string `json:"external_network,omitempty"`
	Zone            uint8  `json:"zone"`
	Direction       uint8  `json:"direction"`
	Bytes           uint64 `json:"bytes,string"`
	Packets         uint64 `json:"packets,string"`
}

// serverSettledWire mirrors state.ServerSettledRecord on the wire — the
// server tier's fold absorber (v4+). Like tenantSettledWire it carries the
// stable project UUID and the already-gated external_network label, and
// adds server_id (the Nova instance UUID). Lifecycle state is not
// persisted — release is re-derived from the Nova list on the next
// reconcile after restore.
type serverSettledWire struct {
	ServerID        string `json:"server_id"`
	TenantID        string `json:"tenant_id"`
	ExternalNetwork string `json:"external_network,omitempty"`
	Zone            uint8  `json:"zone"`
	Direction       uint8  `json:"direction"`
	Bytes           uint64 `json:"bytes,string"`
	Packets         uint64 `json:"packets,string"`
}

// totalSettledWire mirrors state.TotalSettledRecord on the wire — the
// total tier's fold absorber (v5+). No tenant or server dimension: the
// key is exactly the lachesis_bytes_total label tuple (the already-gated
// external_network label plus the flow-key zone/direction encodings).
// Never pruned, so no lifecycle state to persist.
type totalSettledWire struct {
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
