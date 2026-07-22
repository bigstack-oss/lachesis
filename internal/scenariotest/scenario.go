// Package scenariotest declares the types that scenariotest consumes:
// a [Scenario] bundles a topology (built via the existing
// [scenario.Builder] DSL), a placement map, a per-project policy,
// declared [Flow] entries describing traffic to drive, and [Expect]
// entries asserting which /metrics deltas must follow.
//
// In-memory [neutron.BuildTrie] tests continue to consume the
// underlying [scenario.Builder] directly and ignore the live-only
// fields. The scenariotest CLI consumes [Scenario] in full: `up`
// realizes Builder.Build() as live OpenStack resources, `drive`
// pushes the [Flow] traffic, and `assert` checks the [Expect] deltas.
package scenariotest

import (
	"github.com/bigstack-oss/lachesis/internal/testenv/scenario"
)

// Scenario is one named, end-to-end-runnable description: topology
// plus what traffic to drive across it plus what /metrics deltas to
// expect. Constructed in cmd/scenariotest/scenarios.
type Scenario struct {
	// Name is the CLI handle (e.g. "twovms-same-tenant"). Must be
	// unique across the registered scenarios.
	Name string

	// Desc is a one-line human description shown by `scenariotest
	// list` and in failure output.
	Desc string

	// Builder owns the topology. Live realize calls Builder.Build()
	// for the [neutron.Snapshot] it translates into OpenStack
	// resources.
	Builder *scenario.Builder

	// Flavor optionally overrides the Nova flavor used to boot this
	// scenario's VMs. Empty falls back to the config's global
	// prerequisites.flavor_name. Validated at preflight; never
	// created.
	Flavor string

	// Placement pins specific DSL VM ids to hypervisors: either a
	// literal hypervisor name (operator one-offs) or a symbolic slot
	// "node:<i>" naming the i-th entry of the config's cluster.agents
	// list, so a registered scenario never hard-codes a cluster's
	// hostnames. A missing entry leaves placement to the Nova
	// scheduler. Slots resolve and names are validated against the
	// Nova hypervisor list at preflight.
	Placement Placement

	// Projects overrides per-project lifecycle policy. Any project
	// name referenced in the topology but absent from this map
	// defaults to ReuseOrCreate.
	Projects ProjectPolicy

	// FIPs optionally overrides how `up` allocates a VM's floating
	// IP. By default `up` allocates one FIP per VM from the config's
	// external network so `drive` can SSH in; an entry keyed by DSL
	// VM id pins a specific external network or fixed address
	// instead. A VM absent from this map gets the default
	// allocation.
	FIPs map[string]FIPSpec

	// Flows declares the traffic to drive between realize and
	// assert. Each Flow runs once at `scenariotest drive`.
	Flows []Flow

	// Expect lists the per-tuple lower-bound assertions
	// `scenariotest assert` evaluates against /metrics deltas. Live
	// testing only ever lower-bounds; declaring upper bounds is
	// hostile to background tenant traffic.
	Expect []Expect

	// CreateExternalNets lists external-network DSL ids realize must
	// CREATE (with `router:external=true`, no provider segment)
	// instead of binding to the config's provider network — the
	// default for every other external marker. A created external
	// network allocates FIPs and takes router gateways but carries no
	// wire traffic; the multi-external-path scenario uses one as the
	// VM's second external path. Its subnets ARE created (unlike
	// provider-bound markers, whose subnets belong to the platform).
	CreateExternalNets []string

	// Deferred lists DSL VM ids that `up` declares but does NOT boot:
	// no port, no server, no FIP, no attach-gate slot. A later
	// [BootVMStep] realizes them mid-run — e.g. the mac-reuse scenario
	// boots a VM only after another VM's MAC has been swept. Ids here
	// must not appear in Flows that run before their BootVMStep.
	Deferred []string

	// Steps optionally scripts what `run` does between up and down.
	// Empty keeps the classic linear loop — drive every Flow, assert
	// every Expect — so the plain zone scenarios need not declare
	// anything. A non-empty list replaces that loop entirely; see
	// [Step] for the vocabulary.
	Steps []Step
}

// FIPSpec pins how a VM's floating IP is allocated, overriding the
// default (one FIP per VM from the config external network).
type FIPSpec struct {
	// ExternalNet is the external network name to allocate from.
	// Empty falls back to the config's external_network_name.
	ExternalNet string

	// FixedIP requests a specific floating address. Empty lets
	// Neutron assign one from the external pool.
	FixedIP string
}

// Placement maps DSL VM id to a hypervisor name or a "node:<i>"
// slot (see [Scenario.Placement]). Empty value or missing key = let
// Nova schedule.
type Placement map[string]string

// ProjectPolicy maps project name (as it appears in the topology)
// to its lifecycle policy. Default is [ReuseOrCreate].
type ProjectPolicy map[string]Policy

// Policy is the lifecycle policy for a single project.
type Policy int

const (
	// ReuseOrCreate looks the project up in Keystone by mangled
	// name. If present, use it; if absent, create it. Never
	// deleted at teardown.
	ReuseOrCreate Policy = iota

	// ForceFresh fails preflight if a project with the mangled
	// name already exists. Always creates. Still never deleted at
	// teardown.
	ForceFresh
)

// Flow describes one traffic-driving step. From names a DSL VM id;
// To names either another VM (via [VMTarget]) or an arbitrary IP
// reachable from the source VM (via [ExternalTarget]).
type Flow struct {
	From  string
	To    FlowTarget
	Bytes int64
	Proto Protocol
}

// FlowTarget is the destination of a [Flow]. Exactly one of VMID
// or IP is non-empty; construct via [VMTarget] or [ExternalTarget].
type FlowTarget struct {
	VMID string
	IP   string
}

// VMTarget returns a [FlowTarget] pointing at another DSL VM. The
// driver resolves it to the VM's internal IP at drive time.
func VMTarget(vmID string) FlowTarget { return FlowTarget{VMID: vmID} }

// ExternalTarget returns a [FlowTarget] pointing at a literal IP
// reachable from the source VM. Used for "VM → public" and
// "VM → routed-peer" flows.
func ExternalTarget(ip string) FlowTarget { return FlowTarget{IP: ip} }

// Protocol is the L4 protocol a [Flow] drives. The agent counts bytes
// L4-agnostically — the kernel classifier keys on MAC / ethertype /
// zone and accumulates skb->len with no TCP/UDP branch (bpf/telemetry.c)
// — so UDP is attributed exactly like TCP. The driver only generates
// TCP for now because a flow-controlled stream delivers a deterministic
// byte count to lower-bound against; UDP driving (no delivery
// guarantee, no backpressure) is a driver TODO, not an agent limit.
type Protocol int

const (
	TCP Protocol = iota
	UDP
)

// Expect is one lower-bound assertion on the /metrics counter
// tuple {tenant_id, zone, direction}. The delta (post − pre) for
// the named tuple must be at least MinBytes.
type Expect struct {
	// TenantID is the DSL project name (e.g. "T1"). `assert`
	// resolves it to the created/reused Keystone project UUID — the
	// value actually carried in the metric's `tenant_id` label —
	// before matching.
	TenantID string

	// Zone is the zone-label string as it appears in /metrics:
	// one of "same_tenant", "external", "other_tenant", "shared",
	// "infra", "miss", "multicast".
	Zone string

	// Direction is the metric's `direction` label value: "tx" (the
	// VM is sending) or "rx" (the VM is receiving). This is the
	// real exposition vocabulary (see internal/bpf/schema.go), not
	// the host-frame ingress/egress.
	Direction string

	// ExternalNetwork optionally narrows the assertion to series
	// carrying this `external_network` label. Empty matches any
	// (summing across, the pre-label behavior — existing scenarios
	// unchanged). A DSL external-network marker id (e.g. "net-ext")
	// resolves to the provider network the config bound it to, the
	// same way TenantID resolves to a project UUID; any other value
	// (including the "none" sentinel) matches literally.
	ExternalNetwork string

	// VM optionally retargets the assertion at the per-server family
	// `lachesis_server_bytes_total` for this DSL VM's created server
	// (resolved to its Nova UUID via the run-state) instead of the
	// tenant family. Combines with ExternalNetwork.
	VM string

	// Node optionally narrows the assertion to the series one agent's
	// tap exposed, instead of the cluster-wide sum: a placement slot
	// ("node:<i>", the same vocabulary as [Scenario.Placement]) or a
	// literal configured agent host. This is what makes a cross-host
	// assertion mean something — "tx at the sender's node AND rx at
	// the receiver's node" — where the collective sum could not tell
	// the taps apart. Combines with ExternalNetwork and VM. Node means
	// "the agent that OBSERVED the bytes", not "where the VM was
	// booted": after a live migration a server's new bytes surface on
	// the destination node's agent, which is exactly what a migration
	// scenario asserts.
	Node string

	// MinBytes is the lower bound on the delta of
	// lachesis_tenant_bytes_total (or lachesis_server_bytes_total when VM is
	// set) for this tuple over the drive window.
	MinBytes int64
}
