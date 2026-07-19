# ADR 0001 — TC clsact over XDP

**Status:** accepted

## Context

We need an eBPF hook that sees every packet a VM sends and receives, at its tap interface. XDP runs even earlier than TC — at the driver level, before `skb` allocation. It's the fastest possible eBPF hook point, and Cilium and Katran use it for high-throughput packet processing.

## Decision

Attach TC programs under a `clsact` qdisc on each tap — `tc_telemetry_in` on the ingress hook, `tc_telemetry_out` on egress. Reject XDP.

1. **XDP is ingress-only on tap interfaces.** Empirically confirmed (2026-04-30): XDP attached to a tap captures 0% of the packets the VM *receives*. We need both directions for billing.
2. **No `bpf_skb_ct_lookup` for XDP.** XDP runs before `nf_conntrack` has matched the packet. The [Octavia design](../architecture/octavia.md) becomes impossible without conntrack.
3. **Throughput advantage is moot for us.** TC processes ~14 Mpps on a single core with our program. The bottleneck on a real OpenStack node is the OVS forwarding pipeline, not our ~150 ns of telemetry overhead.

## Consequences

- Both directions covered by one qdisc per tap; attach/detach is a single idempotent `FilterReplace` (with a pinned priority — see [boot-and-recovery.md](../architecture/boot-and-recovery.md)).
- The conntrack helper stays available for the Segment-1 zone refinement when Octavia lands.

**When XDP is the right answer:** L4 load balancers, DDoS mitigation, raw-packet analytics — anywhere you don't need both directions or conntrack.
