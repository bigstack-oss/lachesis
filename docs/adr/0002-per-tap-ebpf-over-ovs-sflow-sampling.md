# ADR 0002 — Per-tap eBPF counting over OVS sFlow sampling

**Status:** accepted

## Context

sFlow on OVS samples 1-in-N packets, captures the full Ethernet frame including tunnel headers, and ships samples to a collector. The collector parses the VNI to identify the tenant network — solving the "same CIDR across tenants" problem cleanly, with mature off-the-shelf tooling.

## Decision

Count every packet with eBPF TC at each VM tap; reject sampling as the primary billing mechanism.

1. **Sampling is wrong for billing.** Default 1:1000 sampling means short-lived flows can be missed entirely; even on long flows, the byte count has statistical error proportional to `1/sqrt(packets_in_flow)`. For long-tail traffic patterns, this is unacceptable. Billing demands every-packet accuracy.
2. **Loses per-VM precision when sampled at the uplink.** sFlow on the physical NIC misses same-host VM-to-VM traffic entirely (it never leaves OVS). sFlow on br-int fixes this but loses the VNI advantage (no tunnel encap on local traffic).
3. **MAC uniqueness already solves CIDR overlap.** Neutron assigns globally unique MACs across all tenants. Our `mac_tenant_map` resolves the same ambiguity that VNI would resolve in sFlow — we just don't need the outer header.

## Consequences

- Exact byte counts on every observed packet; the residual error budget is the [edge-case tiers](../architecture/edge-cases.md), not sampling variance.
- Same-host east-west traffic is fully covered (each VM has its own tap).

**When sFlow is the right answer:** network-wide visibility, anomaly detection, traffic-matrix estimation, capacity planning. We'd happily run sFlow alongside as a secondary observability layer; we just won't bill from it.
