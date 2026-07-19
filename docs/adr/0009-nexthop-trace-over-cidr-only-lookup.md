# ADR 0009 — Nexthop trace over CIDR-only lookup

**Status:** accepted

## Context

When resolving a static route's destination CIDR at cold-start, the simple approach is to query Neutron for "any subnet with this CIDR" and use the first result.

## Decision

Resolve every extraroute by tracing its **nexthop** through the Neutron port topology — an iterative graph walk with cycle detection and a hop limit ([trie-construction.md](../architecture/trie-construction.md#the-static-route-resolver)).

1. **Multiple tenants can have the same CIDR.** Tenant A's `10.0.1.0/24`, Tenant B's `10.0.1.0/24`, and Tenant C's `10.0.1.0/24` are all separate subnets in different network namespaces. Picking "the first match" is arbitrary and wrong.
2. **The nexthop is the disambiguator.** The nexthop is a specific port on a specific subnet attached to a specific router. That router has a known set of attached networks. Scoping the destination-CIDR search to those networks gives a deterministic, unambiguous answer — and iterating the walk resolves multi-hop chains a single-hop check would misclassify as EXTERNAL.

## Consequences

- Cold-start carries the resolver's complexity (cycle set, MAX_HOPS=16, ambiguity policy); the per-packet path stays a single LPM lookup regardless of chain length.
- Genuinely ambiguous topologies fall back to EXTERNAL with a warning and surface on `lachesis_neutron_anomalies{class="ambiguity"}` — safe-billing over guessing.
