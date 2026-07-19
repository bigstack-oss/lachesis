# ADR 0011 — No in-VM agent for OS-level routes

**Status:** accepted

## Context

Routes configured inside a guest (`ip route add …` in the VM) are invisible to Neutron and therefore to the trie; such traffic classifies EXTERNAL ([Scenario H](../architecture/scenarios.md)). An in-VM agent could report guest routing tables to close the gap.

## Decision

No guest agent, ever. OS-level routes stay a documented exception that bills at the external rate.

1. **Defeats the eBPF design's whole premise.** The point of TC at the tap is that it works regardless of what the VM runs. An in-VM agent depends on guest cooperation.
2. **Tenants run arbitrary OSes.** Windows, BSD, custom distros, containers-as-VMs. Maintaining agents for all is operational pain.
3. **Tenants have admin on their VMs.** A privileged user can disable the agent and reroute traffic invisibly — the mechanism is defeatable by exactly the party it would police.
4. **A billing-safe fallback exists and aligns incentives.** Unknown routes charge at the higher external rate; tenants who want internal rates have an incentive to use Neutron-managed routing.

## Consequences

- The accuracy ceiling permanently carries this exception ([edge-cases.md](../architecture/edge-cases.md) Tier 3 row 9); it is provider-favorable, not revenue leak.
