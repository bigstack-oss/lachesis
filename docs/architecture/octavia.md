# Octavia LB Attribution

> **Status: designed, not yet implemented.** Nothing in `bpf/telemetry.c` or the
> agent handles Amphorae today — LB traffic currently classifies like any other
> VM traffic and attributes to the Amphora's own (admin) tenant. This chapter is
> the agreed design for the subsystem, kept ahead of the build because its
> empirical groundwork (the two-connection model, the conntrack constraint) was
> expensive to establish. Tracked as feature 131 in the issue backlog.

## The two-connection reality

An [Octavia](./primer.md#octavia-and-amphora-vms) load balancer is implemented by an **Amphora** VM in the admin project, running HAProxy. The traffic appears to flow as one client-to-backend stream, but at the network level it is **two distinct TCP connections** (verified empirically):

```
   Segment 1                              Segment 2
   ──────────                             ──────────
   client ↔ Amphora                       Amphora ↔ backend
   (HAProxy terminates this conn          (HAProxy originates this as a
    inside the Amphora VM)                 brand-new TCP session)
```

HAProxy is an application-layer terminator. From the kernel's perspective these are two completely separate TCP sessions joined only by HAProxy's userspace logic. Conntrack physically cannot bridge them — there is no "single record" with both `client_ip` and `backend_vm_ip`.

This is the same model AWS (ELB) and GCP (Cloud Load Balancing) use: each segment is independently captured at its interface (ENI/VNIC/tap) and independently billed. The billing pipeline sums and dedupes downstream — charging postures and consumption rules in [billing.md](./billing.md).

**Provider scope: amphora only.** The two-connection model below assumes the **amphora** provider — the only Octavia provider enabled on target deployments (verified empirically: the provider list shows amphora alone, and every live LB uses it). The **OVN provider** (no Amphora VM, source IP preserved end-to-end, a single network segment) is a fundamentally different shape and is explicitly out of scope. When this subsystem lands, the agent should log the configured provider at cold-start so a non-amphora deployment is caught loudly rather than silently mis-modeled.

## Billing model — both segments attribute to the LB owner

Naïvely, traffic at the backend's tap appears to come from the Amphora's MAC and would attribute to admin (Amphora's owner). But the customer is the LB's owning tenant. The fix: tag Amphora MACs at cold-start.

| Segment | Captured at | dst_zone | Tenant attribution |
|---|---|---|---|
| 1: client ↔ Amphora | Amphora's tap | depends on client location (EXTERNAL / OTHER / SAME) | LB owner |
| 2: Amphora ↔ backend | Amphora's tap **and** backend's tap | INFRA (LB internal plumbing) | LB owner |

Total LB-mediated billing = Segment 1 + Segment 2 bytes. Segment 2 appears at two taps as the standard one-`tx`-plus-one-`rx` emission pair ([billing.md](./billing.md)); under the per-side charging postures no dedup is needed — and Segment 2 is `infra`, $0 today.

## Mechanism — Amphora MAC flag, not conntrack

At cold-start, the Go agent queries the Octavia API and populates each Amphora's MAC in `mac_tenant_map` with two pieces of metadata:

- `IsAmphora = true`
- `LBOwnerTenant = <tenant_id of the LB>`

(The userspace `ShardedMetadataMap` already carries the `IsAmphora` field on
`TenantMeta`, reserved for this subsystem.)

When a packet arrives:

- If `peer_mac` is flagged Amphora → attribute bytes to `LBOwnerTenant` (instead of Amphora's own admin tenant).
- If `peer_mac` is not an Amphora → normal [hybrid lookup](./packet-classification.md#the-hybrid-lookup-explained).

**No conntrack lookup is required for attribution.** The MAC flag alone is sufficient, and works identically at the Amphora's tap and the backend's tap.

## Optional refinement — conntrack-based zone for Segment 1

At the Amphora's tap, the on-wire packet's `remote_ip` is the post-DNAT Amphora address. To determine the actual client's zone (was the request from the internet, another tenant, or the same tenant?), the kernel can optionally use [`bpf_skb_ct_lookup`](./primer.md#bpf_skb_ct_lookup-and-conntrack) to recover the pre-NAT tuple:

```
ct = bpf_skb_ct_lookup(skb, ...)
if ct: real_client_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip
       re-classify dst_zone using real_client_ip via the LPM trie
else:  dst_zone = EXTERNAL    ← safe-billing default
```

**Critical constraint (verified empirically).** This lookup only works at the **Amphora's tap on the Amphora's compute host**. Reasoning:

1. The conntrack entry that contains the original client_ip is for Segment 1 (`client_ip ↔ floating_ip ↔ Amphora_ip`). It lives on the host that performed the FIP DNAT. In OVN deployments verified empirically, that's the Amphora's compute host (OVN does the DNAT distributed via OVS flow rules with `ct()` actions, and the entry is written to the host's kernel conntrack table).
2. At the backend's tap, the visible conntrack entry is Segment 2's (`Amphora_ip ↔ backend_vm_ip`) — a separate flow with no record of the original client.

**Do not call `bpf_skb_ct_lookup` at the backend's tap.** It would either miss or return Segment 2's entry, which doesn't help. Use the unconditional `INFRA` zone for Segment 2 instead.

## Failure modes

| What fails | Impact | Severity |
|---|---|---|
| Conntrack lookup misses (first SYN, TTL expiry, UDP idle >30s, lookup at wrong tap) | Segment 1 falls back to `dst_zone=EXTERNAL`. **Attribution to LB owner is unaffected** because it comes from the MAC flag, not conntrack | Low |
| Amphora MAC missing from `mac_tenant_map` (Octavia API stale) | Traffic attributes to admin (Amphora's tenant). Self-corrects on the next reconcile pass | Medium |
| UDP listener with sparse traffic | Conntrack default UDP timeout is 30s. Long-idle UDP LB flows lose the Segment 1 conntrack entry between packets → Segment 1 zone falls back to EXTERNAL. Attribution unaffected. Tested deployments use TCP LBs only, so this is not exercised today | Low |

## What this design deliberately does NOT do

Some LB telemetry stories try to "stitch" a single billable record across Conn1 and Conn2 by recovering the client tuple at the backend's tap. We don't:

- AWS and GCP don't (they emit per-ENI / per-VNIC flow records).
- The underlying conntrack physically can't bridge HAProxy-terminated connections.
- Attribution-to-LB-owner doesn't require it.

Our model is segment-by-segment, summed at the billing pipeline.

## Why `bpf_skb_ct_lookup` is TC-only

This helper is only available in TC programs, not XDP — one of the reasons TC was chosen. See [ADR 0001](../adr/0001-tc-clsact-over-xdp.md).

---

Next: [scenarios.md](./scenarios.md) →
