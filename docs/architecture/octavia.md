# Octavia LB Attribution

An [Octavia](./primer.md#octavia-and-amphora-vms) load balancer is implemented by
an **Amphora** VM running HAProxy, and that VM lives in the Octavia service
project — not in the project of the tenant who created the load balancer. Left
alone, every byte a tenant's load balancer moves bills the operator. This chapter
is how the agent bills the customer instead.

## The two-connection reality

The traffic looks like one client-to-backend stream. At the network level it is **two distinct TCP connections** (verified empirically):

```
   Segment 1                              Segment 2
   ──────────                             ──────────
   client ↔ Amphora                       Amphora ↔ backend
   (HAProxy terminates this conn          (HAProxy originates this as a
    inside the Amphora VM)                 brand-new TCP session)
```

HAProxy is an application-layer terminator. From the kernel's perspective these are two completely separate TCP sessions joined only by HAProxy's userspace logic. Conntrack physically cannot bridge them — there is no "single record" with both `client_ip` and `backend_vm_ip`.

This is the same model AWS (ELB) and GCP (Cloud Load Balancing) use: each segment is independently captured at its interface (ENI/VNIC/tap) and independently billed. The billing pipeline sums and dedupes downstream — charging postures and consumption rules in [billing.md](./billing.md).

**Provider scope: amphora only.** The model assumes the **amphora** provider — the only Octavia provider enabled on target deployments (verified: the provider list shows amphora and its deprecated `octavia` alias, and every live LB uses it). The **OVN provider** (no Amphora VM, source IP preserved end-to-end, a single network segment) is a different shape and is out of scope. Load balancers on any other provider are skipped by the join and warn-logged once per sync, so a provider migration surfaces in the log rather than in a billing discrepancy.

## Billing model

| Segment | Captured at | `dst_zone` | Tenant attribution |
|---|---|---|---|
| 1: client ↔ Amphora | Amphora's tap | the **client's** location — `external`, `other_tenant`, or `same_tenant` | LB owner |
| 2: Amphora ↔ backend | Amphora's tap **and** backend's tap | `infra` (LB internal plumbing, $0 today) | Amphora's tap: LB owner. Backend's tap: the backend's own project |

Two properties are worth stating explicitly because both were gotten wrong on the way here:

- **Attribution follows the VM whose tap saw the packet, never the peer.** The Amphora's taps bill the LB owner; the backend VM's tap bills the backend's project. Overriding a backend's tenant because its *peer* is an Amphora would put a `server_id` under a `tenant_id` that does not own it, breaking the `total → tenant → server → port` nesting of [Contract 7](./contracts.md#required-contracts). In the ordinary topology the two coincide anyway — a tenant's load balancer fronts that tenant's own VMs.
- **Segment 1 is billable and must not be swallowed by `infra`.** An internal client reaching a load balancer is real tenant traffic. Zoning it `infra` would make a cross-tenant client's request free in both directions.

## Mechanism

Three pieces, all fed by one join at cold-start and re-asserted on every reconcile.

### 1. Re-attribute the Amphora's ports (userspace)

Attribution is a userspace lookup on the VM-side MAC, so re-attribution needs no kernel involvement at all: write the load balancer's project into the Amphora port's `TenantMeta` instead of the port's own. That single substitution moves both the `tenant_id` Prometheus label and the interned tenant the kernel keys zone comparisons on.

The join (`neutron.AmphoraOwnerByPort`) runs in three hops:

```
load balancer   ─ project_id ─→  the billing tenant
      ↑ loadbalancer_id
  Amphora       ─ compute_id ─→  every port whose device_id matches
                                 MINUS the management port
```

`compute_id` — the Nova instance UUID — is the join key, **not** the Amphora's `vrrp_port_id`. That field names only the VIP-network port. When a pool member lives on another subnet, Octavia plugs the Amphora into the member's network as well, and it does so by handing Nova a network ID with no port; Nova then mints a port indistinguishable from any other `compute:nova` port, with no Octavia marker and no allowed-address-pair. Enumerating by the instance UUID is the only signal that covers both ports.

The **management port** — the one holding the Amphora's `lb_network_ip` on the Octavia management network — is excluded. It carries health-manager heartbeats, not tenant traffic; re-attributing it would bill a tenant a permanent background trickle for the operator's own control plane.

### 2. Mark the Amphora in the kernel (`mac_tenant_map` top bit)

The classifier needs to know an Amphora is on the flow. The marker rides the top bit of the existing `mac_tenant_map` value; the low 31 bits stay the interned tenant id, masked off before the tenant comparison and before use as the `subnet_zone_trie` key.

Packed rather than given its own map because a sidecar lookup would cost ~20–30 ns on every packet whose peer resolves — against a measured 82–110 ns per-packet budget — to produce nothing but a zone label. Packing costs one `AND`. Cilium packs flags into `ipcache` values for the same reason. The mask bounds a deployment at 2³¹−1 tenants, which is documented rather than enforced.

### 3. Separate the segments by the Amphora's own address (`amphora_base_ip`)

Both segments cross the same Amphora MAC, so the marker alone cannot tell them apart. Their **addresses** can:

- Segment 1 — HAProxy accepted the connection on the load balancer's **VIP**.
- Segment 2 — HAProxy originated it from the port's own **base address** (verified on-wire).

So the kernel carries a small set of Amphora base addresses, keyed `(tenant_id, ipv4)`:

```
if either end carries the Amphora marker:
        amp_ip = that end's OWN address
        if amp_ip ∈ amphora_base_ip  → ZONE_INFRA     (Segment 2)
        else                          → fall through  (Segment 1, classify by tenant)
```

Only the marked end's own address is probed, and the key is tenant-scoped, because private CIDRs overlap freely across projects — a bare-IP set would let one tenant's Amphora address silently reclassify another tenant's traffic.

The set is **base addresses, not VIPs**, for two reasons. It is directly derivable from the ports the join already produces — the VIP lives on a separate `device_owner=Octavia` port and appears on a data port only as an allowed-address pair, never as a fixed IP, so a data port's fixed IPs *are* precisely the base addresses. And it fails in the safe direction: a missing entry drops Segment 2 to `same_tenant`, which is $0 either way, whereas a missing VIP in the mirror-image design would mark Segment 1 `infra` and stop billing it.

Checking **both** ends matters because one Segment 2 transfer is seen at the Amphora's tap and at the backend's tap. The both-sides emission invariant pairs one `tx` with one `rx` series per transfer ([billing.md](./billing.md)); splitting that pair across two zones would make it unreconcilable.

An **external** client never reaches this branch at all: its peer MAC is a router interface, absent from `mac_tenant_map`, so Segment 1 falls to the LPM trie and lands `external` — the billable half — with no special case.

## Degradation

Every part of this is additive, and every failure lands on "attribute as if Octavia did not exist" rather than on a wrong tenant:

| What fails | Impact | Severity |
|---|---|---|
| No Octavia endpoint in the Keystone catalog | Both lists empty, no re-attribution. Amphora traffic bills the service project, exactly as before this subsystem existed | Low |
| Octavia unreachable, or the admin-only amphora list refused by policy | Same, plus `lachesis_neutron_api_errors_total{endpoint="amphorae"}` and a warn-log. Self-corrects on the next successful sync | Medium |
| Amphora missing from the list (Octavia stale, or still booting with no `compute_id`) | That Amphora's traffic bills the service project. Self-corrects on the next reconcile | Medium |
| A base address missing from `amphora_base_ip` | Segment 2 zones `same_tenant` instead of `infra`. Both are $0 — no billing impact | Low |
| Load balancer on a non-amphora provider | Not re-attributed, warn-logged with a count once per sync | Low |

`lachesis_neutron_amphora_ports` is the health signal: a drop to zero while load balancers still exist means the join stopped resolving and that traffic has quietly reverted to the service project.

## Known limitation — non-member clients on the Amphora's L2

A tenant VM that is L2-adjacent to the Amphora and talks to the **VIP** is classified correctly (`same_tenant` / `other_tenant`) because the VIP is not in the base-address set. But a VM that talks directly to the Amphora's **base address** — not something Octavia's data path ever does — would zone `infra`. There is no legitimate traffic of that shape; it is recorded here because the rule is address-based rather than intent-based.

## What this design deliberately does NOT do

Some LB telemetry stories try to "stitch" a single billable record across Segment 1 and Segment 2 by recovering the client tuple at the backend's tap. We don't:

- AWS and GCP don't (they emit per-ENI / per-VNIC flow records).
- The underlying conntrack physically can't bridge HAProxy-terminated connections — verified by inspecting host conntrack, where neither segment's entry holds both the client and backend addresses.
- Attribution to the LB owner doesn't require it.

Our model is segment-by-segment, summed at the billing pipeline.

**Per-backend byte counts are also out of scope for the data plane.** Proxy-terminating load balancers (ALB, GCP HTTP LB, HAProxy) never recover per-member bytes from packets; the industry reads the proxy's own statistics instead. If per-member accounting is ever wanted, the source is Octavia's `PROMETHEUS` listener (Octavia ≥ Yoga), which serves `octavia_member_bytes_in_total` / `_bytes_out_total` per pool member — a userspace collector, not a change to this design.

**Conntrack-based Segment 1 refinement is deferred.** The original design used [`bpf_skb_ct_lookup`](./primer.md#bpf_skb_ct_lookup-and-conntrack) at the Amphora's tap to recover a pre-NAT client IP. It turned out to be unnecessary for the common case: external client IPs survive FIP DNAT (only the destination is rewritten), so the trie classifies Segment 1 directly. It would still help for SNAT/hairpin clients, and remains available — the helper is TC-only, one of the reasons TC was chosen ([ADR 0001](../adr/0001-tc-clsact-over-xdp.md)).

---

Next: [scenarios.md](./scenarios.md) →
