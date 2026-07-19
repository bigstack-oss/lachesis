# Trie Construction at Cold Start

This is the hardest part of the system. The kernel does a single LPM lookup
(plus the sentinel fallback); all the intelligence is in **how Go assembles the
trie** before traffic starts flowing. The builder lives in
`internal/neutron` (`BuildTrie`, with the static-route resolver in `resolve.go`).

## Data sources

Neutron v2.0 API only:

| Endpoint | Fields used |
|---|---|
| `GET /v2.0/networks` | `id, tenant_id, shared, router:external` |
| `GET /v2.0/subnets` | `id, network_id, cidr, tenant_id, gateway_ip` |
| `GET /v2.0/ports` | `id, network_id, mac_address, device_id, device_owner, fixed_ips, tenant_id` |
| `GET /v2.0/routers` | `id, tenant_id, external_gateway_info, routes` |
| `GET /v2.0/address-scopes` + `subnetpools` | optional, for explicit cross-tenant peering |

**OVN deployments.** All needed data comes through the standard Neutron port API; no DB queries, no OVN-specific extensions. OVN-specific `device_owner` values (`network:distributed`, etc.) are handled in step 4 below. The traditional Neutron `dvr-mac-addresses` extension is NOT used by OVN, and OVN does not require per-host MAC enumeration because logical routers have a single MAC across all chassis (routing is implemented by OVS flow rules, not per-host `qrouter-XXX` namespaces).

**Why API and not direct MySQL.** Neutron's internal schema migrates with each OpenStack release. The v2.0 API is explicitly versioned and backward-compatible. Direct DB access also requires DB credentials — a security concern. All joins are done in Go memory after caching the API responses. See [ADR 0003](../adr/0003-neutron-api-over-direct-mysql.md).

## The five-step algorithm

Global rows (steps 1, 3, 4) are emitted **once**, under the sentinel
`tenant_id=0` — the kernel falls back to them when the per-tenant lookup misses
([packet-classification.md](./packet-classification.md), step 7). Only steps 2
and 5 emit per-tenant rows. (An earlier per-tenant-everything shape replicated
every global row once per tenant — ~96% of trie occupancy on a 27-tenant
deployment — and would overflow the 16,384 cap at production tenant counts; see
[data-structures.md](./data-structures.md#kernel-side-bpf-maps).)

```
Run once at cold start, then incrementally on every reconcile:

  Step 1 — Catchall                                    [global, once]
    add (0, 0.0.0.0/0) → ZONE_EXTERNAL

  Step 2 — Directly-owned subnets                      [per tenant T]
    for each subnet S where S.network.tenant_id == T
                       AND not S.network.shared
                       AND not S.network.router:external:
      add (T, S.cidr) → ZONE_SAME_TENANT

  Step 3 — Shared networks                             [global, once]
    for each subnet S where S.network.shared == true
                       AND not S.network.router:external:
      add (0, S.cidr) → ZONE_SHARED

  Step 4 — Infrastructure IPs                          [global, once]
    for each port P with device_owner in {
        network:dhcp,                   # traditional Neutron DHCP
        network:metadata,               # traditional Neutron metadata
        network:distributed,            # OVN distributed DHCP — IP only
        network:router_interface,       # router-to-subnet attachment
        network:router_gateway,         # router-to-external attachment
      }:
      add (0, P.fixed_ip/32) → ZONE_INFRA

    for each subnet S where S.gateway_ip is set:
      add (0, S.gateway_ip/32) → ZONE_INFRA

    add (0, 169.254.169.254/32) → ZONE_INFRA           # Nova metadata

  Step 5 — Static routes (extraroutes)                 [per tenant T]
    for each router R where R.tenant_id == T:
      for each (destination_cidr, nexthop) in R.routes:
        zone = resolve_static_route_zone(R, destination_cidr, nexthop)
        add (T, destination_cidr) → zone
```

Notes, in step order:

- **External networks are invisible to steps 2 and 3.** Subnets on networks
  with `router:external == true` are never emitted; their traffic falls
  through to step 1's catchall as `ZONE_EXTERNAL` — even when an operator
  attaches a VM to one directly.
- **Why `ZONE_SHARED` and not SAME/OTHER (step 3).** The LPM trie cannot
  resolve per-VM ownership inside a shared /24, so guessing SAME or OTHER
  systematically mis-bills one direction. The MAC-first hot path still
  classifies L2 traffic on shared networks exactly (intra-tenant L2 compares
  tenant IDs via `mac_tenant_map`); ZONE_SHARED labels only the
  L3-routed-fallback case, where the trie alone has insufficient
  information. Billing engines treat it as its own line item
  ([billing.md](./billing.md)). This rationale is the canonical statement;
  the same ordering governs `zone_for` in step 5's resolver.
- **OVN DHCP (step 4).** The `gateway_ip/32 → INFRA` rule catches OVN's DHCP
  `server_id` (= the subnet's `gateway_ip`), which is the source IP on
  synthesized DHCP responses. OVN's synthesized `server_mac` is NOT a Neutron
  port (verified empirically — it exists only in OVN's own DB), so
  `mac_tenant_map` misses on DHCP responses and the LPM lookup on the gateway
  IP carries the classification. The `network:distributed` filter contributes
  its **fixed IP only** — its MAC is never on the wire, so
  [`mac_tenant_map` population](./data-structures.md#kernel-side-bpf-maps)
  excludes it. OVN also has no `network:metadata` ports (the OVN metadata
  agent proxies 169.254.169.254 directly); absent values produce zero results
  harmlessly, so one filter set covers both architectures.
- **DHCP broadcast half.** The `gateway_ip/32 → INFRA` rule only catches the
  server's side of the exchange. The broadcast DISCOVER/REQUEST half has a
  group destination MAC and classifies `multicast` (never billed, decided by
  the kernel before any trie lookup); the unicast response half bills INFRA.
  Trivial volume; accepted.
- **IPv6 subnets and fixed IPs are skipped** — the kernel trie is keyed on
  u32 IPv4. Deferred: [contracts.md](./contracts.md#deferred-work) item 1.
- **No per-host MAC enumeration step exists.** Traditional Neutron with DVR
  needed a step that queried `dvr-mac-addresses` for each chassis's router
  MAC. OVN eliminates this: a logical router's interface has one MAC across
  all chassis, picked up by the standard port query in step 4. If a
  traditional-Neutron deployment is ever supported, that step returns —
  [contracts.md](./contracts.md#deferred-work) item 2.

## The static route resolver

CIDR alone is ambiguous — multiple tenants can register the same CIDR. The disambiguator is **the nexthop**, not the destination.

A static route may also be **multi-hop**: T1's router points to T2's router, which has its own extraroute pointing to T3, and so on until some router has the destination directly attached. The resolver must walk this chain — a single-hop check would falsely return `EXTERNAL` whenever the destination is more than one router away.

The algorithm is therefore an **iterative graph walk** with cycle detection and a hop limit.

```
function resolve_static_route_zone(R, destination_cidr, initial_nexthop):

  source_tenant = R.tenant_id
  current_router = R
  current_nexthop = initial_nexthop
  visited = { R.id }
  MAX_HOPS = 16

  for hop in 0 .. MAX_HOPS-1:

    Step A — Anchor:
      iface_subnet = pick current_router's interface subnet S where current_nexthop ∈ S.cidr
      if iface_subnet is None:
         return EXTERNAL    ← nexthop not on a directly-attached subnet (misconfig)

    Step B — Identify the device on the other end:
      nexthop_port = port in iface_subnet with fixed_ip == current_nexthop
      switch nexthop_port.device_owner:
        "network:router_interface" → next_router = router with id == device_id; proceed
        starts with "compute:"     →
          vm_owner = nexthop_port.tenant_id
          return zone_for(vm_owner, source_tenant, iface_subnet.network)
          ← VM appliance: classify by the appliance's Neutron-visible tenant.
          ← Nova writes compute:<az-name> — "nova" is only the default AZ —
            so the match is on the prefix, never the literal.
          ← The destination beyond the appliance is opaque; we stop tracing here.
        anything else              → return EXTERNAL    ← unknown device type

      if next_router.id in visited:
         log "routing cycle detected"; return EXTERNAL
      visited.add(next_router.id)

    Step C — Is destination directly attached to next_router?
      candidates = subnets on next_router whose cidr ⊇ destination_cidr,
                   excluding iface_subnet.network (the network we entered through)

      if exactly one candidate, OR multiple all-same-owner:
         owner = that subnet's network.tenant_id
         return zone_for(owner, source_tenant, that network)

      if multiple candidates with different owners:
         log "ambiguous owner"; return EXTERNAL   (or refuse to start in strict mode)

    Step D — If not directly attached, follow next_router's own extraroutes:
      Find next_router.routes entries whose destination ⊇ destination_cidr.
      Pick the longest-prefix match (LPM semantics).

      if a matching route exists:
         current_router  = next_router
         current_nexthop = matching_route.nexthop
         continue                                  ← next iteration: hop further

    Step E — Default route fallback:
      if next_router has external_gateway_info:
         return EXTERNAL                           ← traffic escapes via internet
      else:
         return EXTERNAL                           ← unreachable per Neutron; misconfig

  # Loop fell through without resolving — chain too long.
  log "MAX_HOPS exceeded"; return EXTERNAL


function zone_for(owner_tenant, source_tenant, network):
  if network is router:external == true:  return EXTERNAL
  if network.shared == true:               return SHARED   ← see step 3 above
  if owner_tenant == source_tenant:        return SAME_TENANT
  return OTHER_TENANT
```

The `shared` check sits **above** the owner check so that a shared network owned by the source tenant returns SHARED, not SAME — the same honest-label rule as step 3.

**Cycle detection.** A misconfigured deployment can have routing loops (R2 forwards to R3, R3 forwards back to R2). The `visited` set bounds the walk to each router at most once and bails to `EXTERNAL` on detection. Without this, the resolver would infinite-loop at cold-start.

**Hop limit.** `MAX_HOPS = 16` (`maxStaticRouteHops`, `internal/neutron/schema.go`) is generous — real OpenStack deployments rarely exceed 3–4 hops. If hit, it's almost certainly a configuration issue worth surfacing.

**Performance.** Each iteration is O(1) hashmap lookups against the cached Neutron snapshot. A typical resolution completes in microseconds. Cold-start runtime is dominated by API fetch latency, not the trace.

**VM-appliance nexthop.** When a nexthop resolves to a `compute:<az>` port (a VM acting as a software router, NAT box, or VPN gateway — Nova writes `compute:<az-name>` as the device_owner, `compute:nova` being just the default availability zone), the trace stops there — Neutron has no visibility into what the appliance does with the traffic. The zone for the destination CIDR is determined by the appliance's own Neutron tenant using `zone_for`, giving correct attribution for the immediate hop. However, when the appliance forwards traffic onward, that egress is independently counted at the appliance's own tap — the same bytes appear in billing twice, once at the originating VM's tap and once at the appliance's tap. See [edge-cases.md](./edge-cases.md) and [Scenario L](./scenarios.md).

Why CIDR alone is insufficient — and why we considered and rejected the simpler approach — is detailed in [ADR 0009](../adr/0009-nexthop-trace-over-cidr-only-lookup.md).

**Fallback observability.** The resolver has six distinct EXTERNAL-fallback exits; three warn-log (cycle, MAX_HOPS, ambiguity), the rest return silently. A per-reason fallback counter is deferred pending live-cluster validation — [contracts.md](./contracts.md#deferred-work) item 4.

## Worked example — single hop

```
DEPLOYMENT
  T1=1001 (frontend), T2=1002 (analytics), admin=9999

  Networks:
    net-T1   (T1)      10.0.1.0/24, 10.0.2.0/24
    net-T2   (T2)      10.1.1.0/24, 10.50.0.0/16
    net-shr  (admin)   192.168.100.0/24    [shared=true]
    net-pub  (admin)   203.0.113.0/24      [external]

  Routers:
    router-T1 (T1):
       interfaces  10.0.1.1, 10.0.2.1, 192.168.100.10
       ext gateway → net-pub
       extraroutes:
         dest 10.50.0.0/16    via 192.168.100.20
         dest 172.16.99.0/24  via 10.0.1.50

    router-T2 (T2):
       interfaces  10.1.1.1, 10.50.0.1, 192.168.100.20
       ext gateway → net-pub
```

### Global rows (sentinel `tenant_id=0`, emitted once)

| Step | Trie entry | Why |
|---|---|---|
| 1 | `(0, 0.0.0.0/0) → EXTERNAL` | catchall |
| 3 | `(0, 192.168.100.0/24) → SHARED` | net-shr is shared |
| 4 | `(0, 10.0.1.1/32) → INFRA` … one per router-interface / gateway IP (10.0.2.1, 192.168.100.10, 10.1.1.1, 10.50.0.1, 192.168.100.20) | router interfaces + subnet gateways |
| 4 | `(0, 169.254.169.254/32) → INFRA` | Nova metadata |

net-pub emits nothing — external networks fall to the catchall.

### Per-tenant rows

| Tenant | Step | Resolution | Trie entry |
|---|---|---|---|
| T1 | 2 | owned | `(T1, 10.0.1.0/24) → SAME` |
| T1 | 2 | owned | `(T1, 10.0.2.0/24) → SAME` |
| T1 | 5 | extraroute `10.50.0.0/16` via `192.168.100.20`: hop 0 → nexthop is router-T2's interface; Step C finds `10.50.0.0/16` directly attached → owner T2 | `(T1, 10.50.0.0/16) → OTHER` |
| T1 | 5 | extraroute `172.16.99.0/24` via `10.0.1.50`: nexthop port is `compute:nova`, `tenant_id=T1` → `zone_for(T1, T1, net-T1)` | `(T1, 172.16.99.0/24) → SAME` |
| T2 | 2 | owned | `(T2, 10.1.1.0/24) → SAME` |
| T2 | 2 | owned | `(T2, 10.50.0.0/16) → SAME` |

Note `10.50.0.0/16` appears twice with opposite zones — T1's view says OTHER,
T2's says SAME. That coexistence is exactly why the key is
`(tenant_id, ip)`. And the lookup composes with the sentinel: a T1 VM sending
to `8.8.8.8` misses every `(T1, …)` row, falls back to `(0, 8.8.8.8)`, and hits
the catchall → EXTERNAL. The INFRA /32 rows earn their keep on MAC-miss
traffic: an OVN-synthesized DHCP response arrives from a `server_mac` that is
not any Neutron port, so the MAC path misses and the LPM lookup on its source
IP (`10.0.1.1`, the gateway) classifies it INFRA — note the /32 INFRA row
beats the /24 SHARED row on the transit networks too, because longest prefix
wins within the sentinel rows.

## Worked example — multi-hop chain

A more demanding case: 5 routers in series, ending in a different tenant. This is what verifies the iterative trace works correctly.

```
DEPLOYMENT
  Tenants: T1=1001, T2=1002, T3=1003, T4=1004, T5=1005

  Routers chained via four shared transit networks:

    transit-A  10.10.1.0/24   shared=true
    transit-B  10.10.2.0/24   shared=true
    transit-C  10.10.3.0/24   shared=true
    transit-D  10.10.4.0/24   shared=true

  Routers (each owned by its tenant):
    R1 (T1):   interfaces in net-T1, transit-A
       extraroute:  dest 10.99.0.0/16  via 10.10.1.20
    R2 (T2):   interfaces in net-T2, transit-A, transit-B
       extraroute:  dest 10.99.0.0/16  via 10.10.2.30
    R3 (T3):   interfaces in net-T3, transit-B, transit-C
       extraroute:  dest 10.99.0.0/16  via 10.10.3.40
    R4 (T4):   interfaces in net-T4, transit-C, transit-D
       extraroute:  dest 10.99.0.0/16  via 10.10.4.50
    R5 (T5):   interfaces in net-T5, transit-D
       net-T5 owns 10.99.0.0/16  ← FINAL DESTINATION (directly attached to R5)

  Nexthop addresses on each transit:
    10.10.1.20  = R2's interface in transit-A
    10.10.2.30  = R3's interface in transit-B
    10.10.3.40  = R4's interface in transit-C
    10.10.4.50  = R5's interface in transit-D
```

### Trace for T1's extraroute `dest=10.99.0.0/16 via 10.10.1.20`

| Hop | Current router | Nexthop | Step A — anchor | Step B — peer | Step C — directly attached? | Step D — extraroute? | Action |
|---|---|---|---|---|---|---|---|
| 0 | R1 | 10.10.1.20 | transit-A | R2 (router_interface) | no `10.99.0.0/16` on R2 | LPM hit on R2: `10.99.0.0/16 via 10.10.2.30` | continue → R2 |
| 1 | R2 | 10.10.2.30 | transit-B | R3 | no | LPM hit on R3: via 10.10.3.40 | continue → R3 |
| 2 | R3 | 10.10.3.40 | transit-C | R4 | no | LPM hit on R4: via 10.10.4.50 | continue → R4 |
| 3 | R4 | 10.10.4.50 | transit-D | R5 | **yes**: `10.99.0.0/16` directly on net-T5 | — | **resolve** |

`zone_for(owner=T5, source=T1, network=net-T5)`:
- net-T5 is not external, not shared; T5 ≠ T1 → `OTHER_TENANT`

**Trie entry for T1:** `(T1, 10.99.0.0/16) → OTHER_TENANT` ✓

The chain crosses four transit networks and four router hops, ending in a different tenant five tenants away from the source. The trace correctly identifies T5 as the owner and produces `OTHER_TENANT`. (The transit networks themselves emit one global SHARED row each via step 3.)

### What if T5 didn't exist? (cycle / unreachable)

If R4's extraroute pointed back to R2 instead of forward to R5, the `visited` set catches the cycle at hop 4: `R2.id ∈ visited` → return `EXTERNAL`, log a warning. No infinite loop.

If R4 had no route for `10.99.0.0/16` and no external gateway, Step E returns `EXTERNAL`. Operator misconfig — the route is unreachable per Neutron's view.

If the chain genuinely is longer than `MAX_HOPS = 16` (unrealistic in practice), the loop bails and returns `EXTERNAL` with a warning. Worth logging but extremely rare.

## Ambiguity after scoping

If, after Step C, the peer router has connections to two networks both carrying `10.50.0.0/16` with different owners, we have a genuine ambiguity. Three policies:

| Policy | Behavior |
|---|---|
| **Safe-billing** | Fallback `ZONE_EXTERNAL` and log loudly |
| **Pessimistic** | Fallback `ZONE_OTHER_TENANT` (definitely cross-tenant) |
| **Strict** | Refuse to start; surface the config error |

The implementation ships safe-billing (fallback EXTERNAL, warn log, and the
anomaly surfaces on `lachesis_neutron_anomalies{class="ambiguity"}` with
drill-down at `/debug/anomalies`). For production billing engines, **strict is
the recommended posture** — better to refuse than to bill wrong.

## Incremental updates

Live metadata updates are driven by the Kafka consumer (`internal/kafka`) and the periodic reconcile (`internal/reconcile`). The consumer never applies changes itself: it decodes oslo notifications from `notifications.info` and, on each committed (`*.end`) Neutron change, kicks the reconciler. The reconciler is the single applier — a 5-minute timer and the Kafka kicks feed the same goroutine — so it runs one full Neutron snapshot fetch, diffs it against the last committed state, and pushes only the delta. The kick path and the periodic safety net therefore execute identical apply logic and never overlap. (The kick carries no payload; routing every change through one re-sync keeps a single apply path and guarantees the post-event trie matches a cold-start at the same instant, at the cost of one Neutron `Sync` per debounced burst — the same operation the periodic reconcile already runs.)

The trie delta is applied by `kernelwriter.ApplyTrieDelta`. The BPF LPM trie supports per-entry insert and delete, but **not** transactional multi-entry batches. For changes that touch multiple entries (e.g., a `router.routes` update that affects N CIDR mappings), strict ordering is required:

```
For a change set that REPLACES entries:
  1. Compute the diff:   new_entries[], obsolete_entries[]
  2. Insert / overwrite all new_entries[]   (LPM allows upsert at same key)
  3. Delete obsolete_entries[]              (only after all inserts complete)
```

`ApplyTrieDelta` implements exactly this: it skips unchanged rows, upserts added/changed rows, and — only if every upsert succeeded — deletes the obsolete ones (an upsert failure keeps the stale rows, harmless under LPM longest-match, and the next pass retries). The mac_tenant_map side is reconciled in the same pass: new ports are learned (userspace→kernel), and deleted ports are MarkDeleted into the 60s [lingering ghost](./data-structures.md#lingering-ghost) rather than removed outright.

**Why this order matters.** If we deleted first, there would be a window (microseconds, but real on a busy system) where the entry doesn't exist; packets matching that CIDR would fall through to the next-longest match — typically the sentinel catchall `(0, 0.0.0.0/0) → EXTERNAL`. Those packets would then be **permanently miskeyed in the kernel `flow_key`** because `dst_zone` is baked into the key — the entry never reclassifies even after the trie is fixed. Insert-first guarantees at least one valid entry exists at every moment.

**Atomicity guarantee.** LPM matches are deterministic per-packet — the kernel walks the trie and returns whichever stored entry has the longest matching prefix. During the insert phase, both old and new entries may briefly coexist; LPM's longest-match semantics resolve them deterministically. After the delete phase, only the new state remains. No racy "neither valid" state.

**For tenant-cross-cutting changes** (e.g., a network's `shared` flag flips, affecting how every tenant sees that subnet): batch all the inserts before any delete. The transient state is "both old and new visible" which under LPM longest-match is safe — every flow is classified by whichever prefix is more specific.

**Failure mode if violated.** If an implementation does delete-then-insert (the naive order), every route change creates a small burst of `ZONE_MISS` or wrongly-zoned entries that persist until those flows expire from `telemetry_map`. Visible as a brief blip in zone distribution after each router config change.

---

Next: [octavia.md](./octavia.md) →
