# Concept Primer & Glossary

A senior engineer can skim this once and proceed; the architecture chapters
link here when terms first appear. This is background reference — it sits
outside the reading sequence.

## eBPF in 60 seconds

eBPF (extended Berkeley Packet Filter) lets you attach small programs to specific kernel hook points. The programs run in a sandboxed virtual machine inside the kernel — no kernel modules, no recompilation, no reboots. The kernel verifier statically rejects programs that could crash, loop, or read invalid memory.

For our use case, eBPF gives us three things:

1. **Per-packet hooks** at the network stack — we can run code on every packet in/out of an interface, in the kernel, at line rate.
2. **Maps** — kernel data structures (hash, array, LPM trie, etc.) that BPF programs and userspace can share.
3. **Helper functions** — kernel-provided functions BPF programs can call, including `bpf_map_lookup_elem`, `bpf_skb_pull_data`, `bpf_ktime_get_ns`, and (critically for us) `bpf_skb_ct_lookup`.

We use the `cilium/ebpf` Go library for loading and managing programs. The C source is compiled with `clang -target bpf` and embedded into the Go binary via `bpf2go`.

External: [eBPF.io overview](https://ebpf.io/what-is-ebpf/), [Cilium eBPF docs](https://docs.cilium.io/en/stable/bpf/).

## TC clsact qdisc

Linux's traffic control (TC) layer hooks into the kernel network stack at queueing-discipline (qdisc) boundaries. Most qdiscs only see one direction, but `clsact` is special: it provides **both** an ingress and an egress hook on the same interface.

```
                  ┌─────────────┐
   from VM ──────▶│ clsact      │──────▶ to OVS
                  │ ingress hook│
                  ├─────────────┤
   to VM   ◀──────│ egress hook │◀────── from OVS
                  └─────────────┘
                       (tap)
```

We attach our BPF programs to both hooks:

- `tc_telemetry_in` on ingress (VM is sending — direction=0)
- `tc_telemetry_out` on egress (VM is receiving — direction=1)

`clsact` is added to an interface as a `replace` operation (idempotent). Filters under it reference our BPF programs by FD; deleting the filter removes the program reference.

Note: in TC's terminology, "ingress" and "egress" are from the *interface's* perspective. For a tap interface, ingress means "data flowing INTO the host stack from the VM" — i.e., the VM is the sender. We rename in our code to "VM sending" / "VM receiving" because that's clearer (and the metric labels translate further to `tx`/`rx` — see [metrics.md](./metrics.md)).

## BTF (BPF Type Format)

BTF is a compact metadata format that describes kernel data structures (struct layouts, types). The kernel ships with `/sys/kernel/btf/vmlinux`, which describes every type in the running kernel.

We use BTF for **CO-RE (Compile Once, Run Everywhere)** — our BPF programs reference kernel structs (like `struct __sk_buff`, `struct iphdr`) and are compiled once. The BPF loader patches the program's struct field accesses at load time using BTF, so the same binary runs on different kernels with different struct layouts.

We generate a flattened `vmlinux.h` from BTF and include it in our BPF C code. One gotcha: macros like `TC_ACT_OK` are not in BTF (they're preprocessor `#define`s), so we redefine them in our C code.

External: [Andrii Nakryiko's BTF intro](https://nakryiko.com/posts/btf-dedup/).

## PERCPU_HASH

`BPF_MAP_TYPE_PERCPU_HASH` is a hash map where each entry has *N* values internally — one per CPU. When CPU 7 does `bpf_map_lookup_elem` and gets a non-NULL pointer, it's pointing at CPU 7's slot specifically. CPU 8 can update its own slot in parallel without contention.

```
            CPU 0    CPU 1    CPU 2    ...   CPU 31
         ┌────────┬────────┬────────┬─────┬────────┐
key A    │ 100 B  │  50 B  │ 200 B  │ ... │  10 B  │  ← logical sum: 360 B
         ├────────┼────────┼────────┼─────┼────────┤
key B    │  20 B  │   0 B  │   0 B  │ ... │  80 B  │  ← logical sum: 100 B
         └────────┴────────┴────────┴─────┴────────┘
```

**Why this matters for us.** A regular hash with `__sync_fetch_and_add` works, but at 10 Gbps × 32 cores, the cache line bouncing on the atomic counter caps throughput well below line rate. PERCPU_HASH eliminates the contention; userspace just sums across CPUs at scrape time.

**Subtlety: first-packet TOCTOU.** When a flow doesn't exist yet, the BPF program does `lookup → null → update_elem(BPF_ANY, init)`. Two CPUs racing on the *first packet* of a new flow can both see null and both call update_elem — one's `BPF_ANY` overwrites the other's value. We lose at most 1 packet per new flow per race. Subsequent packets (the >99.999% case) are race-free because each CPU updates its own slot.

External: [BPF maps documentation](https://docs.kernel.org/bpf/maps.html).

## LPM Trie

`BPF_MAP_TYPE_LPM_TRIE` is a longest-prefix-match data structure. You insert entries with `(prefixlen, data)` keys. Lookups specify the full data and the trie returns the value of the longest stored prefix that matches.

```
Stored entries:                      Lookup with key 10.50.0.5/32:
  10.0.0.0/8       → A                 walks trie
  10.50.0.0/16     → B                 longest match: 10.50.0.0/16
  10.50.42.0/24    → C                 returns: B
  0.0.0.0/0        → default
```

We use it because zone classification fundamentally is a "longest-prefix-match" question: a destination IP might match a host-specific entry (`/32`), a subnet (`/24`), a tenant range (`/16`), or fall to the catchall (`/0`). Whichever is most specific wins.

**Our key has `(tenant_id ++ ip)`.** The `prefixlen` field in the BPF LPM key counts bits in the data after the prefixlen field itself. Since we always want exact `tenant_id` match, every stored entry has `prefixlen ≥ 32`. The remaining `prefixlen - 32` bits are the IP prefix.

```
{prefixlen=32, tenant_id=1001, ip=0}              ← "tenant 1001, anything"   /0
{prefixlen=56, tenant_id=1001, ip=10.0.1.0}       ← "tenant 1001, 10.0.1.0/24"
{prefixlen=64, tenant_id=1001, ip=10.0.1.5}       ← "tenant 1001, 10.0.1.5/32"
```

Lookup keys always have `prefixlen=64` (full match requested); the trie walks itself. Global rows use the sentinel `tenant_id=0` and are found by a second lookup — see [packet-classification.md](./packet-classification.md).

## `bpf_skb_ct_lookup` and conntrack

The Linux kernel maintains a connection tracking table (conntrack) for stateful firewalling and NAT. Each entry is keyed by 5-tuple and stores the original tuple (pre-NAT) plus the reply tuple (post-NAT).

```
Original tuple:    src=1.2.3.4:50000   dst=203.0.113.5:443      (client → floating IP)
Reply tuple:       src=10.0.1.5:443    dst=1.2.3.4:50000        (after DNAT to backend)
```

`bpf_skb_ct_lookup` is a TC-only BPF helper that takes the current packet and queries conntrack, returning a pointer to the matching entry. From there we can read both tuples.

**Why the Octavia design needs it (optional refinement).** Used at the Amphora's tap for Segment 1 zone classification — recovering the original client_ip lets us classify the zone as EXTERNAL/OTHER/SAME based on the real client. Attribution to the LB owner does NOT depend on this lookup (it comes from the Amphora MAC flag in `mac_tenant_map`). See [octavia.md](./octavia.md) for the full algorithm and why `bpf_skb_ct_lookup` is NOT called at the backend's tap.

**Why it's TC-only.** XDP runs before conntrack (at the very earliest stage of packet ingress), so the conntrack entry might not even be matched yet. TC runs *after* `nf_conntrack` has done its lookup, which is why the helper is only available there.

External: [conntrack architecture](https://people.netfilter.org/pablo/docs/login.pdf), [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).

## Netlink

Netlink is the Linux kernel's primary IPC interface for managing the network stack. The `vishvananda/netlink` Go library wraps it for our use.

We use netlink for three things:

1. **Creating qdiscs** — `netlink.QdiscReplace` adds/replaces the `clsact` qdisc on a tap interface.
2. **Attaching/detaching BPF filters** — `netlink.FilterReplace` and `netlink.FilterDel`.
3. **Subscribing to interface lifecycle events** — `netlink.Subscribe(unix.NETLINK_ROUTE)` gives us `RTM_NEWLINK` and `RTM_DELLINK` notifications. We watch these to attach our BPF program to newly-created taps and clean up registry entries when taps disappear.

External: [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).

## OpenStack networking primer

For engineers without OpenStack background, here's the minimum needed.

**Neutron** is OpenStack's networking service. It manages virtual networks, subnets, ports, routers, floating IPs, and security groups — all as API objects.

**OVS (Open vSwitch)** is the kernel-level virtual switch that implements Neutron's networks. OVS has multiple bridges:

- `br-int` — the integration bridge; all VM tap interfaces attach here.
- `br-tun` — the tunnel bridge; encapsulates traffic for cross-host transport.
- `br-ex` — the external bridge; connects to physical infrastructure.

**tap interface (tapXXX)** — a virtual network interface created per VM port. The VM's vNIC is connected to the tap on one end; the other end is plugged into OVS br-int. Our TC hooks attach here.

**VXLAN / Geneve** — overlay tunneling protocols that wrap an Ethernet frame in UDP/IP for transport between hypervisors, each tenant network getting a unique tunnel ID (VXLAN's 24-bit **VNI**, or Geneve's VNI plus extensible options). OVN ML2 — what CubeCOS runs — tunnels with **Geneve**; VXLAN is the traditional-Neutron default. The distinction is immaterial to this design: at our tap layer packets are pre-encapsulation, so we never see either tunnel header.

**Floating IP** — a public IP address allocated to a tenant. When attached to a VM port, the platform performs DNAT (destination NAT) for inbound traffic. The VM still uses its private IP internally; the floating IP is invisible to the VM.

**DVR (Distributed Virtual Routing)** — a *traditional Neutron* mode where each compute node runs its own router namespace. With DVR, intra-tenant E-W routing happens locally; without it, all routing goes through a central network node. Each compute node's DVR router has its own MAC, even for the same logical Neutron router — hence the need for `dvr-mac-addresses` enumeration. **OVN deployments do not use DVR** (see below); they distribute routing via OVS flow rules instead, with a single MAC per logical router across all chassis. CubeCOS targets OVN; DVR is mentioned for context only.

**Address scope** — Neutron's mechanism for allowing cross-tenant routing while preventing CIDR overlap. Subnets in the same address scope must have non-overlapping CIDRs.

**OVN (Open Virtual Network).** CubeCOS deployments use Neutron's **OVN ML2 plugin** instead of the traditional OVS-agent + L3-agent stack. OVN replaces several traditional components:

- The `neutron-openvswitch-agent` on each compute node is replaced by `ovn-controller`, which reads logical flow specifications from the OVN Southbound DB and programs OVS flow tables directly.
- The `neutron-l3-agent` is gone; **logical routers are implemented entirely as OVS flow rules** distributed across all chassis. There are no `qrouter-XXX` namespaces.
- The `neutron-dhcp-agent` is replaced by OVS flow rules that synthesize DHCP responses. Neutron records the DHCP "ports" with `device_owner=network:distributed` and a port status of `DOWN` (because there's no real interface — the MAC and IP exist only as flow-rule parameters).
- Each compute node ("chassis") runs `ovn-controller` plus a `neutron-ovn-metadata-agent` for VM metadata service.

For our cold-start ([trie-construction.md](./trie-construction.md)), this means **no `dvr-mac-addresses` extension and no per-host MAC enumeration step are needed**: logical routers have a single MAC across all chassis, and that MAC is visible via the standard Neutron port API.

The traditional Neutron architecture is *not* supported by this design; see [deferred item 2](./contracts.md#deferred-work) for the retrofit path if a future deployment requires it.

External: [Neutron API reference](https://docs.openstack.org/api-ref/network/v2/), [OVN architecture](https://www.ovn.org/support/dist-docs/ovn-architecture.7.html).

## Octavia and Amphora VMs

**Octavia** is OpenStack's load-balancer-as-a-service. When a tenant creates an LB, Octavia provisions an **Amphora** — a dedicated VM running HAProxy — in a special "service" project (typically the admin project). The Amphora sits between external clients and the tenant's backend VMs.

```
external client
    │
    ▼ (port 443 on floating IP)
floating IP   ←── DNAT ──→ Amphora VM (in admin project)
    │
    ▼ HAProxy forwards
Amphora ── NAT'd ──→ backend VM (in tenant project)
```

The naive view: bytes are charged to whoever owns the Amphora (admin). The correct view: bytes are charged to the LB's owning tenant (because they configured the LB and benefit from the traffic). The [Octavia design](./octavia.md) tags Amphora MACs at cold-start with `IsAmphora=true` + `LBOwnerTenant` so traffic touching an Amphora attributes to the LB owner regardless of which tap captures it. HAProxy on the Amphora creates two distinct TCP connections (client↔Amphora, Amphora↔backend); both segments are captured and billed to the same LB owner.

External: [Octavia architecture](https://docs.openstack.org/octavia/latest/reference/introduction.html).

## DPDK / SR-IOV / Smart NIC

These are alternative datapaths that bypass the standard kernel network stack — and therefore bypass our eBPF TC hooks.

**DPDK (Data Plane Development Kit)** — userspace networking. The NIC is unbound from the kernel driver and bound to a userspace driver (`vfio-pci`/`uio`). Packets are polled from the NIC into userspace ring buffers; OVS-DPDK handles them entirely in userspace. The kernel network stack is never invoked. TC hooks don't fire.

**SR-IOV (Single Root I/O Virtualization)** — hardware-level NIC virtualization. The physical NIC exposes Virtual Functions (VFs); each VF is assigned to a VM with PCI passthrough. The VM talks directly to the NIC hardware; no virtual switch is involved. No tap interface exists at all.

**Smart NIC offload (NVIDIA BlueField, Intel IPU, AWS Nitro, Mellanox ASAP²)** — the datapath is offloaded to NIC hardware. The hypervisor provisions flows; the NIC enforces them. Some smart NICs run their own embedded OS; some let you load eBPF directly to NIC hardware.

For our design: all three are out-of-scope. They're deployment choices that require alternative telemetry (NIC-level counters, sFlow on physical infrastructure, smart-NIC eBPF). We assume the standard kernel-OVS datapath. See [edge-cases.md](./edge-cases.md) Tier 1.

## Write-Ahead Log

A WAL is a durable record of state-changing operations, written before the operation is acknowledged. Databases use WALs for crash recovery; we use a simplified version.

Our WAL is a **single JSON snapshot** of `GlobalState` at a point in time — not an append-only log of operations. The trade-off: simpler implementation, but up to 60 seconds of state can be lost if we crash between flushes.

**Atomic write pattern**: write to `path.tmp`, fsync, `os.Rename` to `path`, then fsync the parent directory. The rename is atomic on POSIX filesystems, so readers either see the old file or the new file — never a partial write. The directory fsync makes the rename itself durable: on ext4/XFS a rename lives in the directory's metadata, and without journaling it a power loss can resurrect the pre-rename view even after the flush reported success.

For a billing system, "≤60s data loss on hard reboot" is acceptable. For tighter guarantees we'd need an append-only log with shorter checkpoints, at higher I/O cost. The simpler scheme also makes the file human-readable for debugging. Full schema and flush/boot procedures: [data-structures.md](./data-structures.md#userspace-structures).

## Glossary

| Term | One-line definition |
|---|---|
| **Amphora** | The VM that implements an Octavia load balancer (runs HAProxy). |
| **ARP** | Address Resolution Protocol — how a host learns the MAC for a given IP. |
| **BPF / eBPF** | extended Berkeley Packet Filter — kernel-side sandboxed VMs. |
| **BTF** | BPF Type Format — kernel struct metadata, enables CO-RE. |
| **CIDR** | Classless Inter-Domain Routing notation, e.g. `10.0.1.0/24`. |
| **clsact** | A Linux TC qdisc that exposes both ingress and egress hooks. |
| **CO-RE** | Compile Once, Run Everywhere — BTF-driven BPF binary portability. |
| **conntrack** | Kernel connection-tracking table for stateful firewalling and NAT. |
| **DNAT** | Destination NAT — rewriting destination IP/port. |
| **DPDK** | Data Plane Development Kit — userspace networking, bypasses kernel. |
| **DVR** | Distributed Virtual Routing — *traditional Neutron mode only* (per-host router namespaces). Not used by OVN; CubeCOS targets OVN. |
| **floating IP** | A public IP that can be attached to a VM port via DNAT. |
| **GSO/TSO** | Generic/TCP Segmentation Offload — kernel hands NIC a single large packet. |
| **HAProxy** | The load balancer software running inside an Amphora. |
| **LPM** | Longest Prefix Match. |
| **MAC** | Media Access Control address — 48-bit hardware-level identifier. |
| **Netlink** | Linux's IPC for managing the network stack. |
| **Neutron** | OpenStack's networking service. |
| **Nova** | OpenStack's compute service (manages VMs). |
| **Octavia** | OpenStack's load balancer service. |
| **OVS** | Open vSwitch — virtual switch implementing Neutron's networks. |
| **PERCPU** | A BPF map type with one slot per CPU, eliminates atomic contention. |
| **port (Neutron)** | A logical network endpoint with a MAC, IP, and tenant — backs each tap. |
| **qdisc** | Queueing discipline — Linux TC's primary abstraction. |
| **sFlow** | Sampling-based network telemetry protocol. |
| **SR-IOV** | Single Root I/O Virtualization — direct NIC passthrough. |
| **tap interface** | Virtual NIC that carries a VM's traffic to OVS. |
| **TC** | Traffic Control — Linux's kernel layer for shaping/classifying packets. |
| **tenant / project** | An isolation boundary in OpenStack (Keystone term: project). |
| **tuple (5-tuple)** | (src_ip, dst_ip, src_port, dst_port, proto). |
| **VM** | Virtual Machine. |
| **vNIC** | The virtual NIC inside a guest VM. |
| **VNI** | VXLAN Network Identifier — 24-bit tenant network ID. |
| **VXLAN** | UDP-encapsulating overlay protocol for Layer 2 tunneling. |
| **WAL** | Write-Ahead Log — durable record of state for crash recovery. |
| **XDP** | eXpress Data Path — eBPF hook at the NIC driver, fastest but limited. |
| **zone** | Our classification of a flow's remote endpoint: `external`, `same_tenant`, `other_tenant`, `infra`, `shared`, `multicast`, plus `miss` as the unclassified state. See [packet-classification.md](./packet-classification.md). |
