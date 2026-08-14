// SPDX-License-Identifier: GPL-2.0
/*
 * Per-VM TC classifier. Counts bytes and packets per
 * (src_mac, dst_mac, eth_proto, direction, dst_zone) tuple and classifies
 * the destination zone via a hybrid MAC-first / LPM-fallback lookup.
 *
 * Attached at each VM's tap interface (clsact ingress and egress). The
 * userspace agent populates mac_tenant_map and subnet_zone_trie; this
 * program only reads them.
 *
 * Design: docs/architecture/data-structures.md (data structures) and §4 (classification).
 */

/*
 * UAPI headers, not vmlinux.h. This program touches no kernel-internal type
 * and takes no CO-RE relocation: __sk_buff, ethhdr and iphdr are all stable
 * UAPI, and the only skb fields read (data, data_end, len) are rewritten by
 * the verifier rather than relocated against BTF. Depending on vmlinux.h
 * would mean deriving a multi-megabyte header from some kernel's BTF at
 * build time — which forces a privileged container and makes the artifact
 * depend on whichever kernel the builder happened to run. UAPI keeps the
 * build hermetic and reproducible off any checkout.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK         0
#define ETH_P_IP          0x0800
#define ETH_P_IPV6        0x86DD

/*
 * Zone codes stored in flow_key.dst_zone. Values are stable across releases
 * because they are persisted to the WAL. Mirror the Zone* constants in
 * internal/bpf/abi.go.
 *
 * __attribute__((packed)) forces 1-byte width so flow_key stays 16 bytes.
 */
enum zone_code {
	ZONE_EXTERNAL     = 0,
	ZONE_SAME_TENANT  = 1,
	ZONE_OTHER_TENANT = 2,
	ZONE_INFRA        = 3,
	ZONE_MISS         = 4,
	ZONE_SHARED       = 5,	/* destination is on a shared Neutron network;
				 * billing is structurally ambiguous between
				 * SAME_TENANT and OTHER_TENANT because /24 LPM
				 * cannot resolve per-VM ownership inside the
				 * shared CIDR. Emitted by trie Step 3.
				 */
	ZONE_MULTICAST    = 6,	/* destination MAC has the multicast/broadcast
				 * bit set (platform-L2 chatter: mDNS, SSDP,
				 * DHCP broadcast, ...). Never resolves to a
				 * tenant MAC, so it is classified here rather
				 * than left to fall into MISS/EXTERNAL. Kept
				 * counted for transparency but never billed;
				 * excluded from the revenue-leak SLO.
				 */
} __attribute__((packed));

/*
 * TC hook direction relative to the VM, stored in flow_key.direction.
 * Mirror the Direction* constants in internal/bpf/abi.go.
 */
enum tc_direction {
	TC_DIR_INGRESS = 0,	/* VM is sending */
	TC_DIR_EGRESS  = 1,	/* VM is receiving */
} __attribute__((packed));

/*
 * flow_key: 16-byte composite key for telemetry_map. Packed so the kernel's
 * byte-wise hash is stable (no uninitialized padding bytes).
 */
struct flow_key {
	__u8  src_mac[6];
	__u8  dst_mac[6];
	__u16 eth_proto;
	enum tc_direction direction;
	enum zone_code    dst_zone;
} __attribute__((packed));

struct flow_metrics {
	__u64 bytes;
	__u64 packets;
	__u64 last_seen_ns;
	/*
	 * created_ns stamps THIS entry's identity: written once, in the
	 * creation branch below, and never updated while the entry lives.
	 * Userspace differences the cumulative counters, which is only
	 * meaningful if the entry that produced `current` is the same one
	 * that produced its stored baseline — and the kernel owns that
	 * lifetime (pressure-relief eviction, the unresolved-buffer fold,
	 * the ghost sweep, an unpinned restart). Comparing this stamp is
	 * how userspace tells "the counter advanced" from "a different
	 * entry now occupies this key" without inferring it from the
	 * magnitudes, which fails whenever a re-created entry climbs back
	 * to its predecessor's value inside one scrape interval
	 * (docs/adr/0014-in-band-entry-identity-over-inferred-resets.md).
	 *
	 * PERCPU: only the creating CPU runs the else-branch, so peer CPUs
	 * hold 0 here. Userspace folds this field with MAX across slots
	 * (as it already does for last_seen_ns), which yields the creating
	 * CPU's stamp — and, after a delete zeroes every slot, the next
	 * creator's.
	 */
	__u64 created_ns;
};

/*
 * lpm_key: prefixlen covers bits in (tenant_id ++ ip).
 *   - Catchall entry:   prefixlen=32 → exact tenant_id, /0 ip wildcard.
 *   - Subnet /24 entry: prefixlen=56 → exact tenant_id + 24-bit ip prefix.
 */
struct lpm_key {
	__u32 prefixlen;
	__u32 tenant_id;
	__u32 ip;		/* IPv4 only */
};

/* PERCPU_HASH: each CPU writes to its own slot; no atomics on the hot path. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_metrics);
} telemetry_map SEC(".maps");

/*
 * subnet_zone_trie: (tenant_id, dst_ip) → zone code. Populated by the
 * userspace agent at startup and updated incrementally via the metadata
 * event stream.
 *
 * # Cardinality
 *
 * Trie dedup (sentinel tenant_id=0) emits the global rows —
 * catchall, SHARED, INFRA /32s, and the Nova metadata /32 —
 * exactly once with tenant_id=0; only SAME_TENANT subnets and
 * per-tenant extraroutes scale with tenant count. Per
 * docs/architecture/data-structures.md#kernel-side-bpf-maps cardinality is O(G + Σ O_t), where G is
 * the global-row count and O_t the per-tenant SAME_TENANT rows.
 *
 * # Sizing
 *
 * 16384 is the retained cap. Empirically a 37-tenant OVN-Yoga
 * single-host deployment drops from ~14252 entries (pre-dedup)
 * to well under 1000 (post-dedup); 16384 leaves an order of
 * magnitude of headroom for future per-tenant SAME_TENANT growth
 * (more owned subnets, more extraroutes) without a `task generate`
 * cycle. Headroom is cheap on an LPM_TRIE with BPF_F_NO_PREALLOC
 * — entries are allocated on demand, not pre-reserved.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_zone_trie SEC(".maps");

/*
 * mac_tenant_map: MAC → (amphora flag ++ tenant_id). The MAC is packed
 * into the low 48 bits of a u64 in big-endian order (see mac_to_u64).
 * Populated by the userspace agent from the platform's port metadata.
 *
 * Sizing: one entry per active Neutron port (compute:nova VMs plus
 * Amphora data ports). dev-cmp empirically observes ~17 compute:nova
 * ports today; a production OVN-Yoga deployment can reach a few
 * thousand. 8192 = 2× headroom over a 4000-port target in a
 * power-of-two.
 *
 * # Why the value is packed, not a second map
 *
 * The top bit marks an Octavia Amphora data port; the low 31 bits are the
 * interned tenant id. A sidecar amphora_meta map would cost an extra hash
 * lookup on every packet whose peer resolves — ~20-30ns against a measured
 * 82-110ns per-packet budget — to produce nothing but a zone label. Packing
 * costs one AND. Cilium packs flags into ipcache values for the same reason.
 *
 * 31 bits bounds the deployment at 2^31-1 tenants; the interner assigns
 * from 1 and a cluster reaches thousands. Userspace mirror and the writer
 * that sets the bit: internal/bpf.TenantAmphoraFlag / TenantIDMask.
 */
#define TENANT_AMPHORA_FLAG 0x80000000u
#define TENANT_ID_MASK      0x7fffffffu

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u32);
} mac_tenant_map SEC(".maps");

/*
 * amphora_key: (tenant_id, ip) identifying one address of an Amphora.
 *
 * Scoped by tenant because private CIDRs overlap freely across projects
 * — two tenants can each own 10.0.0.5, and a bare-IP set would let one
 * tenant's Amphora address silently reclassify the other's traffic.
 */
struct amphora_key {
	__u32 tenant_id;
	__u32 ip;		/* IPv4, network byte order (wire order) */
};

/*
 * amphora_base_ip: the set of Amphora BASE addresses — every fixed IP of
 * every Amphora data port. Presence means "this address is the Amphora
 * originating side", i.e. Segment 2.
 *
 * # What it separates
 *
 * Both Octavia segments cross the same Amphora MAC, so the MAC flag in
 * mac_tenant_map cannot tell them apart. The Amphora's own address can:
 *
 *   Segment 1  client <-> Amphora    Amphora side is the VIP
 *   Segment 2  Amphora <-> backend   Amphora side is the base IP
 *
 * HAProxy accepts Segment 1 on the VIP and originates Segment 2 from the
 * base address (verified on-wire). So a hit here means plumbing (INFRA)
 * and a miss means Segment 1, which must keep classifying by tenant —
 * an internal client's traffic to a load balancer is real, billable
 * same_tenant / other_tenant traffic (docs/architecture/octavia.md).
 *
 * # Why base addresses rather than VIPs
 *
 * Fail-safe direction. A missing entry here drops Segment 2 to
 * same_tenant, which is $0 either way; a missing VIP in the mirror-image
 * design would mark Segment 1 INFRA and stop billing it. The base set is
 * also directly derivable from the ports userspace already enumerates,
 * including the member-network ports Octavia plugs after the fact.
 *
 * Sizing: one entry per fixed IP of an Amphora data port — 1-2 per
 * Amphora on a normal topology, a few more when pool members span
 * subnets. 1024 covers hundreds of load balancers with headroom, at
 * 8 bytes of key per entry.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct amphora_key);
	__type(value, __u8);
} amphora_base_ip SEC(".maps");

/*
 * is_amphora_segment2 - does this flow's Amphora side use its base
 * address rather than the VIP?
 *
 * amp_tid must already be masked; amp_ip is the Amphora side's on-wire
 * address in network byte order.
 */
static __always_inline _Bool is_amphora_segment2(__u32 amp_tid, __be32 amp_ip)
{
	struct amphora_key k = { .tenant_id = amp_tid, .ip = amp_ip };
	return bpf_map_lookup_elem(&amphora_base_ip, &k) != NULL;
}

/*
 * Slot indices for telemetry_stats. Mirror the Stat* constants in
 * internal/bpf/schema.go. STAT_REASON_MAX doubles as the map's
 * max_entries, so adding a reason here without updating the Go-side
 * mirror fails bpf.ValidateMapSizes at boot instead of skewing slots.
 */
enum stat_reason {
	STAT_UPDATE_FAILURE    = 0,	/* telemetry_map insert rejected (map full); the flow's bytes are lost */
	STAT_SKIPPED_ETHERTYPE = 1,	/* non-IP frame passed through uncounted */
	STAT_REASON_MAX,
};

/*
 * telemetry_stats: cumulative counters for the failure/skip paths above,
 * drained into lachesis_bpf_update_failures_total by the userspace
 * scraper. PERCPU_ARRAY so an increment is a plain per-CPU store — no
 * atomics — and only the failure/skip paths touch it; the happy path
 * stays unchanged (Cilium pkg/maps metricsmap pattern).
 *
 * Sizing: exactly one slot per enum stat_reason value; capacity does
 * not scale with deployment size.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_REASON_MAX);
	__type(key, __u32);
	__type(value, __u64);
} telemetry_stats SEC(".maps");

/*
 * stat_inc - bump one telemetry_stats slot.
 *
 * The lookup cannot miss — reason is always a valid enum value and
 * ARRAY slots always exist — so the NULL check only satisfies the
 * verifier.
 */
static __always_inline void stat_inc(enum stat_reason reason)
{
	__u32 slot = reason;
	__u64 *count = bpf_map_lookup_elem(&telemetry_stats, &slot);
	if (count)
		*count += 1;	/* PERCPU slot: this CPU is the sole writer */
}

/*
 * mac_to_u64 - pack a 6-byte MAC into the low 48 bits of a u64 (big-endian).
 *
 * Open-coded as six shifts rather than a loop; matches the Go-side encoding
 * used by tests and the agent so cross-language map lookups agree.
 */
static __always_inline __u64 mac_to_u64(const __u8 mac[6])
{
	return ((__u64)mac[0] << 40) | ((__u64)mac[1] << 32) |
	       ((__u64)mac[2] << 24) | ((__u64)mac[3] << 16) |
	       ((__u64)mac[4] <<  8) |  (__u64)mac[5];
}

/*
 * lookup_zone - resolve the destination zone for a flow.
 *
 * Implements the hybrid MAC-first / LPM-fallback algorithm:
 *   1. vm_mac must be a known VM in mac_tenant_map, otherwise ZONE_MISS.
 *   2. Direct-L2 fast path: if peer_mac is also a known VM, compare
 *      tenants exactly. No trie consulted, no CIDR ambiguity.
 *   2a. Octavia: when either end carries the Amphora flag, that end's own
 *      address decides the segment. Base address -> Segment 2, the load
 *      balancer's internal plumbing, ZONE_INFRA. VIP -> Segment 1, which
 *      falls through and classifies by tenant like any other flow.
 *
 *      Checking both ends matters because the same Segment 2 transfer is
 *      seen at the Amphora's tap and the backend's tap; the both-sides
 *      emission pairs one tx with one rx series per transfer, and
 *      splitting that pair across two zones makes it unreconcilable
 *      (docs/architecture/billing.md).
 *
 *      Segment 1 must NOT be swallowed here. An external client's
 *      peer_mac is a router interface, absent from mac_tenant_map, so it
 *      never reaches this branch at all and lands EXTERNAL via the trie.
 *      An INTERNAL client does reach it — and is real billable
 *      same_tenant / other_tenant traffic, so only the base-address test
 *      keeps it out of INFRA (docs/architecture/octavia.md).
 *   3. Routed fallback: LPM trie keyed on (vm_tenant_id, remote_ip);
 *      hits SAME_TENANT rows and per-tenant extraroute rows.
 *   4. Sentinel fallback: if (3) misses, re-key with tenant_id=0
 *      and look up again. Trie-dedup writes global rows (catchall,
 *      SHARED, INFRA, metadata) once at tenant_id=0; the catchall
 *      guarantees this second lookup hits in steady state, so
 *      ZONE_MISS here means the trie hasn't been populated yet
 *      (cold-start race) or a bug, not a normal miss.
 *
 * Userspace contract: see internal/neutron.BuildTrie (per-tenant
 * vs TenantID="" emission rules) and docs/architecture/data-structures.md#kernel-side-bpf-maps.
 */
static __always_inline __u8 lookup_zone(const __u8 vm_mac[6],
					const __u8 peer_mac[6],
					__be32 local_ip_be,
					__be32 remote_ip_be)
{
	__u64 vm_key = mac_to_u64(vm_mac);
	__u32 *vm_val = bpf_map_lookup_elem(&mac_tenant_map, &vm_key);
	if (!vm_val)
		return ZONE_MISS;
	__u32 vm_tid = *vm_val & TENANT_ID_MASK;

	__u64 peer_key = mac_to_u64(peer_mac);
	__u32 *peer_val = bpf_map_lookup_elem(&mac_tenant_map, &peer_key);
	if (peer_val) {
		__u32 peer_tid = *peer_val & TENANT_ID_MASK;
		/* Test each Amphora end against its OWN address. Only the
		 * flagged side is probed: an unflagged peer's address is
		 * ordinary tenant space and could collide with some other
		 * project's Amphora base IP. */
		if ((*vm_val & TENANT_AMPHORA_FLAG) &&
		    is_amphora_segment2(vm_tid, local_ip_be))
			return ZONE_INFRA;
		if ((*peer_val & TENANT_AMPHORA_FLAG) &&
		    is_amphora_segment2(peer_tid, remote_ip_be))
			return ZONE_INFRA;
		return (peer_tid == vm_tid) ? ZONE_SAME_TENANT : ZONE_OTHER_TENANT;
	}

	struct lpm_key lk = {
		.prefixlen = 64,	/* request full match; trie picks the longest stored prefix */
		.tenant_id = vm_tid,
		/*
		 * Network byte order. The kernel LPM trie walks key data
		 * byte-by-byte, MSB-first within each byte; for CIDR
		 * matching to work the IPv4 address must lead with its
		 * MSB octet in memory. `remote_ip_be` is the wire bytes
		 * read directly from the IP header, so assigning here
		 * preserves wire order. Userspace agrees via
		 * internal/bpf.LpmKeyForPrefix (NativeEndian encode).
		 */
		.ip        = remote_ip_be,
	};
	__u8 *zone = bpf_map_lookup_elem(&subnet_zone_trie, &lk);
	if (zone)
		return *zone;

	/* Sentinel fallback. Same key, tenant_id rewritten to 0; the
	 * verifier is happy with a second lookup on the same stack-
	 * allocated struct. Catchall at 0.0.0.0/0 guarantees a hit
	 * in steady state. */
	lk.tenant_id = 0;
	zone = bpf_map_lookup_elem(&subnet_zone_trie, &lk);
	return zone ? *zone : ZONE_MISS;
}

/*
 * handle_packet - per-packet classification and counter update.
 *
 * Inlined into both tc_telemetry_in and tc_telemetry_out; the direction
 * argument is a per-program constant so the compiler can drop the
 * unreachable branches in each instance.
 */
static __always_inline int handle_packet(struct __sk_buff *skb,
					 enum tc_direction direction)
{
	/* Pull Ethernet + IPv4 headers into the linear region before reading. */
	if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)) < 0)
		return TC_ACT_OK;

	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	__u16 proto = bpf_ntohs(eth->h_proto);
	/* ARP / LLDP / non-IP: pass through uncounted, but keep the skip
	 * observable — a sustained rise flags a trunk/VLAN blind spot. */
	if (proto != ETH_P_IP && proto != ETH_P_IPV6) {
		stat_inc(STAT_SKIPPED_ETHERTYPE);
		return TC_ACT_OK;
	}

	struct flow_key key = {};
	__builtin_memcpy(key.src_mac, eth->h_source, 6);
	__builtin_memcpy(key.dst_mac, eth->h_dest, 6);
	key.eth_proto = proto;
	key.direction = direction;

	/*
	 * Multicast/broadcast destination: the low bit of the first octet
	 * is the IEEE 802 I/G bit. Frames addressed to a group MAC (IPv6
	 * mDNS 33:33:*, IPv4 SSDP/link-local 01:00:5e:*, DHCP broadcast
	 * ff:ff:*, ...) can never resolve to a tenant in mac_tenant_map, so
	 * classify them into the dedicated never-billed multicast zone
	 * rather than letting a received frame fall to MISS (numerator of
	 * the revenue-leak SLO) or a VM-sent frame fall through the trie to
	 * the EXTERNAL catchall. Checked on the destination MAC (already
	 * copied into key.dst_mac above), so it covers both received group
	 * traffic (egress hook) and VM-originated multicast tx (ingress
	 * hook), for both IPv4 and IPv6. Gated behind the ethertype check
	 * above so non-IP frames (ARP, ...) stay skipped-uncounted as
	 * before. See lachesis#150.
	 */
	if (key.dst_mac[0] & 0x01) {
		key.dst_zone = ZONE_MULTICAST;
	} else if (proto == ETH_P_IP) {
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end)
			return TC_ACT_OK;

		/*
		 * Directional swap: always classify against the VM's own MAC
		 * and the remote endpoint IP, regardless of which TC hook fired.
		 *
		 *   INGRESS (VM sending):   vm_mac = h_source, remote_ip = daddr
		 *   EGRESS  (VM receiving): vm_mac = h_dest,   remote_ip = saddr
		 *
		 * Without the swap, egress traffic looks up the VM's own
		 * address as the remote peer and produces a wrong classification.
		 *
		 * local_ip is the VM side's own address — the mirror of
		 * remote_ip under the same swap. Only the Octavia branch reads
		 * it, to tell an Amphora's VIP (Segment 1) from its base
		 * address (Segment 2).
		 */
		const _Bool ingress = (direction == TC_DIR_INGRESS);
		const __u8 *vm_mac    = ingress ? eth->h_source : eth->h_dest;
		const __u8 *peer_mac  = ingress ? eth->h_dest   : eth->h_source;
		__be32      remote_ip = ingress ? iph->daddr    : iph->saddr;
		__be32      local_ip  = ingress ? iph->saddr    : iph->daddr;

		key.dst_zone = lookup_zone(vm_mac, peer_mac, local_ip, remote_ip);
	} else {
		/* IPv6 zone resolution is not yet implemented; record as MISS. */
		key.dst_zone = ZONE_MISS;
	}

	__u64 pkt_len = skb->len;
	__u64 now     = bpf_ktime_get_ns();

	struct flow_metrics *val = bpf_map_lookup_elem(&telemetry_map, &key);
	if (val) {
		/* PERCPU slot: no atomic needed; this CPU is the sole writer. */
		val->bytes       += pkt_len;
		val->packets     += 1;
		val->last_seen_ns = now;
	} else {
		struct flow_metrics init = {
			.bytes        = pkt_len,
			.packets      = 1,
			.last_seen_ns = now,
			.created_ns   = now,
		};
		/*
		 * BPF_ANY: on a first-packet race between CPUs, one CPU's
		 * initial count overwrites the other's. Acceptable: at most
		 * one packet lost per new flow. PERCPU eliminates contention
		 * on all subsequent packets, which is what matters at line rate.
		 *
		 * A nonzero return means the map is full (-E2BIG) and this
		 * flow's bytes are lost until space frees up. Count the loss
		 * — billing-path errors are never silent (docs/architecture/edge-cases.md
		 * Tier 2 #4).
		 */
		if (bpf_map_update_elem(&telemetry_map, &key, &init, BPF_ANY) != 0)
			stat_inc(STAT_UPDATE_FAILURE);
	}

	return TC_ACT_OK;
}

SEC("tc")
int tc_telemetry_in(struct __sk_buff *skb)
{
	return handle_packet(skb, TC_DIR_INGRESS);
}

SEC("tc")
int tc_telemetry_out(struct __sk_buff *skb)
{
	return handle_packet(skb, TC_DIR_EGRESS);
}

char _license[] SEC("license") = "GPL";
