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
 * Design: docs/architecture/data-structures.md
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
 * Zone codes stored in flow_key.dst_zone. Values are STABLE across
 * releases — they are persisted to the WAL. Mirror the Zone* constants in
 * internal/bpf/abi.go. packed keeps flow_key at 16 bytes.
 *
 * Which zones bill is docs/architecture/billing.md.
 */
enum zone_code {
	ZONE_EXTERNAL     = 0,	/* off-cloud (the trie catchall) */
	ZONE_SAME_TENANT  = 1,	/* peer in the VM's own project */
	ZONE_OTHER_TENANT = 2,	/* peer in a different project */
	ZONE_INFRA        = 3,	/* router / DHCP / metadata endpoint */
	ZONE_MISS         = 4,	/* vm_mac unknown, or no trie row */
	ZONE_SHARED       = 5,	/* shared network; LPM cannot resolve owner */
	ZONE_MULTICAST    = 6,	/* group MAC; counted, never billed */
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

/*
 * Per-flow counters, cumulative for one entry's lifetime. last_seen_ns
 * is the GC eviction key; created_ns is the entry-identity stamp,
 * written once and never updated. Never infer a reset from magnitudes.
 *
 * docs/adr/0014-in-band-entry-identity-over-inferred-resets.md
 */
struct flow_metrics {
	__u64 bytes;
	__u64 packets;
	__u64 last_seen_ns;
	__u64 created_ns;
};

/*
 * lpm_key: prefixlen covers bits in (tenant_id ++ ip). ip is IPv4 only and
 * holds wire byte order (see the assignment in lookup_zone).
 *   - Catchall entry:   prefixlen=32 → exact tenant_id, /0 ip wildcard.
 *   - Subnet /24 entry: prefixlen=56 → exact tenant_id + 24-bit ip prefix.
 */
struct lpm_key {
	__u32 prefixlen;
	__u32 tenant_id;
	__u32 ip;
};

/* PERCPU_HASH: each CPU writes to its own slot; no atomics on the hot path. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_metrics);
} telemetry_map SEC(".maps");

/*
 * subnet_zone_trie: (tenant_id, dst_ip) → zone code. 16384 is the cap
 * AFTER global-row dedup; do not shrink it without re-measuring against
 * a real tenant count. Headroom is near-free under NO_PREALLOC.
 *
 * docs/architecture/data-structures.md#kernel-side-bpf-maps
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_zone_trie SEC(".maps");

/*
 * mac_tenant_map: MAC → (amphora flag ++ tenant_id), the MAC packed into
 * the low 48 bits of a u64 big-endian (see mac_to_u64).
 *
 * The top bit marks an Octavia Amphora data port and the low 31 bits are
 * the interned tenant id — packed rather than given a sidecar map because
 * a second lookup would cost ~20-30ns against an 82-110ns per-packet
 * budget, to produce nothing but a zone label. Mask before comparing
 * tenants or keying the trie. Bounds a deployment at 2^31-1 tenants.
 *
 * 8192 is 2x headroom over a 4000-active-port target; re-measure before
 * shrinking.
 *
 * docs/architecture/octavia.md
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
 * internal/bpf/schema.go — STAT_REASON_MAX is also the map's max_entries,
 * so a reason added here without the Go mirror fails ValidateMapSizes at
 * boot rather than silently skewing slots.
 */
enum stat_reason {
	STAT_UPDATE_FAILURE    = 0,	/* telemetry_map insert rejected */
	STAT_SKIPPED_ETHERTYPE = 1,	/* non-IP frame passed uncounted */
	STAT_REASON_MAX,		/* sentinel: slot count, not a reason */
};

/*
 * telemetry_stats: the failure/skip counters, drained by the scraper.
 * PERCPU_ARRAY so an increment is a plain per-CPU store and only the
 * failure paths touch it — the happy path is unchanged (Cilium's
 * metricsmap pattern). One slot per reason; never scales with deployment.
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
 * lookup_zone - MAC-first, then LPM, then the tenant_id=0 sentinel where
 * the global rows live. The catchall makes that last lookup hit in steady
 * state, so ZONE_MISS means an unpopulated trie or a bug, never a miss.
 *
 * MAC-first, then LPM, then the tenant_id=0 sentinel where the global
 * rows live. The catchall makes that last lookup hit in steady state, so
 * ZONE_MISS means an unpopulated trie or a bug, never a normal miss.
 *
 * Octavia: each flagged end is tested against its OWN address, because an
 * unflagged peer's address is ordinary tenant space that could collide
 * with another project's Amphora base IP. Both ends are checked so the
 * same transfer zones identically at the Amphora's tap and the backend's
 * — split across two zones it is unreconcilable. Only the base address
 * means Segment 2 (infra); a VIP is Segment 1, which is real billable
 * traffic and must not be swallowed here.
 *
 * docs/architecture/octavia.md
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

	/*
	 * ip holds WIRE byte order, not host: the trie walks key bytes
	 * MSB-first, so the address must lead with its MSB in memory for
	 * CIDR matching. Userspace agrees via internal/bpf.LpmKeyForPrefix.
	 */
	struct lpm_key lk = {
		.prefixlen = 64,		/* trie picks longest stored */
		.tenant_id = vm_tid,		/* already masked, exact-matched */
		.ip        = remote_ip_be,	/* wire order; see above */
	};
	__u8 *zone = bpf_map_lookup_elem(&subnet_zone_trie, &lk);
	if (zone)
		return *zone;

	/*
	 * Sentinel fallback. Same key, tenant_id rewritten to 0; the
	 * verifier is happy with a second lookup on the same stack-
	 * allocated struct. Catchall at 0.0.0.0/0 guarantees a hit
	 * in steady state.
	 */
	lk.tenant_id = 0;
	zone = bpf_map_lookup_elem(&subnet_zone_trie, &lk);
	return zone ? *zone : ZONE_MISS;
}

/* IEEE 802 I/G bit: multicast and broadcast destinations. */
static __always_inline _Bool is_group_mac(const __u8 mac[6])
{
	return mac[0] & 0x01;
}

/* One flow's endpoints named from the VM's side, not the hook's. */
struct flow_endpoints {
	const __u8 *vm_mac;
	const __u8 *peer_mac;
	__be32      local_ip;	/* the VM's own address */
	__be32      remote_ip;	/* the peer's */
};

/*
 * endpoints_from_vm - resolve who is the VM and who is the peer.
 *
 * Both hooks sit on the same tap, so the wire roles invert between them.
 * Reading h_source/daddr unconditionally would make egress look the VM's
 * own address up as its peer — which classifies, and mis-bills, silently.
 */
static __always_inline struct flow_endpoints
endpoints_from_vm(const struct ethhdr *eth, const struct iphdr *iph,
		  enum tc_direction direction)
{
	if (direction == TC_DIR_INGRESS)
		return (struct flow_endpoints){
			.vm_mac = eth->h_source, .peer_mac = eth->h_dest,
			.local_ip = iph->saddr,  .remote_ip = iph->daddr,
		};
	return (struct flow_endpoints){
		.vm_mac = eth->h_dest,   .peer_mac = eth->h_source,
		.local_ip = iph->daddr,  .remote_ip = iph->saddr,
	};
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
	/*
	 * ARP / LLDP / non-IP: pass through uncounted, but keep the skip
	 * observable — a sustained rise flags a trunk/VLAN blind spot.
	 */
	if (proto != ETH_P_IP && proto != ETH_P_IPV6) {
		stat_inc(STAT_SKIPPED_ETHERTYPE);
		return TC_ACT_OK;
	}

	struct flow_key key = {};
	__builtin_memcpy(key.src_mac, eth->h_source, 6);
	__builtin_memcpy(key.dst_mac, eth->h_dest, 6);
	key.eth_proto = proto;
	key.direction = direction;

	if (is_group_mac(key.dst_mac)) {
		key.dst_zone = ZONE_MULTICAST;
	} else if (proto == ETH_P_IP) {
		struct iphdr *iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end)
			return TC_ACT_OK;

		struct flow_endpoints e = endpoints_from_vm(eth, iph, direction);

		key.dst_zone = lookup_zone(e.vm_mac, e.peer_mac,
					   e.local_ip, e.remote_ip);
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
		 * BPF_ANY: a first-packet race costs at most one packet, and
		 * PERCPU removes contention on every packet after. A nonzero
		 * return means the map is full and this flow's bytes are lost
		 * until space frees — count it, never drop it silently.
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
