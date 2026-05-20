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
 * Design: docs/DESIGN.md §3 (data structures) and §4 (classification).
 */

#include "vmlinux.h"
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
 * docs/DESIGN.md §3.1 cardinality is O(G + Σ O_t), where G is
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
 * mac_tenant_map: MAC → tenant_id. The MAC is packed into the low 48 bits
 * of a u64 in big-endian order (see mac_to_u64). Populated by the userspace
 * agent from the platform's port metadata.
 *
 * Sizing: one entry per active Neutron port (compute:nova VMs plus
 * Amphora data ports). dev-cmp empirically observes ~17 compute:nova
 * ports today; a production OVN-Yoga deployment can reach a few
 * thousand. 8192 = 2× headroom over a 4000-port target in a
 * power-of-two.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u32);
} mac_tenant_map SEC(".maps");

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
 * vs TenantID="" emission rules) and docs/DESIGN.md §3.1.
 */
static __always_inline __u8 lookup_zone(const __u8 vm_mac[6],
					const __u8 peer_mac[6],
					__be32 remote_ip_be)
{
	__u64 vm_key = mac_to_u64(vm_mac);
	__u32 *vm_tid = bpf_map_lookup_elem(&mac_tenant_map, &vm_key);
	if (!vm_tid)
		return ZONE_MISS;

	__u64 peer_key = mac_to_u64(peer_mac);
	__u32 *peer_tid = bpf_map_lookup_elem(&mac_tenant_map, &peer_key);
	if (peer_tid)
		return (*peer_tid == *vm_tid) ? ZONE_SAME_TENANT : ZONE_OTHER_TENANT;

	struct lpm_key lk = {
		.prefixlen = 64,	/* request full match; trie picks the longest stored prefix */
		.tenant_id = *vm_tid,
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
	/* ARP / LLDP / non-IP: pass through uncounted. */
	if (proto != ETH_P_IP && proto != ETH_P_IPV6)
		return TC_ACT_OK;

	struct flow_key key = {};
	__builtin_memcpy(key.src_mac, eth->h_source, 6);
	__builtin_memcpy(key.dst_mac, eth->h_dest, 6);
	key.eth_proto = proto;
	key.direction = direction;

	if (proto == ETH_P_IP) {
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
		 */
		const _Bool ingress = (direction == TC_DIR_INGRESS);
		const __u8 *vm_mac    = ingress ? eth->h_source : eth->h_dest;
		const __u8 *peer_mac  = ingress ? eth->h_dest   : eth->h_source;
		__be32      remote_ip = ingress ? iph->daddr    : iph->saddr;

		key.dst_zone = lookup_zone(vm_mac, peer_mac, remote_ip);
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
		};
		/*
		 * BPF_ANY: on a first-packet race between CPUs, one CPU's
		 * initial count overwrites the other's. Acceptable: at most
		 * one packet lost per new flow. PERCPU eliminates contention
		 * on all subsequent packets, which is what matters at line rate.
		 */
		bpf_map_update_elem(&telemetry_map, &key, &init, BPF_ANY);
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
