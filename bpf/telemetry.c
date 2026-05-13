#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK         0
#define ETH_P_IP          0x0800
#define ETH_P_IPV6        0x86DD

// Zone codes — single source of truth (mirrored to Go via bpf2go BTF).
// __attribute__((packed)) keeps it __u8-sized so flow_key stays 16 bytes.
enum zone_code {
    ZONE_EXTERNAL     = 0,
    ZONE_SAME_TENANT  = 1,
    ZONE_OTHER_TENANT = 2,
    ZONE_INFRA        = 3,
    ZONE_MISS         = 4,
} __attribute__((packed));

// TC hook direction — single source of truth (mirrored to Go via bpf2go BTF).
enum tc_direction {
    TC_DIR_INGRESS = 0, // VM is sending (packet arrives at tap ingress)
    TC_DIR_EGRESS  = 1, // VM is receiving (packet arrives at tap egress)
} __attribute__((packed));

// 16-byte MAC-pair + direction + dst_zone flow key (real design from spec)
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

// LPM key: prefixlen covers bits in (tenant_id ++ ip).
// Catchall entry:  prefixlen=32 → exact tenant_id, /0 ip wildcard.
// Subnet /24 entry: prefixlen=56 → exact tenant_id + 24-bit ip prefix.
struct lpm_key {
    __u32 prefixlen;
    __u32 tenant_id;
    __u32 ip; // IPv4; IPv6 extension out of demo scope
};

// PERCPU_HASH: each CPU owns its slot — no atomic needed at 10 Gbps × N cores.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} telemetry_map SEC(".maps");

// LPM trie: (tenant_id, dst_ip) → zone code.
// Populated from Go side on boot (demo stubs; production: MySQL cold-start + Kafka).
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_zone_trie SEC(".maps");

// MAC → tenant_id.  Key: MAC as big-endian u64 (low 6 bytes used).
// Populated from Go side on boot (demo stubs; production: OpenStack metadata).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} mac_tenant_map SEC(".maps");

static __always_inline __u64 mac_to_u64(const __u8 mac[6])
{
    return ((__u64)mac[0] << 40) | ((__u64)mac[1] << 32) |
           ((__u64)mac[2] << 24) | ((__u64)mac[3] << 16) |
           ((__u64)mac[4] <<  8) |  (__u64)mac[5];
}

// Hybrid MAC-first / LPM-fallback zone resolution (§4.3).
//
//   1. vm_mac must be in mac_tenant_map; otherwise ZONE_MISS — not our VM.
//   2. Direct-L2 fast path: if peer_mac is also in mac_tenant_map, compare
//      tenant_ids exactly. No trie consulted, no CIDR ambiguity.
//   3. Routed traffic (peer_mac is a router or unknown) falls back to the
//      LPM trie keyed on (vm_tenant_id, remote_ip).
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
        .prefixlen = 64, // request full match; trie finds longest stored prefix
        .tenant_id = *vm_tid,
        .ip        = bpf_ntohl(remote_ip_be),
    };
    __u8 *zone = bpf_map_lookup_elem(&subnet_zone_trie, &lk);
    return zone ? *zone : ZONE_MISS;
}

// Shared packet handler; direction is inlined as a constant per program.
static __always_inline int handle_packet(struct __sk_buff *skb, enum tc_direction direction)
{
    // Pull Ethernet + IPv4 headers into linear region before accessing.
    if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)) < 0)
        return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = bpf_ntohs(eth->h_proto);
    // ARP/LLDP/non-IP: pass through uncounted per spec.
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

        // Directional swap: always classify against the VM's own MAC and
        // the *remote* endpoint IP.
        //
        // INGRESS (VM sending):  vm_mac=h_source, remote_ip=daddr.
        //   → "what zone is the VM sending to?"
        // EGRESS  (VM receiving): vm_mac=h_dest, remote_ip=saddr.
        //   → "what zone is the VM receiving from?"
        //
        // Without this swap, egress traffic from 8.8.8.8 would look up
        // daddr (the VM's own IP) and classify a Google download as
        // same-tenant — a direct billing loss.
        const _Bool ingress = (direction == TC_DIR_INGRESS);
        const __u8 *vm_mac   = ingress ? eth->h_source : eth->h_dest;
        const __u8 *peer_mac = ingress ? eth->h_dest   : eth->h_source;
        __be32      remote_ip = ingress ? iph->daddr    : iph->saddr;

        key.dst_zone = lookup_zone(vm_mac, peer_mac, remote_ip);
    } else {
        // IPv6 zone resolution: out of demo scope, mark as miss.
        key.dst_zone = ZONE_MISS;
    }

    __u64 pkt_len = skb->len;
    __u64 now     = bpf_ktime_get_ns();

    struct flow_metrics *val = bpf_map_lookup_elem(&telemetry_map, &key);
    if (val) {
        // PERCPU slot: no atomic needed — this CPU is the sole writer.
        val->bytes       += pkt_len;
        val->packets     += 1;
        val->last_seen_ns = now;
    } else {
        struct flow_metrics init = {
            .bytes       = pkt_len,
            .packets     = 1,
            .last_seen_ns = now,
        };
        // BPF_ANY: on a first-packet race between CPUs, one CPU's initial
        // count overwrites the other's.  Acceptable: at most 1 packet lost
        // per new flow.  PERCPU eliminates contention on all subsequent
        // packets, which is what matters at line-rate.
        bpf_map_update_elem(&telemetry_map, &key, &init, BPF_ANY);
    }

    return TC_ACT_OK;
}

SEC("tc")
int tc_telemetry_in(struct __sk_buff *skb)
{
    return handle_packet(skb, TC_DIR_INGRESS); // VM is sending
}

SEC("tc")
int tc_telemetry_out(struct __sk_buff *skb)
{
    return handle_packet(skb, TC_DIR_EGRESS); // VM is receiving
}

char _license[] SEC("license") = "GPL";
