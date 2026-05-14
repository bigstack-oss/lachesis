// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal BPF program for exercising the bpfunit test driver.
 *
 * Not production code. Lives in bpf/test_fixtures/ so it never bleeds into
 * the real classifier (bpf/telemetry.c) or its generated bindings.
 *
 * Behavior: bumps a single counter and returns TC_ACT_OK on every packet.
 * Tests load this program, run packets through it, and read the counter
 * to verify the driver round-trips correctly.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} run_count SEC(".maps");

static __always_inline int bump_counter(void)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&run_count, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
	return TC_ACT_OK;
}

SEC("tc")
int tc_noop_in(struct __sk_buff *skb)
{
	return bump_counter();
}

SEC("tc")
int tc_noop_out(struct __sk_buff *skb)
{
	return bump_counter();
}

char _license[] SEC("license") = "GPL";
