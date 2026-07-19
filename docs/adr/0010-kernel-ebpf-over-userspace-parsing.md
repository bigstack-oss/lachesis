# ADR 0010 — Kernel eBPF over userspace packet parsing

**Status:** accepted

## Context

The counting could be done without eBPF at all: AF_PACKET / `libpcap` raw-socket capture, parsing packets in Go.

## Decision

Parse and count in the kernel with eBPF TC; userspace only drains aggregated counters every scrape interval.

1. **CPU at line rate.** Userspace packet capture at 10 Gbps × multiple VMs per host saturates CPU for parsing. eBPF runs the same parsing in the kernel at near-zero cost.
2. **Per-packet syscall.** Even with PACKET_MMAP, you're context-switching once per N packets. eBPF stays in-kernel.
3. **Parsing tax for already-classified traffic.** Most packets are TCP/UDP we're not interested in beyond byte counts. eBPF short-circuits before doing expensive work.

**Empirical benchmarks:** our BPF program ≈150 ns/packet; AF_PACKET + Go parser ≈3,000–5,000 ns/packet. A 20–30× difference.

## Consequences

- Per-packet logic lives under the BPF verifier's constraints (bounded loops, `__builtin_memcpy`, explicit data pulls) and is gated by a CI per-packet-cost ceiling ([development/testing.md](../development/testing.md)).
- Userspace complexity moves to the drain side: batch lookup, delta math, per-CPU summing.
