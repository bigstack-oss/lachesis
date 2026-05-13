package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package bpf -type zone_code -type tc_direction Telemetry /app/bpf/telemetry.c -- -I/app/.include
