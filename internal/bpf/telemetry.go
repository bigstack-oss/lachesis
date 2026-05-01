package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package bpf Telemetry /app/bpf/telemetry.c -- -I/app/.include
