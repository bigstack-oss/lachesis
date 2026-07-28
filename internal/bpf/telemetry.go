package bpf

// Paths are relative to this directory, so generation works from any checkout
// root — the Docker builder, an rpmbuild tree, or a bare clone. .include is the
// one normalized include root; see the headers task in Taskfile.yml.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package bpf -type zone_code -type tc_direction telemetry ../../bpf/telemetry.c -- -I../../.include
