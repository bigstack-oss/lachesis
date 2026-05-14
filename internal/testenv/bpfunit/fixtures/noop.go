// Package fixtures contains BPF programs used only by the test infrastructure.
//
// These programs are not production code; they exist as targets for the
// bpfunit driver so the test framework can be exercised independently of
// the real classifier.
package fixtures

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package fixtures Noop /app/bpf/test_fixtures/noop.c -- -I/app/.include
