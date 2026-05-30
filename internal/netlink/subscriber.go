package netlink

import "context"

// Subscriber is the cross-platform interface the agent uses to start
// and stop the netlink link-event watcher. The Linux implementation
// lives in subscriber_linux.go; on darwin the interface is unused
// (agent unit tests wire a nil and skip Run).
type Subscriber interface {
	// Run drives the subscriber until ctx is cancelled. Returns
	// nil on clean shutdown or a non-nil error if the netlink
	// socket failed.
	Run(ctx context.Context) error
}

// Attacher attaches the telemetry programs to a matched interface by
// name. It is the seam that keeps this package (L3) from depending on
// the L1 TC-attach machinery: the subscriber calls AttachLink on a
// match and the agent composition root supplies the implementation
// (over internal/tcattach), so neither *ebpf.Program nor internal/tcattach
// appears in this package.
type Attacher interface {
	// AttachLink attaches the telemetry programs to the named
	// interface. A non-nil error leaves the interface unregistered;
	// the subscriber records an attach failure and moves on.
	AttachLink(name string) error
}
