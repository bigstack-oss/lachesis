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
