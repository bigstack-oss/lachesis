package netlink

import "context"

// Subscriber is the cross-platform interface the agent uses to start
// and stop the netlink link-event watcher. The Linux implementation
// lives in subscriber_linux.go; on darwin the interface is unused
// (agent unit tests wire a nil and skip Run).
type Subscriber interface {
	// Run drives the subscriber until ctx is cancelled. A lost
	// netlink subscription is re-established, not returned.
	Run(ctx context.Context) error
}
