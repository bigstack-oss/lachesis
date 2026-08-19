//go:build linux

package netlink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Options bundles the inputs to [New]. All fields are required
// except Metrics, which may be nil for tests.
type Options struct {
	// Attacher attaches the telemetry programs to a matched link.
	// The agent supplies an implementation over internal/tcattach so
	// this package stays free of the L1 attach machinery.
	Attacher Attacher

	// Prefixes and Explicit form the allowlist evaluated by
	// [ShouldAttach]. At least one must be non-empty or the
	// subscriber will attach to nothing.
	Prefixes []string
	Explicit []string

	// Registry tracks attached interfaces. May be shared with
	// other goroutines (e.g. the gauge in [Metrics]).
	Registry *Registry

	// Metrics receives attach-failure observations. Optional.
	Metrics *Metrics
}

func (o Options) validate() error {
	if o.Attacher == nil {
		return errors.New("netlink: Attacher is required")
	}
	if o.Registry == nil {
		return errors.New("netlink: Registry is required")
	}
	return nil
}

// linuxSubscriber listens on RTM_NEWLINK / RTM_DELLINK and attaches
// telemetry programs to every link whose name matches the
// configured allowlist. It writes a single value through the
// netlink.LinkSubscribeWithOptions(ListExisting: true) stream so
// the "subscribe before initial sweep" race is closed by construction
// — the kernel itself replays existing links as NEWLINK events on the
// same socket.
//
// Boot sequence: docs/architecture/boot-and-recovery.md#boot-sequence
type linuxSubscriber struct {
	opts Options
}

// New constructs a Subscriber. Returns an error if Options are
// incomplete; otherwise the returned Subscriber is ready to Run.
func New(opts Options) (Subscriber, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	// Defensive copy of allowlist slices so a caller mutating
	// the config later does not race the subscriber goroutine.
	opts.Prefixes = slices.Clone(opts.Prefixes)
	opts.Explicit = slices.Clone(opts.Explicit)
	return &linuxSubscriber{opts: opts}, nil
}

// Run drives the subscriber until ctx is cancelled. Returns nil on
// clean shutdown.
func (s *linuxSubscriber) Run(ctx context.Context) error {
	ch := make(chan netlink.LinkUpdate, eventChanDepth)
	done := make(chan struct{})
	defer close(done)

	// netlink's receive goroutine invokes ErrorCallback for two very
	// different classes of error. Most are transient and continue-able:
	// a stray NLMSG_ERROR, a wrong-portid message, a dump interrupt, or
	// a per-message deserialize failure on an exotic link — after any of
	// these the library logs and keeps reading. Exactly one is fatal:
	// the socket Receive() failing, after which the library closes ch.
	//
	// So we must NOT treat a callback as fatal — doing that would let a
	// single odd message permanently kill tap discovery (new VMs would
	// never get TC filters, their traffic silently uncounted). We log
	// every callback, remember the last error, and rely on ch closing as
	// the one true fatal signal. The store is non-blocking, so a burst of
	// callbacks can never wedge the library's receive goroutine.
	var (
		mu      sync.Mutex
		lastErr error
	)
	if err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ListExisting: true,
		ErrorCallback: func(err error) {
			slog.Warn("event error (continuing)", "component", component, "err", err)
			mu.Lock()
			lastErr = err
			mu.Unlock()
		},
	}); err != nil {
		return fmt.Errorf("netlink: LinkSubscribe: %w", err)
	}

	slog.Info("subscriber started",
		"component", component,
		"prefixes", s.opts.Prefixes,
		"explicit", s.opts.Explicit)

	// Attach synchronously on this goroutine. We deliberately do NOT
	// fan out to a worker goroutine: all netlink work must stay on the
	// one goroutine the caller controls (the integration harness pins it
	// to a network namespace, and a spawned goroutine would escape that
	// pin and operate in the wrong netns). Burst absorption comes from
	// the buffered ch above, which the library's own receive goroutine
	// keeps filling while we attach.
	for {
		select {
		case <-ctx.Done():
			slog.Info("subscriber stopping", "component", component, "attached", s.opts.Registry.Len())
			return nil
		case ev, ok := <-ch:
			if !ok {
				// The library closed ch: the netlink socket died.
				// This is the genuine fatal condition. Surface the
				// last callback error (the Receive failure) as the
				// cause if we captured one.
				mu.Lock()
				err := lastErr
				mu.Unlock()
				if err != nil {
					return fmt.Errorf("netlink: socket closed: %w", err)
				}
				return nil
			}
			s.handle(ev)
		}
	}
}

// handle dispatches a single LinkUpdate to the attach or detach
// path. Filtering by name happens here, not in the netlink layer,
// so the subscriber's match policy stays in one place.
func (s *linuxSubscriber) handle(ev netlink.LinkUpdate) {
	name := ev.Link.Attrs().Name
	if !ShouldAttach(name, s.opts.Prefixes, s.opts.Explicit) {
		return
	}
	switch ev.Header.Type {
	case unix.RTM_NEWLINK:
		s.onNewLink(name)
	case unix.RTM_DELLINK:
		s.onDelLink(name)
	}
}

// onNewLink attaches the telemetry programs to the named interface.
// Idempotent at the attach level: a second NEWLINK for an
// already-attached interface is a netlink no-op via FilterReplace, so
// we skip the round-trip when the Registry already records us as
// attached.
func (s *linuxSubscriber) onNewLink(name string) {
	if s.opts.Registry.IsAttached(name) {
		return
	}
	// AttachLink is all-or-nothing: on a partial failure it rolls back,
	// so the link is left unattached and the Registry/gauge stay
	// consistent with reality.
	if err := s.opts.Attacher.AttachLink(name); err != nil {
		slog.Warn("attach failed",
			"component", component, "iface", name, "err", err)
		s.opts.Metrics.recordAttachFailure(s.kindFor(name))
		return
	}
	s.opts.Registry.MarkAttached(name)
	slog.Info("attached",
		"component", component, "iface", name, "kind", s.kindFor(name))
}

// onDelLink forgets a link from the Registry. The kernel removes
// the qdisc and filters automatically when the link goes away, so
// no FilterDel is needed.
func (s *linuxSubscriber) onDelLink(name string) {
	if !s.opts.Registry.IsAttached(name) {
		return
	}
	s.opts.Registry.Forget(name)
	slog.Info("detached",
		"component", component, "iface", name)
}

// kindFor returns the iface_kind label value for metrics: "tap" when
// name matched a prefix, "other" otherwise (i.e. an explicit-list
// match). It reuses the same prefix matcher as [ShouldAttach] so the
// label can never drift from the actual match policy.
func (s *linuxSubscriber) kindFor(name string) string {
	if matchesPrefix(name, s.opts.Prefixes) {
		return ifaceKindTap
	}
	return ifaceKindOther
}
