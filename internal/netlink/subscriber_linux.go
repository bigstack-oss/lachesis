//go:build linux

package netlink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Attacher attaches the telemetry programs to a link and reports
// whether a link carries them. It is the seam that keeps this package
// (L3) from depending on the L1 TC-attach machinery: the agent
// composition root supplies the implementation (over
// internal/tcattach), so neither *ebpf.Program nor internal/tcattach
// appears in this package.
type Attacher interface {
	// Attach attaches the telemetry programs to link. A non-nil
	// error leaves the link unattached.
	Attach(link netlink.Link) error

	// Attached reports whether link carries the telemetry programs
	// in the slot Attach installs them.
	Attached(link netlink.Link) bool
}

// Options bundles the inputs to [New]. All fields are required
// except Metrics, which may be nil for tests, and ResyncInterval.
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

	// ResyncInterval is the cadence of the attach-presence sweep,
	// which re-attaches any allowlisted link the kernel shows without
	// the telemetry filters. Zero disables the sweep.
	//
	// docs/architecture/boot-and-recovery.md#attach-presence-resync
	ResyncInterval time.Duration
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

	// stream, listLinks, backoff and after are fixed in production;
	// tests replace them to drive the re-subscribe loop and the sweep
	// without a kernel event source.
	stream    func(ctx context.Context, resyncFirst bool) error
	listLinks func() ([]netlink.Link, error)
	backoff   backoffPolicy
	after     func(time.Duration) <-chan time.Time

	// failing holds the links the last sweep failed to re-attach, so
	// a persistently failing link warns once rather than every sweep.
	failing map[string]struct{}
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
	return newLinuxSubscriber(opts), nil
}

func newLinuxSubscriber(opts Options) *linuxSubscriber {
	s := &linuxSubscriber{
		opts:      opts,
		listLinks: netlink.LinkList,
		backoff:   backoffPolicy{min: resubscribeBackoffMin, max: resubscribeBackoffMax},
		after:     time.After,
		failing:   make(map[string]struct{}),
	}
	s.stream = s.runStream
	return s
}

// next returns the delay after one more consecutive failure: double
// the current one, capped at max.
func (b backoffPolicy) next(d time.Duration) time.Duration {
	return min(2*d, b.max)
}

// linkGone reports whether the kernel positively says the link at
// index does not exist. Any other lookup error counts as present, so
// an unexplained attach failure is still recorded as one.
func linkGone(index int) bool {
	_, err := netlink.LinkByIndex(index)
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}

// Run drives the subscriber until ctx is cancelled, always returning
// nil. A lost subscription (the netlink socket dies, e.g. ENOBUFS when
// an event storm overflows it) is re-established after a capped
// exponential backoff rather than ending discovery: every event
// between the loss and the re-subscribe is gone, so the new stream
// opens with an attach-presence sweep, and its ListExisting replay
// covers links that appeared meanwhile.
func (s *linuxSubscriber) Run(ctx context.Context) error {
	delay := s.backoff.min
	resyncFirst := false
	for {
		started := time.Now()
		err := s.stream(ctx, resyncFirst)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) >= s.backoff.max {
			delay = s.backoff.min
		}
		s.opts.Metrics.recordRestart()
		slog.Warn("subscription lost; re-subscribing",
			"component", component, "err", err, "backoff", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-s.after(delay):
		}
		delay = s.backoff.next(delay)
		resyncFirst = true
	}
}

// runStream subscribes once and consumes link events until ctx is
// cancelled (returns nil) or the subscription fails (returns the
// cause). With resyncFirst it sweeps before consuming the first event.
func (s *linuxSubscriber) runStream(ctx context.Context, resyncFirst bool) error {
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
	// single odd message end this subscription for nothing. We log
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
		"explicit", s.opts.Explicit,
		"resync_interval", s.opts.ResyncInterval)

	var tick <-chan time.Time
	if s.opts.ResyncInterval > 0 {
		t := time.NewTicker(s.opts.ResyncInterval)
		defer t.Stop()
		tick = t.C
	}
	if resyncFirst && tick != nil {
		s.resync()
	}

	// Attach synchronously on this goroutine. We deliberately do NOT
	// fan out to a worker goroutine: all netlink work must stay on the
	// one goroutine the caller controls (the integration harness pins it
	// to a network namespace, and a spawned goroutine would escape that
	// pin and operate in the wrong netns). Burst absorption comes from
	// the buffered ch above, which the library's own receive goroutine
	// keeps filling while we attach. The resync sweep runs here too, so
	// it never races the event path on the Registry.
	for {
		select {
		case <-ctx.Done():
			slog.Info("subscriber stopping", "component", component, "attached", s.opts.Registry.Len())
			return nil
		case <-tick:
			s.resync()
		case ev, ok := <-ch:
			if !ok {
				// The library closed ch: the netlink socket died.
				// Surface the last callback error (the Receive
				// failure) as the cause if we captured one.
				mu.Lock()
				err := lastErr
				mu.Unlock()
				if err == nil {
					err = errors.New("netlink: event channel closed")
				}
				return fmt.Errorf("netlink: socket closed: %w", err)
			}
			s.handle(ev)
		}
	}
}

// handle dispatches a single LinkUpdate to the attach or detach
// path. Filtering by name happens here, not in the netlink layer,
// so the subscriber's match policy stays in one place.
func (s *linuxSubscriber) handle(ev netlink.LinkUpdate) {
	name := ev.Attrs().Name
	if !ShouldAttach(name, s.opts.Prefixes, s.opts.Explicit) {
		return
	}
	switch ev.Header.Type {
	case unix.RTM_NEWLINK:
		s.onNewLink(ev.Link)
	case unix.RTM_DELLINK:
		s.onDelLink(name)
	}
}

// onNewLink attaches the telemetry programs to link.
// Idempotent at the attach level: a second NEWLINK for an
// already-attached interface is a netlink no-op via FilterReplace, so
// we skip the round-trip when the Registry already records us as
// attached.
//
// A failure on a link that has since vanished is not an attach
// failure: a tap unregistering (e.g. the source side of a live
// migration) can still have a NEWLINK queued behind its DELLINK, and
// there is nothing left to attach to or bill.
func (s *linuxSubscriber) onNewLink(link netlink.Link) {
	attrs := link.Attrs()
	name := attrs.Name
	if s.opts.Registry.IsAttached(name) {
		return
	}
	// Attach is all-or-nothing: on a partial failure it rolls back,
	// so the link is left unattached and the Registry/gauge stay
	// consistent with reality.
	if err := s.opts.Attacher.Attach(link); err != nil {
		if linkGone(attrs.Index) {
			slog.Debug("attach skipped: interface vanished",
				"component", component, "iface", name, "err", err)
			return
		}
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

// resync is the attach-presence sweep: it checks every allowlisted
// link against the kernel, re-attaches those missing the telemetry
// filters, and rebuilds the Registry as the set the kernel actually
// carries. The kernel is the truth, not the Registry — a missed
// NEWLINK/DELLINK or a filter removed out-of-band leaves the Registry
// wrong in ways only the kernel shows. A link that vanishes mid-sweep
// is skipped, as on the event path.
//
// docs/architecture/boot-and-recovery.md#attach-presence-resync
func (s *linuxSubscriber) resync() {
	links, err := s.listLinks()
	if err != nil {
		slog.Warn("resync: list links failed", "component", component, "err", err)
		return
	}
	var (
		attached   []string
		unattached = map[string]int{ifaceKindTap: 0, ifaceKindOther: 0}
		failing    = make(map[string]struct{})
	)
	for _, link := range links {
		attrs := link.Attrs()
		name := attrs.Name
		if !ShouldAttach(name, s.opts.Prefixes, s.opts.Explicit) {
			continue
		}
		if s.opts.Attacher.Attached(link) {
			attached = append(attached, name)
			continue
		}
		kind := s.kindFor(name)
		if err := s.opts.Attacher.Attach(link); err != nil {
			if linkGone(attrs.Index) {
				continue
			}
			failing[name] = struct{}{}
			unattached[kind]++
			s.opts.Metrics.recordReattach(kind, outcomeFailed)
			if _, known := s.failing[name]; !known {
				slog.Warn("resync: re-attach failed",
					"component", component, "iface", name, "err", err)
			}
			continue
		}
		attached = append(attached, name)
		s.opts.Metrics.recordReattach(kind, outcomeHealed)
		slog.Info("resync: re-attached an unattached interface",
			"component", component, "iface", name, "kind", kind)
	}
	s.failing = failing
	s.opts.Registry.Replace(attached)
	s.opts.Metrics.setUnattached(unattached)
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
