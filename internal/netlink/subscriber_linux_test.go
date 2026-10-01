//go:build linux

package netlink

import (
	"context"
	"errors"
	"math"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// vanishedIndex is an ifindex no interface holds, so linkGone reports
// it gone; loIndex (lo exists in every netns) is one that is present.
const vanishedIndex = math.MaxInt32

func loIndex(t *testing.T) int {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lookup lo: %v", err)
	}
	return lo.Index
}

// fakeAttacher reports attached for the names in attached and fails
// Attach for the names in errs; a successful Attach marks the name
// attached. It records every Attach call.
type fakeAttacher struct {
	attached map[string]bool
	errs     map[string]error
	calls    []string
}

func (a *fakeAttacher) Attach(link netlink.Link) error {
	name := link.Attrs().Name
	a.calls = append(a.calls, name)
	if err := a.errs[name]; err != nil {
		return err
	}
	if a.attached == nil {
		a.attached = make(map[string]bool)
	}
	a.attached[name] = true
	return nil
}

func (a *fakeAttacher) Attached(link netlink.Link) bool {
	return a.attached[link.Attrs().Name]
}

func tapLink(name string, index int) netlink.Link {
	return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}
}

// TestOnNewLink_AttachFailureCounting pins which attach failures move
// lachesis_tc_attach_failures_total: a NEWLINK whose interface is gone
// by the time the attach runs (the source side of a live migration)
// is a skip, while a failure on a still-present interface counts. The
// presence check hits the real kernel.
func TestOnNewLink_AttachFailureCounting(t *testing.T) {
	cases := []struct {
		name    string
		index   int
		wantTap string
	}{
		{name: "vanished interface is not a failure", index: vanishedIndex, wantTap: "0"},
		{name: "present interface failure counts", index: loIndex(t), wantTap: "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()
			metrics := NewMetrics(registry.Len)
			s := newLinuxSubscriber(Options{
				Attacher: &fakeAttacher{errs: map[string]error{"tap29a0c4f7-85": errors.New("attach failed")}},
				Prefixes: []string{"tap"},
				Registry: registry,
				Metrics:  metrics,
			})

			s.handle(netlink.LinkUpdate{
				Header: unix.NlMsghdr{Type: unix.RTM_NEWLINK},
				Link:   tapLink("tap29a0c4f7-85", tc.index),
			})

			if registry.IsAttached("tap29a0c4f7-85") {
				t.Error("failed attach left the interface registered")
			}
			reg := prometheus.NewPedanticRegistry()
			reg.MustRegister(metrics.Collectors()...)
			want := `
# HELP lachesis_tc_attach_failures_total TC clsact attach failures from the netlink subscriber, labelled by iface_kind ("tap" for prefix-matched, "other" for explicit-list entries).
# TYPE lachesis_tc_attach_failures_total counter
lachesis_tc_attach_failures_total{iface_kind="other"} 0
lachesis_tc_attach_failures_total{iface_kind="tap"} ` + tc.wantTap + `
`
			if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
				"lachesis_tc_attach_failures_total"); err != nil {
				t.Errorf("metric mismatch:\n%v", err)
			}
		})
	}
}

// TestResync pins the attach-presence sweep against the kernel's view
// (the fake Attacher): an attached link is left alone, an unattached
// one is re-attached (healed) or counted failed while present, a
// vanished one is skipped, a non-allowlisted one is ignored, and the
// Registry is rebuilt to exactly what is attached — dropping a stale
// entry and adding the healed ones.
func TestResync(t *testing.T) {
	present := loIndex(t)
	attacher := &fakeAttacher{
		attached: map[string]bool{"tap-ok": true},
		errs: map[string]error{
			"tap-fail": errors.New("attach failed"),
			"tap-gone": errors.New("no such device"),
		},
	}
	registry := NewRegistry()
	registry.MarkAttached("tap-ok")
	registry.MarkAttached("tap-stale")
	metrics := NewMetrics(registry.Len)
	s := newLinuxSubscriber(Options{
		Attacher: attacher,
		Prefixes: []string{"tap"},
		Explicit: []string{"br-ex"},
		Registry: registry,
		Metrics:  metrics,
	})
	s.listLinks = func() ([]netlink.Link, error) {
		return []netlink.Link{
			tapLink("tap-ok", present),
			tapLink("tap-miss", present),
			tapLink("tap-fail", present),
			tapLink("tap-gone", vanishedIndex),
			tapLink("eth0", present),
			tapLink("br-ex", present),
		}, nil
	}

	s.resync()
	// A second sweep: the healed links are now attached (no new
	// attempt), the persistent failure is attempted and counted again.
	s.resync()

	if got, want := registry.Snapshot(), []string{"br-ex", "tap-miss", "tap-ok"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Registry = %v, want %v", got, want)
	}
	wantCalls := []string{"tap-miss", "tap-fail", "tap-gone", "br-ex", "tap-fail", "tap-gone"}
	if !reflect.DeepEqual(attacher.calls, wantCalls) {
		t.Errorf("Attach calls = %v, want %v", attacher.calls, wantCalls)
	}
	if _, ok := s.failing["tap-fail"]; !ok || len(s.failing) != 1 {
		t.Errorf("failing = %v, want only tap-fail", s.failing)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(metrics.Collectors()...)
	want := `
# HELP lachesis_tc_reattach_total Attach-presence sweep re-attach attempts, labelled by iface_kind and outcome ("healed" or "failed"). A healed re-attach is a missed netlink event or a filter removed out-of-band.
# TYPE lachesis_tc_reattach_total counter
lachesis_tc_reattach_total{iface_kind="other",outcome="failed"} 0
lachesis_tc_reattach_total{iface_kind="other",outcome="healed"} 1
lachesis_tc_reattach_total{iface_kind="tap",outcome="failed"} 2
lachesis_tc_reattach_total{iface_kind="tap",outcome="healed"} 1
# HELP lachesis_tc_unattached_interfaces Allowlisted interfaces the last attach-presence sweep found without the telemetry TC programs and failed to re-attach, labelled by iface_kind. Sustained > 0 means traffic on them is unbilled.
# TYPE lachesis_tc_unattached_interfaces gauge
lachesis_tc_unattached_interfaces{iface_kind="other"} 0
lachesis_tc_unattached_interfaces{iface_kind="tap"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want),
		"lachesis_tc_reattach_total", "lachesis_tc_unattached_interfaces"); err != nil {
		t.Errorf("metric mismatch:\n%v", err)
	}
}

// TestResync_ListFailureKeepsState: a sweep that cannot list links
// changes nothing — it must not empty the Registry or zero the gauge.
func TestResync_ListFailureKeepsState(t *testing.T) {
	registry := NewRegistry()
	registry.MarkAttached("tap-ok")
	s := newLinuxSubscriber(Options{
		Attacher: &fakeAttacher{},
		Prefixes: []string{"tap"},
		Registry: registry,
	})
	s.listLinks = func() ([]netlink.Link, error) { return nil, errors.New("dump interrupted") }

	s.resync()

	if !registry.IsAttached("tap-ok") {
		t.Error("a failed link listing dropped a Registry entry")
	}
}

// TestRun_Resubscribes drives the re-subscribe loop with a fake stream:
// every lost subscription is counted and retried after the capped
// exponential backoff, a stream that lived at least the cap resets it,
// every stream after the first opens with a resync, and cancelling ctx
// ends Run with nil.
func TestRun_Resubscribes(t *testing.T) {
	const (
		bmin = time.Millisecond
		bmax = 4 * time.Millisecond
	)
	// Each entry is one stream: how long it lives before failing.
	// The last stream blocks until ctx is cancelled.
	lives := []time.Duration{0, 0, 0, 0, 2 * bmax, 0}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := NewMetrics(func() int { return 0 })
	s := newLinuxSubscriber(Options{
		Attacher: &fakeAttacher{},
		Registry: NewRegistry(),
		Metrics:  metrics,
	})
	s.backoff = backoffPolicy{min: bmin, max: bmax}
	var (
		delays      []time.Duration
		resyncFirst []bool
	)
	s.after = func(d time.Duration) <-chan time.Time {
		delays = append(delays, d)
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	s.stream = func(ctx context.Context, first bool) error {
		resyncFirst = append(resyncFirst, first)
		n := len(resyncFirst)
		if n > len(lives) {
			cancel()
			<-ctx.Done()
			return nil
		}
		time.Sleep(lives[n-1])
		return errors.New("socket closed")
	}

	if err := s.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}

	// 1→2→4 (capped) →4, then the long-lived stream resets to 1 → 2.
	wantDelays := []time.Duration{bmin, 2 * bmin, bmax, bmax, bmin, 2 * bmin}
	if !reflect.DeepEqual(delays, wantDelays) {
		t.Errorf("backoff delays = %v, want %v", delays, wantDelays)
	}
	wantFirst := []bool{false, true, true, true, true, true, true}
	if !reflect.DeepEqual(resyncFirst, wantFirst) {
		t.Errorf("resyncFirst per stream = %v, want %v", resyncFirst, wantFirst)
	}
	if got := testutil.ToFloat64(metrics.restarts); got != float64(len(lives)) {
		t.Errorf("restarts = %v, want %d", got, len(lives))
	}
}
