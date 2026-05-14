//go:build linux

// Package netns provides Linux network namespace lifecycle helpers for tests.
//
// This is not production code. Production agents do not manipulate netns
// directly; this package exists so tests can simulate multi-VM topologies
// on a single host.
//
// All operations require Linux + CAP_NET_ADMIN. Gate test files with
// //go:build integration.
package netns

import (
	"fmt"
	"net"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NS owns a Linux network namespace. Zero value is not usable; call New.
type NS struct {
	handle netns.NsHandle
}

// New creates a fresh anonymous network namespace and returns a handle.
// The caller must call [NS.Close] to release.
func New() (*NS, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("netns: capture current: %w", err)
	}
	defer orig.Close()

	// netns.New() creates AND switches the calling thread into the new ns.
	h, err := netns.New()
	if err != nil {
		return nil, fmt.Errorf("netns: create: %w", err)
	}

	// Switch back to the caller's ns; the new handle survives because we hold it.
	if err := netns.Set(orig); err != nil {
		h.Close()
		return nil, fmt.Errorf("netns: restore original: %w", err)
	}
	return &NS{handle: h}, nil
}

// Close destroys the namespace and releases the handle. Safe to call twice.
func (n *NS) Close() error {
	if !n.handle.IsOpen() {
		return nil
	}
	err := n.handle.Close()
	n.handle = netns.NsHandle(-1)
	return err
}

// Do runs fn while the calling goroutine is inside the namespace.
// The goroutine's OS thread is locked for the duration of fn; fn must not
// spawn long-running goroutines that escape this thread.
func (n *NS) Do(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("netns Do: capture current: %w", err)
	}
	defer func() {
		_ = netns.Set(orig)
		orig.Close()
	}()

	if err := netns.Set(n.handle); err != nil {
		return fmt.Errorf("netns Do: switch in: %w", err)
	}
	return fn()
}

// VethSpec describes a veth pair to create with AddVeth.
// Inner = the end that gets moved into the namespace; Outer = the end that
// stays in the caller's current namespace (typically the host's initial ns).
type VethSpec struct {
	InnerName, OuterName string
	InnerMAC, OuterMAC   net.HardwareAddr
	InnerIP, OuterIP     *net.IPNet
}

// AddVeth creates a veth pair: InnerName lives inside n, OuterName stays in
// the caller's current namespace. Both ends get the specified MAC + IP and
// are brought up. Returns the outer link for further configuration (e.g.,
// attaching TC filters).
func (n *NS) AddVeth(spec VethSpec) (netlink.Link, error) {
	// netlink convention: LinkAttrs.Name is the "primary" link, PeerName is
	// the "other end" of the pair. We make the primary the side we'll move
	// into the namespace, so the names track the action: "create the
	// inner one with its peer being the outer one; then move the inner."
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         spec.InnerName,
			HardwareAddr: spec.InnerMAC,
		},
		PeerName:         spec.OuterName,
		PeerHardwareAddr: spec.OuterMAC,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("netns: add veth %s<->%s: %w", spec.InnerName, spec.OuterName, err)
	}

	innerSide, err := netlink.LinkByName(spec.InnerName)
	if err != nil {
		return nil, fmt.Errorf("netns: lookup inner side %s: %w", spec.InnerName, err)
	}
	outerSide, err := netlink.LinkByName(spec.OuterName)
	if err != nil {
		_ = netlink.LinkDel(innerSide)
		return nil, fmt.Errorf("netns: lookup outer side %s: %w", spec.OuterName, err)
	}

	if err := netlink.LinkSetNsFd(innerSide, int(n.handle)); err != nil {
		_ = netlink.LinkDel(outerSide)
		return nil, fmt.Errorf("netns: move %s into ns: %w", spec.InnerName, err)
	}

	if err := n.Do(func() error {
		l, err := netlink.LinkByName(spec.InnerName)
		if err != nil {
			return fmt.Errorf("inner lookup: %w", err)
		}
		if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: spec.InnerIP}); err != nil {
			return fmt.Errorf("inner addr: %w", err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return fmt.Errorf("inner up: %w", err)
		}
		return nil
	}); err != nil {
		_ = netlink.LinkDel(outerSide)
		return nil, fmt.Errorf("netns: configure inner %s: %w", spec.InnerName, err)
	}

	if err := netlink.AddrAdd(outerSide, &netlink.Addr{IPNet: spec.OuterIP}); err != nil {
		_ = netlink.LinkDel(outerSide)
		return nil, fmt.Errorf("netns: outer addr on %s: %w", spec.OuterName, err)
	}
	if err := netlink.LinkSetUp(outerSide); err != nil {
		_ = netlink.LinkDel(outerSide)
		return nil, fmt.Errorf("netns: outer up on %s: %w", spec.OuterName, err)
	}
	return outerSide, nil
}
