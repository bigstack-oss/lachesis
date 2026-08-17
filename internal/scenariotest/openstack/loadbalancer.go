// loadbalancer.go is the Octavia half of the driver: creating a load
// balancer with its listener, pool and members, waiting for each
// mutation to settle, reading back the Amphorae, and the cascade delete
// that reclaims the Amphora VMs. See docs/architecture/octavia.md for
// why the harness needs to drive Octavia at all.

package openstack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/amphorae"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// errNoOctavia is returned by every load-balancer call when the
// Keystone catalog carried no Octavia endpoint. Distinct message so a
// scenario author sees "this cluster has no Octavia" rather than a
// nil-pointer panic.
var errNoOctavia = errors.New("openstack: no octavia endpoint in the catalog")

// lbProvisioningActive / lbProvisioningError are the Octavia
// provisioning_status values [Cloud.WaitLBActive] settles on. Every
// other value (PENDING_CREATE, PENDING_UPDATE, …) means keep polling.
const (
	lbProvisioningActive = "ACTIVE"
	lbProvisioningError  = "ERROR"
)

// lbPollInterval is how often WaitLBActive re-reads the load balancer.
// Amphora boots take tens of seconds, so a tight poll buys nothing and
// a slow one adds latency to every mutation; 5s matches the cadence the
// compute waiters use.
const lbPollInterval = 5 * time.Second

// FindLBFlavor resolves an Octavia load-balancer flavor by exact name.
// Listing and filtering client-side rather than by query parameter:
// Octavia's flavor list is a handful of rows, and the exact-match
// semantics stay identical to [Cloud.FindFlavor].
func (o *Cloud) FindLBFlavor(ctx context.Context, name string) (string, error) {
	if o.loadbalancer == nil {
		return "", errNoOctavia
	}
	pages, err := flavors.List(o.loadbalancer, flavors.ListOpts{}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list lb flavors: %w", err)
	}
	all, err := flavors.ExtractFlavors(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract lb flavors: %w", err)
	}
	for _, f := range all {
		if f.Name == name {
			if !f.Enabled {
				return "", fmt.Errorf("openstack: lb flavor %q is disabled", name)
			}
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("openstack: lb flavor %q not found", name)
}

// CreateLoadBalancer creates a load balancer in projectID and returns
// its ID and the VIP address Octavia assigned. It does NOT wait — the
// caller pairs it with [Cloud.WaitLBActive], because realize wants the
// id recorded in run-state before the multi-minute Amphora boot starts.
func (o *Cloud) CreateLoadBalancer(ctx context.Context, projectID string, spec scenariotest.LBSpec) (string, string, string, error) {
	cli, err := o.lbClient(ctx, projectID)
	if err != nil {
		return "", "", "", err
	}
	opts := loadbalancers.CreateOpts{
		Name:        spec.Name,
		VipSubnetID: spec.VIPSubnetID,
		AdminStateUp: func() *bool {
			up := true
			return &up
		}(),
	}
	if spec.FlavorID != "" {
		opts.FlavorID = spec.FlavorID
	}
	lb, err := loadbalancers.Create(ctx, cli, opts).Extract()
	if err != nil {
		return "", "", "", fmt.Errorf("openstack: create load balancer %s: %w", spec.Name, err)
	}
	return lb.ID, lb.VipAddress, lb.VipPortID, nil
}

// CreateListener adds a listener and waits for the load balancer to
// settle: Octavia rejects a second mutation while one is in flight.
func (o *Cloud) CreateListener(ctx context.Context, projectID string, spec scenariotest.ListenerSpec) (string, error) {
	cli, err := o.lbClient(ctx, projectID)
	if err != nil {
		return "", err
	}
	l, err := listeners.Create(ctx, cli, listeners.CreateOpts{
		Name:           spec.Name,
		LoadbalancerID: spec.LoadBalancerID,
		Protocol:       listeners.Protocol(spec.Protocol),
		ProtocolPort:   spec.ProtocolPort,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create listener %s: %w", spec.Name, err)
	}
	if err := o.WaitLBActive(ctx, projectID, spec.LoadBalancerID); err != nil {
		return l.ID, err
	}
	return l.ID, nil
}

// CreatePool adds a backend pool to a listener. As with
// [Cloud.CreateListener] it settles before returning.
func (o *Cloud) CreatePool(ctx context.Context, projectID string, spec scenariotest.PoolSpec) (string, error) {
	cli, err := o.lbClient(ctx, projectID)
	if err != nil {
		return "", err
	}
	p, err := pools.Create(ctx, cli, pools.CreateOpts{
		Name:        spec.Name,
		ListenerID:  spec.ListenerID,
		Protocol:    pools.Protocol(spec.Protocol),
		LBMethod:    pools.LBMethod(spec.LBAlgorithm),
		Persistence: nil,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create pool %s: %w", spec.Name, err)
	}
	if len(p.Loadbalancers) == 0 {
		// Pools created through a listener still report their parent; if
		// Octavia ever omits it, settling is the caller's job via the
		// load-balancer id it already holds.
		return p.ID, nil
	}
	if err := o.WaitLBActive(ctx, projectID, p.Loadbalancers[0].ID); err != nil {
		return p.ID, err
	}
	return p.ID, nil
}

// CreateMember adds one backend to a pool and settles.
//
// Naming a SubnetID the Amphora is not attached to makes Octavia plug
// it into that network — a Nova interface-attach, which needs a free
// PCIe slot on the Amphora guest. On a cluster whose computes leave
// nova.conf's [libvirt] num_pcie_ports unset the Amphora boots with no
// spare slots and the plug fails with "No more available PCI slots";
// the member then lands in ERROR while the load balancer stays ACTIVE,
// which is why the caller checks member status rather than trusting the
// LB's.
func (o *Cloud) CreateMember(ctx context.Context, projectID string, spec scenariotest.MemberSpec) (string, error) {
	cli, err := o.lbClient(ctx, projectID)
	if err != nil {
		return "", err
	}
	m, err := pools.CreateMember(ctx, cli, spec.PoolID, pools.CreateMemberOpts{
		Name:         spec.Name,
		Address:      spec.Address,
		ProtocolPort: spec.ProtocolPort,
		SubnetID:     spec.SubnetID,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create member %s: %w", spec.Address, err)
	}
	return m.ID, nil
}

// WaitLBActive polls until the load balancer reports ACTIVE, fails fast
// on ERROR, and surfaces the last seen status when the context expires
// so a timeout says what it was still waiting on.
func (o *Cloud) WaitLBActive(ctx context.Context, projectID, lbID string) error {
	cli, err := o.lbClient(ctx, projectID)
	if err != nil {
		return err
	}
	last := "unknown"
	for {
		lb, err := loadbalancers.Get(ctx, cli, lbID).Extract()
		if err != nil {
			return fmt.Errorf("openstack: get load balancer %s: %w", lbID, err)
		}
		last = lb.ProvisioningStatus
		switch last {
		case lbProvisioningActive:
			return nil
		case lbProvisioningError:
			return fmt.Errorf("openstack: load balancer %s went ERROR", lbID)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("openstack: load balancer %s still %s: %w", lbID, last, ctx.Err())
		case <-time.After(lbPollInterval):
		}
	}
}

// ListAmphorae returns the Amphorae serving lbID. Admin-scoped: the
// amphora API is operator-only, and the harness authenticates as admin.
func (o *Cloud) ListAmphorae(ctx context.Context, lbID string) ([]scenariotest.AmphoraRef, error) {
	if o.loadbalancer == nil {
		return nil, errNoOctavia
	}
	pages, err := amphorae.List(o.loadbalancer, amphorae.ListOpts{LoadbalancerID: lbID}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("openstack: list amphorae for %s: %w", lbID, err)
	}
	all, err := amphorae.ExtractAmphorae(pages)
	if err != nil {
		return nil, fmt.Errorf("openstack: extract amphorae: %w", err)
	}
	out := make([]scenariotest.AmphoraRef, 0, len(all))
	for _, a := range all {
		out = append(out, scenariotest.AmphoraRef{
			ID:          a.ID,
			ComputeID:   a.ComputeID,
			LBNetworkIP: a.LBNetworkIP,
			Role:        a.Role,
		})
	}
	return out, nil
}

// DeleteLoadBalancer cascade-deletes a load balancer and waits for it
// to disappear. 404-tolerant like every other teardown verb, so a
// re-run of `down` converges.
//
// Cascade is not an optimisation: Octavia owns the Amphora VMs and
// their Neutron ports, and deleting those directly would leave its
// records dangling with no way to reclaim them.
func (o *Cloud) DeleteLoadBalancer(ctx context.Context, projectID, id string) error {
	cli, err := o.lbClient(ctx, projectID)
	if err != nil {
		return err
	}
	if err := loadbalancers.Delete(ctx, cli, id, loadbalancers.DeleteOpts{Cascade: true}).ExtractErr(); err != nil {
		return ignoreNotFound(err)
	}
	for {
		_, err := loadbalancers.Get(ctx, cli, id).Extract()
		if err != nil {
			if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
				return nil
			}
			return fmt.Errorf("openstack: await load balancer %s deletion: %w", id, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("openstack: load balancer %s not gone: %w", id, ctx.Err())
		case <-time.After(lbPollInterval):
		}
	}
}

// lbClient returns the Octavia client scoped to projectID, so created
// load balancers are owned by the tenant rather than by admin — the
// ownership the attribution join reads. Falls back to the admin client
// only for the read-only calls that take no project.
func (o *Cloud) lbClient(ctx context.Context, projectID string) (*gophercloud.ServiceClient, error) {
	if o.loadbalancer == nil {
		return nil, errNoOctavia
	}
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if sc.loadbalancer == nil {
		return nil, errNoOctavia
	}
	return sc.loadbalancer, nil
}
