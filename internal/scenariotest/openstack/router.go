package openstack

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/routers"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

func (o *Cloud) CreateRouter(ctx context.Context, projectID string, spec scenariotest.RouterSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	up := true
	opts := routers.CreateOpts{Name: spec.Name, AdminStateUp: &up}
	if spec.ExternalNetworkID != "" {
		opts.GatewayInfo = &routers.GatewayInfo{NetworkID: spec.ExternalNetworkID}
	}
	r, err := routers.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create router %q: %w", spec.Name, err)
	}
	return r.ID, nil
}

func (o *Cloud) AddRouterInterface(ctx context.Context, projectID, routerID, subnetID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	_, err = routers.AddInterface(ctx, sc.network, routerID, routers.AddInterfaceOpts{
		SubnetID: subnetID,
		PortID:   portID,
	}).Extract()
	if err != nil {
		return fmt.Errorf("openstack: add interface (router %s, subnet %q, port %q): %w", routerID, subnetID, portID, err)
	}
	return nil
}

func (o *Cloud) SetRouterRoutes(ctx context.Context, projectID, routerID string, routes []scenariotest.RouteSpec) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	rs := make([]routers.Route, len(routes))
	for i, r := range routes {
		rs[i] = routers.Route{DestinationCIDR: r.Destination, NextHop: r.Nexthop}
	}
	_, err = routers.Update(ctx, sc.network, routerID, routers.UpdateOpts{Routes: &rs}).Extract()
	if err != nil {
		return fmt.Errorf("openstack: set routes on router %s: %w", routerID, err)
	}
	return nil
}

// SetRouterGateway replaces a router's external gateway network — the
// re-gateway mutation of the router-regateway scenario. Empty
// externalNetworkID clears the gateway.
func (o *Cloud) SetRouterGateway(ctx context.Context, projectID, routerID, externalNetworkID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	var gw *routers.GatewayInfo
	if externalNetworkID != "" {
		gw = &routers.GatewayInfo{NetworkID: externalNetworkID}
	}
	_, err = routers.Update(ctx, sc.network, routerID, routers.UpdateOpts{GatewayInfo: gw}).Extract()
	if err != nil {
		return fmt.Errorf("openstack: set gateway on router %s: %w", routerID, err)
	}
	return nil
}

// --- teardown ---

func (o *Cloud) ClearRouterRoutes(ctx context.Context, projectID, routerID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	// Must be a non-nil empty slice: it marshals to "routes": [], which
	// clears. A nil slice would send "routes": null and leave them —
	// and that only ever surfaces live, as a 409 on the next detach.
	empty := []routers.Route{}
	_, err = routers.Update(ctx, sc.network, routerID, routers.UpdateOpts{Routes: &empty}).Extract()
	if err := ignoreNotFound(err); err != nil {
		return fmt.Errorf("openstack: clear routes on router %s: %w", routerID, err)
	}
	return nil
}

func (o *Cloud) RemoveRouterInterface(ctx context.Context, projectID, routerID, subnetID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	_, err = routers.RemoveInterface(ctx, sc.network, routerID, routers.RemoveInterfaceOpts{
		SubnetID: subnetID,
		PortID:   portID,
	}).Extract()
	if err := ignoreNotFound(err); err != nil {
		return fmt.Errorf("openstack: remove interface (router %s, subnet %q, port %q): %w", routerID, subnetID, portID, err)
	}
	return nil
}

func (o *Cloud) DeleteRouter(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(routers.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete router %s: %w", id, err)
	}
	return nil
}
