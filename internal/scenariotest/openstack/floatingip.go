package openstack

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/layer3/floatingips"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// CreateFIP allocates a floating IP and binds it to a port, returning
// the FIP's id and its address.
func (o *Cloud) CreateFIP(ctx context.Context, projectID string, spec scenariotest.FIPCreateSpec) (string, string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", "", err
	}
	opts := floatingips.CreateOpts{
		FloatingNetworkID: spec.ExternalNetworkID,
		PortID:            spec.PortID,
		FixedIP:           spec.FixedIP,
		FloatingIP:        spec.FloatingIP,
	}
	fip, err := floatingips.Create(ctx, sc.network, opts).Extract()
	if err != nil {
		return "", "", fmt.Errorf("openstack: allocate floating ip: %w", err)
	}
	return fip.ID, fip.FloatingIP, nil
}

func (o *Cloud) DeleteFIP(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(floatingips.Delete(ctx, sc.network, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete floating ip %s: %w", id, err)
	}
	return nil
}
