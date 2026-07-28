package openstack

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/attachinterfaces"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/hypervisors"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/keypairs"
	"github.com/gophercloud/gophercloud/v2/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"

	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// serverPollInterval is how often [Cloud.WaitServerActive] re-checks a
// booting server. Boot on a real cluster takes tens of seconds, so a
// few seconds between polls keeps Nova load low without adding
// meaningful latency.
const serverPollInterval = 3 * time.Second

// --- prerequisite + placement lookups ---

func (o *Cloud) FindImage(ctx context.Context, name string) (string, error) {
	pages, err := images.List(o.image, images.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list images: %w", err)
	}
	all, err := images.ExtractImages(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract images: %w", err)
	}
	if len(all) == 0 {
		return "", fmt.Errorf("openstack: image %q not found", name)
	}
	return all[0].ID, nil
}

func (o *Cloud) FindFlavor(ctx context.Context, name string) (string, error) {
	pages, err := flavors.ListDetail(o.compute, flavors.ListOpts{}).AllPages(ctx)
	if err != nil {
		return "", fmt.Errorf("openstack: list flavors: %w", err)
	}
	all, err := flavors.ExtractFlavors(pages)
	if err != nil {
		return "", fmt.Errorf("openstack: extract flavors: %w", err)
	}
	for _, f := range all {
		if f.Name == name {
			return f.ID, nil
		}
	}
	return "", fmt.Errorf("openstack: flavor %q not found", name)
}

func (o *Cloud) CheckKeypair(ctx context.Context, name string) error {
	if _, err := keypairs.Get(ctx, o.compute, name, keypairs.GetOpts{}).Extract(); err != nil {
		return fmt.Errorf("openstack: keypair %q: %w", name, err)
	}
	return nil
}

func (o *Cloud) Hypervisors(ctx context.Context) ([]string, error) {
	pages, err := hypervisors.List(o.compute, hypervisors.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("openstack: list hypervisors: %w", err)
	}
	all, err := hypervisors.ExtractHypervisors(pages)
	if err != nil {
		return nil, fmt.Errorf("openstack: extract hypervisors: %w", err)
	}
	hosts := make([]string, 0, len(all))
	for _, h := range all {
		hosts = append(hosts, h.HypervisorHostname)
	}
	return hosts, nil
}

// --- servers ---

func (o *Cloud) CreateServer(ctx context.Context, projectID string, spec scenariotest.ServerSpec) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	nics := []servers.Network{{Port: spec.PortID}}
	for _, extra := range spec.ExtraPortIDs {
		nics = append(nics, servers.Network{Port: extra})
	}
	base := servers.CreateOpts{
		Name:             spec.Name,
		FlavorRef:        spec.FlavorID,
		ImageRef:         spec.ImageID,
		Networks:         nics,
		AvailabilityZone: spec.AvailabilityZone,
	}
	var opts servers.CreateOptsBuilder = base
	if spec.KeypairName != "" {
		opts = keypairs.CreateOptsExt{CreateOptsBuilder: base, KeyName: spec.KeypairName}
	}
	s, err := servers.Create(ctx, sc.compute, opts, nil).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: boot server %q: %w", spec.Name, err)
	}
	return s.ID, nil
}

func (o *Cloud) WaitServerActive(ctx context.Context, projectID, serverID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(serverPollInterval)
	defer ticker.Stop()
	for {
		s, err := servers.Get(ctx, sc.compute, serverID).Extract()
		if err != nil {
			return fmt.Errorf("openstack: get server %s: %w", serverID, err)
		}
		switch s.Status {
		case "ACTIVE":
			return nil
		case "ERROR":
			return fmt.Errorf("openstack: server %s entered ERROR state", serverID)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("openstack: server %s not ACTIVE before deadline (last status %q): %w", serverID, s.Status, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (o *Cloud) ServerHost(ctx context.Context, projectID, serverID string) (string, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return "", err
	}
	s, err := servers.Get(ctx, sc.compute, serverID).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: get server %s: %w", serverID, err)
	}
	if s.Host == "" {
		return "", fmt.Errorf("openstack: server %s exposes no OS-EXT-SRV-ATTR:host (token lacks admin?)", serverID)
	}
	return s.Host, nil
}

func (o *Cloud) LiveMigrateServer(ctx context.Context, projectID, serverID, targetHost string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	// At the default compute microversion os-migrateLive REQUIRES
	// block_migration and disk_over_commit — omitting them is a 400,
	// not a default (found live). False/false is correct for the
	// shared-storage (CephFS instances dir) clusters this harness
	// targets; a block-migration cluster would need a knob nobody has
	// asked for yet.
	no := false
	opts := servers.LiveMigrateOpts{BlockMigration: &no, DiskOverCommit: &no}
	if targetHost != "" {
		opts.Host = &targetHost
	}
	if err := servers.LiveMigrate(ctx, sc.compute, serverID, opts).ExtractErr(); err != nil {
		return fmt.Errorf("openstack: live-migrate server %s: %w", serverID, err)
	}
	return nil
}

// ListProjectServers lists servers through a token scoped to
// projectID, so the returned set is exactly that project's servers —
// never another tenant's. It does no name filtering: `down` owns the
// exact-prefix match, keeping the collision-safety discipline in one
// place. Backs the residual server sweep for a boot Nova accepted in
// the create→save window.
func (o *Cloud) ListProjectServers(ctx context.Context, projectID string) ([]scenariotest.ServerRef, error) {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return nil, err
	}
	pages, err := servers.List(sc.compute, servers.ListOpts{}).AllPages(ctx)
	if err != nil {
		return nil, fmt.Errorf("openstack: list servers in project %s: %w", projectID, err)
	}
	all, err := servers.ExtractServers(pages)
	if err != nil {
		return nil, fmt.Errorf("openstack: extract servers: %w", err)
	}
	refs := make([]scenariotest.ServerRef, 0, len(all))
	for _, s := range all {
		refs = append(refs, scenariotest.ServerRef{ID: s.ID, Name: s.Name})
	}
	return refs, nil
}

// --- NIC hot-plug ---

func (o *Cloud) AttachInterface(ctx context.Context, projectID, serverID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	opts := attachinterfaces.CreateOpts{PortID: portID}
	if _, err := attachinterfaces.Create(ctx, sc.compute, serverID, opts).Extract(); err != nil {
		return fmt.Errorf("openstack: attach port %s to server %s: %w", portID, serverID, err)
	}
	return nil
}

func (o *Cloud) DetachInterface(ctx context.Context, projectID, serverID, portID string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := attachinterfaces.Delete(ctx, sc.compute, serverID, portID).ExtractErr(); err != nil {
		return fmt.Errorf("openstack: detach port %s from server %s: %w", portID, serverID, err)
	}
	return nil
}

// --- teardown ---

func (o *Cloud) DeleteServer(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	if err := ignoreNotFound(servers.Delete(ctx, sc.compute, id).ExtractErr()); err != nil {
		return fmt.Errorf("openstack: delete server %s: %w", id, err)
	}
	return nil
}

func (o *Cloud) WaitServerGone(ctx context.Context, projectID, id string) error {
	sc, err := o.scopedFor(ctx, projectID)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(serverPollInterval)
	defer ticker.Stop()
	for {
		_, err := servers.Get(ctx, sc.compute, id).Extract()
		if gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("openstack: poll server %s: %w", id, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("openstack: server %s still present at deadline: %w", id, ctx.Err())
		case <-ticker.C:
		}
	}
}
