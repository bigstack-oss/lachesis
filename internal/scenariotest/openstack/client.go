// Package openstack is the gophercloud-backed [scenariotest.Cloud]:
// every live OpenStack call the harness makes to realize, mutate and
// tear down a scenario's topology.
//
// The surface is split by service — [identity.go] for Keystone,
// [network.go] for Neutron's networks/subnets/ports, [router.go] for
// its layer-3 extension, [floatingip.go] for FIPs, [compute.go] for
// Nova — so a reader looking for "how does the harness boot a server"
// opens one file rather than scrolling one API façade.
//
// One of scenariotest's leaf driver packages: it depends on the core
// harness for the spec types and on internal/osclient for the Keystone
// bootstrap. The core never imports it.
package openstack

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	gcopenstack "github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"

	"github.com/bigstack-oss/lachesis/internal/osclient"
	"github.com/bigstack-oss/lachesis/internal/scenariotest"
)

// Cloud is the gophercloud-backed [scenariotest.Cloud]. It holds
// admin-scoped service clients plus a cache of per-project-scoped
// Network/Compute clients, minted lazily by re-authenticating the admin
// credentials scoped to the target project (see
// [osclient.AuthenticateProject]). Used single-threaded by realize, so
// the scoped-client cache needs no locking.
type Cloud struct {
	creds   osclient.Credentials
	timeout time.Duration
	eo      gophercloud.EndpointOpts
	log     *slog.Logger

	identity *gophercloud.ServiceClient
	network  *gophercloud.ServiceClient
	compute  *gophercloud.ServiceClient
	image    *gophercloud.ServiceClient

	userID      string // authenticated admin user, for role grants
	adminRoleID string // resolved lazily on first GrantAdminRole

	scoped map[string]*scopedClients
}

type scopedClients struct {
	network *gophercloud.ServiceClient
	compute *gophercloud.ServiceClient
}

// New resolves the config's two-mode credentials, authenticates
// (admin, scoped to the credential's own project), and returns a ready
// [scenariotest.Cloud]. The endpoint-catalog interface defaults to
// "public" — scenariotest is an operator-facing tool, not a
// compute-node agent. log (nil = discard) receives one
// [scenariotest.LevelTrace] line per API call.
func New(ctx context.Context, oc scenariotest.OpenStackCreds, log *slog.Logger) (*Cloud, error) {
	creds, err := oc.ResolveCredentials()
	if err != nil {
		return nil, err
	}
	eo, err := creds.EndpointOpts("public")
	if err != nil {
		return nil, fmt.Errorf("openstack: %w", err)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	o := &Cloud{
		creds:   creds,
		timeout: oc.RequestTimeout,
		eo:      eo,
		log:     log,
		scoped:  map[string]*scopedClients{},
	}

	provider, err := osclient.Authenticate(ctx, creds)
	if err != nil {
		return nil, fmt.Errorf("openstack: %w", err)
	}
	o.applyTimeout(provider)

	ar := provider.GetAuthResult()
	ctr, ok := ar.(tokens.CreateResult)
	if !ok {
		return nil, fmt.Errorf("openstack: unexpected auth result %T (want identity v3 token)", ar)
	}
	user, err := ctr.ExtractUser()
	if err != nil {
		return nil, fmt.Errorf("openstack: extract auth user: %w", err)
	}
	o.userID = user.ID

	if o.identity, err = gcopenstack.NewIdentityV3(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: identity endpoint: %w", err)
	}
	if o.network, err = gcopenstack.NewNetworkV2(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: network endpoint: %w", err)
	}
	if o.compute, err = gcopenstack.NewComputeV2(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: compute endpoint: %w", err)
	}
	if o.image, err = gcopenstack.NewImageV2(provider, o.eo); err != nil {
		return nil, fmt.Errorf("openstack: image endpoint: %w", err)
	}
	return o, nil
}

// applyTimeout caps every request on the provider with the config's
// request_timeout and installs the wire-trace transport. osclient
// deliberately leaves HTTP-client policy to its consumers.
func (o *Cloud) applyTimeout(provider *gophercloud.ProviderClient) {
	provider.HTTPClient = http.Client{
		Timeout:   o.timeout, // zero = unbounded, as before
		Transport: scenariotest.NewTraceTransport(nil, o.log),
	}
}

// scopedFor returns Network/Compute clients whose token is scoped to
// projectID, minting and caching them on first use. The admin user
// must already hold a role on projectID (see [Cloud.GrantAdminRole]).
func (o *Cloud) scopedFor(ctx context.Context, projectID string) (*scopedClients, error) {
	if sc, ok := o.scoped[projectID]; ok {
		return sc, nil
	}
	provider, err := osclient.AuthenticateProject(ctx, o.creds, projectID)
	if err != nil {
		return nil, fmt.Errorf("openstack: scope to project %s: %w", projectID, err)
	}
	o.applyTimeout(provider)
	net, err := gcopenstack.NewNetworkV2(provider, o.eo)
	if err != nil {
		return nil, fmt.Errorf("openstack: scoped network endpoint: %w", err)
	}
	comp, err := gcopenstack.NewComputeV2(provider, o.eo)
	if err != nil {
		return nil, fmt.Errorf("openstack: scoped compute endpoint: %w", err)
	}
	sc := &scopedClients{network: net, compute: comp}
	o.scoped[projectID] = sc
	return sc, nil
}

// ignoreNotFound swallows 404s so deletes are idempotent: removing a
// resource that is already gone is success, and a re-run of `down`
// converges instead of failing on the survivors of a partial pass.
func ignoreNotFound(err error) error {
	if err == nil || gophercloud.ResponseCodeIs(err, http.StatusNotFound) {
		return nil
	}
	return err
}
