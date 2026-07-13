// Package osclient is the shared OpenStack client bootstrap: the
// [Credentials] vocabulary, the admin-openrc parser ([ParseOpenRC]),
// and Keystone v3 authentication ([Authenticate],
// [AuthenticateProject]). It exists because the agent's Neutron
// subsystem and the scenariotest harness authenticate the same way;
// each consumer keeps its own config surface and resolves it down to
// a [Credentials] before calling in here.
//
// The package is deliberately thin: no service-client construction
// (consumers pick their own catalog services), no config-file
// knowledge (that stays with each consumer's config layer), no
// retries (gophercloud's AllowReauth handles token expiry; boot-time
// patience is the caller's policy).
package osclient

// Credentials is the resolved set of Keystone v3 password-auth
// values used to obtain a project-scoped token. Consumers produce it
// from their own config (the agent via neutron.FromConfig, the
// scenariotest harness via its OpenStackCreds) or from an
// admin-openrc-style file via [ParseOpenRC].
type Credentials struct {
	AuthURL       string
	Username      string
	Password      string
	ProjectName   string
	UserDomain    string
	ProjectDomain string
	Region        string
	// Interface is the Keystone endpoint-catalog interface to pick
	// when discovering service URLs: "public", "internal", or
	// "admin". Empty falls through to the consumer's default (see
	// [Credentials.EndpointOpts]) — compute-node agents want
	// "internal", operator tools want "public".
	Interface string
}

// defaultDomain is the Keystone v3 domain assumed for the user and
// project when an openrc file does not name one. "default" is the
// literal domain name every stock OpenStack deployment ships with.
const defaultDomain = "default"
