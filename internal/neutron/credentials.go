// credentials.go maps the agent's [config.NeutronConfig] onto the
// shared [osclient.Credentials]: inline fields copy over directly,
// and the credentials_file mode delegates to [osclient.ParseOpenRC].

package neutron

import (
	"github.com/bigstack-oss/lachesis/internal/config"
	"github.com/bigstack-oss/lachesis/internal/osclient"
)

// Credentials is the resolved set of Keystone v3 password-auth
// values the agent authenticates with — the shared
// [osclient.Credentials], aliased so this package's API reads in its
// own vocabulary.
type Credentials = osclient.Credentials

// FromConfig resolves Credentials from a [config.NeutronConfig].
// The caller is expected to have run [config.NeutronConfig.Validate]
// already, so the exactly-one-of constraint is asserted rather than
// re-validated.
func FromConfig(c config.NeutronConfig) (Credentials, error) {
	if c.CredentialsFile != "" {
		return osclient.ParseOpenRC(c.CredentialsFile)
	}
	return Credentials{
		AuthURL:       c.AuthURL,
		Username:      c.Username,
		Password:      c.Password,
		ProjectName:   c.ProjectName,
		UserDomain:    c.UserDomain,
		ProjectDomain: c.ProjectDomain,
		Region:        c.Region,
		Interface:     c.Interface,
	}, nil
}
