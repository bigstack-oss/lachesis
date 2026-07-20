// schema.go gathers package config's package-level constants: the schema
// version, the default environment-variable prefix, the JSON secret
// placeholder, and the env-var name suffixes shared between applyEnv and
// applyFlags (load.go). The section
// types keep the documented one-file-per-section layout (http.go, bpf.go,
// scrape.go, logging.go, wal.go, neutron.go), each owning its own defaults
// helper and Validate method.

package config

// Version is the configuration schema version this binary understands.
// Bumped only on breaking schema changes; consumers gate on it.
const Version = "1"

// DefaultEnvPrefix is used when [Options.EnvPrefix] is empty.
const DefaultEnvPrefix = "LACHESIS"

// redactedSecret is what secret fields serialize as in JSON
// ([NeutronConfig.MarshalJSON]), keeping credentials off the
// unauthenticated /debug/config wire.
const redactedSecret = "***"

// Environment-variable name suffixes. applyEnv reads <prefix>_<suffix>
// and applyFlags' envHint advertises the same <prefix>_<suffix> in
// `-help`; declaring each suffix once keeps the two bindings and the
// error messages in lockstep. The flag names (kebab-case) are single-use
// and stay at their binding sites in load.go.
const (
	envConfig                            = "CONFIG"
	envHTTPListen                        = "HTTP_LISTEN"
	envBPFPinPath                        = "BPF_PIN_PATH"
	envBPFAttachPrefixes                 = "BPF_ATTACH_PREFIXES"
	envBPFAttachInterfaces               = "BPF_ATTACH_INTERFACES"
	envBPFUnsafeAllowUnpinnedMaps        = "BPF_UNSAFE_ALLOW_UNPINNED_MAPS"
	envScrapeInterval                    = "SCRAPE_INTERVAL"
	envLogLevel                          = "LOG_LEVEL"
	envLogFormat                         = "LOG_FORMAT"
	envWALPath                           = "WAL_PATH"
	envWALFlushInterval                  = "WAL_FLUSH_INTERVAL"
	envWALEnabled                        = "WAL_ENABLED"
	envNeutronEnabled                    = "NEUTRON_ENABLED"
	envNeutronCredentialsFile            = "NEUTRON_CREDENTIALS_FILE"
	envNeutronUnsafeAllowAmbiguousRoutes = "NEUTRON_UNSAFE_ALLOW_AMBIGUOUS_ROUTES"
	envKafkaEnabled                      = "KAFKA_ENABLED"
	envKafkaBrokers                      = "KAFKA_BROKERS"
)
