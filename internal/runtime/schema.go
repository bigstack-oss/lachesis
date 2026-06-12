// schema.go holds package runtime's package-level constants. The Manager
// that owns runtime config state and serves the reload / debug paths lives
// in reload.go.

package runtime

// Component values for the "component" slog attribute. Reload logs
// cover the SIGHUP path; debug logs cover the /debug HTTP handlers.
const (
	componentReload = "reload"
	componentDebug  = "debug"
)

// logLevelMaxBodyBytes caps the PUT /debug/log-level request body via
// http.MaxBytesReader. The legitimate body is a one-field JSON object
// (~20 bytes); 1 KiB leaves generous slack while keeping the
// unauthenticated endpoint from buffering an attacker-sized body.
const logLevelMaxBodyBytes = 1 << 10
