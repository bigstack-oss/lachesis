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
