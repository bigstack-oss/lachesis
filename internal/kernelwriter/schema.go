// schema.go holds package kernelwriter's package-level constants. The
// MapUpdater seam interface and the writer functions live in writer.go.

package kernelwriter

// componentKernelWriter is the slog `component` attribute used by
// log calls in this package. Matches the per-package convention
// the rest of the codebase follows.
const componentKernelWriter = "kernelwriter"
