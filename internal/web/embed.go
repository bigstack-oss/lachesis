// Package web bundles the static UI assets — HTML templates and
// vendored JavaScript — the agent's /debug pages render. The
// assets are baked into the binary via [embed]; nothing here is
// loaded from disk at runtime so the agent stays a single-binary
// deploy on air-gapped hosts.
//
// The package is intentionally consumer-agnostic: it exposes
// [embed.FS] handles rather than parsed templates so callers
// register their own [template.FuncMap] before parsing.
package web

import "embed"

// Templates contains the HTML templates rendered by the /debug
// handlers in the agent package. Each template file lives under
// `templates/` and is parsed by its consumer.
//
//go:embed templates/*.html
var Templates embed.FS
