// schema.go holds package scraper's package-level constants. The
// MapReader seam interface and the Scraper type live with their logic
// in scraper.go.

package scraper

// initialBufCap is the starting capacity for the per-tick BatchLookup
// buffer. Picked to cover a typical compute host's steady-state flow
// count without growing on the hot path; the map grows on demand if
// the host actually has more flows.
const initialBufCap = 1024

// componentScraper is the value of the "component" slog attribute for
// logs originating in this package.
const componentScraper = "scraper"
