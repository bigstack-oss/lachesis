// Package docs holds no production code: this test is the docs-reference
// guard. Code comments cite documentation as repo-relative
// "docs/<path>.md#<heading-anchor>" references, and the docs cross-link
// each other with relative markdown links. Both kinds silently rot when
// a file moves or a heading is renamed — this test makes that rot a CI
// failure that names the offending citation. (Precedent: the Linux
// kernel's tools/docs/documentation-file-ref-check, extended here with
// GitHub heading-anchor validation.)
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot walks up from the package directory to the go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above package directory")
		}
		dir = parent
	}
}

// anchorsOf returns the set of GitHub heading anchors in a markdown file:
// every heading line outside fenced code blocks, slugified the way GitHub
// does (lowercase; drop everything but letters, digits, spaces, hyphens
// and underscores; spaces become hyphens).
func anchorsOf(t *testing.T, path string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	drop := regexp.MustCompile(`[^\p{L}\p{N} _-]`)
	heading := regexp.MustCompile(`^#{1,6}\s+(.*)$`)
	inline := strings.NewReplacer("`", "", "*", "", "~", "")
	link := regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)

	anchors := map[string]bool{}
	fenced := false
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		m := heading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		text := link.ReplaceAllString(m[1], "$1") // [t](u) → t
		text = inline.Replace(text)
		slug := strings.ToLower(strings.TrimSpace(text))
		slug = drop.ReplaceAllString(slug, "")
		slug = strings.ReplaceAll(slug, " ", "-")
		anchors[slug] = true
	}
	return anchors
}

// splitFragment separates "path#fragment" into its halves.
func splitFragment(ref string) (string, string) {
	if i := strings.IndexByte(ref, '#'); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// checkTarget verifies one resolved reference: the file exists and, when a
// fragment is present, the target's headings contain it.
func checkTarget(t *testing.T, root, source, absPath, fragment string, anchorCache map[string]map[string]bool) {
	t.Helper()
	info, err := os.Stat(absPath)
	if err != nil {
		t.Errorf("%s references %s: file does not exist", source, absPath)
		return
	}
	if fragment == "" || info.IsDir() {
		return
	}
	anchors, ok := anchorCache[absPath]
	if !ok {
		anchors = anchorsOf(t, absPath)
		anchorCache[absPath] = anchors
	}
	if !anchors[fragment] {
		t.Errorf("%s references %s#%s: no heading with that anchor", source, absPath, fragment)
	}
}

// TestCodeDocReferences walks our own Go and C source trees and validates
// each repo-relative docs/... citation. The walk is pinned to the source
// roots we author — a whole-repo walk would sweep up vendored material like
// the .include/ kernel headers task generate drops, whose comments mention
// external documentation paths (e.g. docs/gcc/...) that look like citations
// but aren't ours.
func TestCodeDocReferences(t *testing.T) {
	root := repoRoot(t)
	ref := regexp.MustCompile(`docs/[A-Za-z0-9_./-]+\.(?:md|html)(?:#[A-Za-z0-9_-]+)?`)
	anchorCache := map[string]map[string]bool{}
	seen := 0

	for _, top := range []string{"internal", "cmd", "bpf"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(d.Name()); ext != ".go" && ext != ".c" && ext != ".h" {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range ref.FindAllString(string(raw), -1) {
				seen++
				rel, frag := splitFragment(m)
				checkTarget(t, root, path, filepath.Join(root, rel), frag, anchorCache)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Fatal("no docs references found in any source file — the scanner is broken")
	}
	t.Logf("validated %d docs references", seen)
}

// TestMarkdownLinks walks every markdown file under docs/ (plus the root
// README) and validates each relative link — file existence always, heading
// anchors when a fragment is present. External URLs and pure fragments are
// out of scope.
func TestMarkdownLinks(t *testing.T) {
	root := repoRoot(t)
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	anchorCache := map[string]map[string]bool{}
	seen := 0

	var files []string
	err := filepath.WalkDir(filepath.Join(root, "docs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(d.Name()) == ".md" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join(root, "README.md"))

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range link.FindAllStringSubmatch(string(raw), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") || strings.HasPrefix(target, "#") {
				continue
			}
			rel, frag := splitFragment(target)
			if rel == "" {
				continue
			}
			seen++
			checkTarget(t, root, f, filepath.Join(filepath.Dir(f), rel), frag, anchorCache)
		}
	}
	if seen == 0 {
		t.Fatal("no relative links found under docs/ — the scanner is broken")
	}
	t.Logf("validated %d markdown links", seen)
}
