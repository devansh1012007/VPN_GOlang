// Package version records build metadata (injected via -ldflags).
package version

import "fmt"

var (
	// Version is the release tag (e.g. "v1.0.0"); "dev" for untagged builds.
	Version = "v1.0.0"
	// Commit is the short git hash; "none" outside a repo.
	Commit = "none"
	// Date is the build timestamp; empty for dev builds.
	Date = ""
)

// String renders the canonical version banner.
func String() string {
	s := fmt.Sprintf("vpnd %s (commit %s)", Version, Commit)
	if Date != "" {
		s += " built " + Date
	}
	return s
}
