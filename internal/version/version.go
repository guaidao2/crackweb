// Package version holds crackweb's version and authorship metadata.
//
// crackweb —— traffic-driven web DAST scanner
// Maintained by guaidao2 & coolmoon
//
// It is the single source of truth for the version string: the Makefile and the
// release workflow both read the Version constant out of this file, so a release
// only ever needs to edit one line.
package version

const (
	// Name is the executable name.
	Name = "crackweb"
	// Version is the semantic version, bumped in this file alone.
	Version = "1.3.5"
	// Authors is the authorship line shown in banners, help and reports.
	Authors = "guaidao2 & coolmoon"
	// Repo is the canonical upstream, used in help output and reports.
	Repo = "https://github.com/guaidao2/crackweb"
)

// Full returns a one-line version banner.
func Full() string {
	return Name + " v" + Version + " (by " + Authors + ")"
}
