package crawl

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// chromiumCandidates are the binary names looked for on PATH, in order of
// preference. Edge is included because it is a Chromium build and is the one
// browser that is present on a stock Windows install.
var chromiumCandidates = []string{
	"chromium",
	"chromium-browser",
	"google-chrome",
	"google-chrome-stable",
	"chrome",
	"headless_shell",
	"msedge",
	"microsoft-edge",
	"microsoft-edge-stable",
}

// FindChromium locates a Chromium-based browser.
//
// The search order is deliberate. An explicit CRACKWEB_CHROME wins, so a user
// with a browser in an unusual place is never second-guessed. PATH comes next,
// because that is what a package manager install produces. Then the locations
// each platform actually uses, and finally the browser caches left behind by
// Playwright and Puppeteer — a developer machine often has a perfectly good
// Chromium there and nothing on PATH.
//
// An empty result is not an error: the caller degrades to the HTTP engine,
// which needs no browser at all.
func FindChromium() string {
	if override := strings.TrimSpace(os.Getenv("CRACKWEB_CHROME")); override != "" {
		if isRunnableFile(override) {
			return override
		}
		// An override that does not exist is worth reporting, but it should not
		// stop the search: a typo should not disable crawling entirely.
	}

	for _, name := range chromiumCandidates {
		if path, err := execLookPath(name); err == nil && isRunnableFile(path) {
			return path
		}
	}

	for _, path := range platformChromiumPaths() {
		if isRunnableFile(path) {
			return path
		}
	}

	for _, pattern := range browserCacheGlobs() {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		// Newest-looking first: version directories sort lexically, and the
		// last one is usually the most recent download.
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		for _, match := range matches {
			if isRunnableFile(match) {
				return match
			}
		}
	}

	return ""
}

// isRunnableFile reports whether a path names something that could be a
// browser binary: it exists, it is not a directory, and on platforms with an
// executable bit it is set.
func isRunnableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		// Windows has no executable bit to check.
		return true
	}
	return info.Mode()&0o111 != 0
}

// homePath joins a path onto the user's home directory, tolerating a missing
// HOME.
func homePath(parts ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home}, parts...)...)
}

// envPath joins a path onto an environment variable, tolerating it being unset.
func envPath(variable string, parts ...string) string {
	base := os.Getenv(variable)
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base}, parts...)...)
}
