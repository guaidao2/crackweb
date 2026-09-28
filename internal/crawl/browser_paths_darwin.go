//go:build darwin

package crawl

import (
	"os/exec"
	"path/filepath"
)

// execLookPath is exec.LookPath behind a seam, so the platform files can share
// the search logic.
func execLookPath(name string) (string, error) { return exec.LookPath(name) }

// platformChromiumPaths are the locations macOS installs a Chromium-based
// browser into. The in-bundle binary is the one to run; the app bundle itself
// is a directory and would be rejected by the runnable-file check.
func platformChromiumPaths() []string {
	system := "/Applications"
	user := homePath("Applications")

	browsers := []struct {
		bundle string
		binary string
	}{
		{"Google Chrome.app", "Google Chrome"},
		{"Chromium.app", "Chromium"},
		{"Microsoft Edge.app", "Microsoft Edge"},
		{"Brave Browser.app", "Brave Browser"},
		{"Vivaldi.app", "Vivaldi"},
	}

	var paths []string
	for _, browser := range browsers {
		for _, root := range []string{system, user} {
			if root == "" {
				continue
			}
			paths = append(paths, filepath.Join(root, browser.bundle, "Contents", "MacOS", browser.binary))
		}
	}
	return paths
}

// browserCacheGlobs are the paths browser-automation tools download Chromium
// into.
func browserCacheGlobs() []string {
	return []string{
		homePath("Library", "Caches", "ms-playwright", "*", "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium"),
		homePath("Library", "Caches", "ms-playwright", "*", "chrome-mac-arm64", "Chromium.app", "Contents", "MacOS", "Chromium"),
		homePath(".cache", "ms-playwright", "*", "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium"),
		homePath(".cache", "puppeteer", "chrome", "*", "chrome-mac-x64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
		homePath(".cache", "puppeteer", "chrome", "*", "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
	}
}
