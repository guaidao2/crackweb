//go:build linux

package crawl

import "os/exec"

// execLookPath is exec.LookPath behind a seam, so the platform files can share
// the search logic.
func execLookPath(name string) (string, error) { return exec.LookPath(name) }

// platformChromiumPaths are the locations Linux distributions and vendors
// install a Chromium-based browser into.
func platformChromiumPaths() []string {
	return []string{
		// Distribution packages.
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/microsoft-edge",
		"/usr/bin/microsoft-edge-stable",
		"/usr/local/bin/chromium",
		"/usr/local/bin/google-chrome",
		// Vendor bundles.
		"/opt/google/chrome/chrome",
		"/opt/microsoft/msedge/msedge",
		"/usr/lib/chromium/chromium",
		"/usr/lib/chromium-browser/chromium-browser",
		// Snap and Flatpak, both of which put binaries outside PATH for
		// non-interactive shells.
		"/snap/bin/chromium",
		"/var/lib/flatpak/exports/bin/com.google.Chrome",
		"/var/lib/flatpak/exports/bin/org.chromium.Chromium",
	}
}

// browserCacheGlobs are the paths browser-automation tools download Chromium
// into. A machine that has run Playwright or Puppeteer has a usable browser
// here even when nothing is installed system-wide.
func browserCacheGlobs() []string {
	return []string{
		homePath(".cache", "ms-playwright", "*", "chrome-linux", "chrome"),
		homePath(".cache", "ms-playwright", "*", "chrome-linux", "headless_shell"),
		homePath(".cache", "puppeteer", "chrome", "*", "chrome-linux64", "chrome"),
		homePath(".cache", "puppeteer", "chrome-headless-shell", "*", "chrome-headless-shell-linux64", "chrome-headless-shell"),
		homePath(".cache", "chromedp", "*", "chromium", "*", "chrome"),
		homePath(".cache", "chromium", "*", "chrome"),
	}
}
