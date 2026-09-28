//go:build windows

package crawl

import (
	"os/exec"
	"path/filepath"
)

// execLookPath is exec.LookPath behind a seam, so the platform files can share
// the search logic.
func execLookPath(name string) (string, error) { return exec.LookPath(name) }

// platformChromiumPaths are the locations Windows installs a Chromium-based
// browser into.
//
// Edge leads the list because it ships with Windows: a machine with no
// developer tooling at all still has a usable Chromium there, which makes the
// headless engine work out of the box rather than after an install.
func platformChromiumPaths() []string {
	type location struct {
		env     string
		subpath []string
	}

	candidates := []location{
		{"ProgramFiles", []string{"Microsoft", "Edge", "Application", "msedge.exe"}},
		{"ProgramFiles(x86)", []string{"Microsoft", "Edge", "Application", "msedge.exe"}},
		{"ProgramFiles", []string{"Google", "Chrome", "Application", "chrome.exe"}},
		{"ProgramFiles(x86)", []string{"Google", "Chrome", "Application", "chrome.exe"}},
		{"LOCALAPPDATA", []string{"Google", "Chrome", "Application", "chrome.exe"}},
		{"ProgramFiles", []string{"Chromium", "Application", "chrome.exe"}},
		{"ProgramFiles", []string{"BraveSoftware", "Brave-Browser", "Application", "brave.exe"}},
		{"LOCALAPPDATA", []string{"Microsoft", "Edge", "Application", "msedge.exe"}},
	}

	var paths []string
	for _, candidate := range candidates {
		if path := envPath(candidate.env, candidate.subpath...); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

// browserCacheGlobs are the paths browser-automation tools download Chromium
// into. The nested directory layout differs between Puppeteer versions, so both
// the "chrome-win64" and older flat spellings are covered.
func browserCacheGlobs() []string {
	return []string{
		homePath("AppData", "Local", "ms-playwright", "*", "chrome-win", "chrome.exe"),
		envPath("LOCALAPPDATA", "ms-playwright", "*", "chrome-win", "chrome.exe"),
		homePath(".cache", "puppeteer", "chrome", "*", "chrome-win64", "chrome.exe"),
		envPath("LOCALAPPDATA", "puppeteer", "chrome", "*", "chrome-win64", "chrome.exe"),
		filepath.Join("C:\\", "Program Files", "Google", "Chrome", "Application", "chrome.exe"),
	}
}
