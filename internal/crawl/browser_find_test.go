package crawl

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFindChromiumReturnsAUsableBinary(t *testing.T) {
	path := FindChromium()
	if path == "" {
		t.Skip("no Chromium-based browser on this machine")
	}
	if !isRunnableFile(path) {
		t.Errorf("FindChromium returned %q, which is not a runnable file", path)
	}
}

// TestFindChromiumHonoursTheOverride is the escape hatch for a browser in an
// unusual place, so it has to win over everything else.
func TestFindChromiumHonoursTheOverride(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test relies on the executable bit")
	}

	dir := t.TempDir()
	fake := filepath.Join(dir, "my-browser")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake browser: %v", err)
	}

	t.Setenv("CRACKWEB_CHROME", fake)
	if got := FindChromium(); got != fake {
		t.Errorf("FindChromium() = %q, want the override %q", got, fake)
	}
}

// TestFindChromiumIgnoresABadOverride checks that a typo in the override does
// not disable crawling: the search falls through to the real browser.
func TestFindChromiumIgnoresABadOverride(t *testing.T) {
	t.Setenv("CRACKWEB_CHROME", filepath.Join(t.TempDir(), "does-not-exist"))

	found := FindChromium()
	if found == "" {
		t.Skip("no fallback browser on this machine to fall through to")
	}
	if !isRunnableFile(found) {
		t.Errorf("fallback returned %q, which is not runnable", found)
	}
}

func TestFindChromiumRejectsADirectoryOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CRACKWEB_CHROME", dir)

	if got := FindChromium(); got == dir {
		t.Error("a directory was accepted as a browser binary")
	}
}

func TestPlatformChromiumPathsAreDeclared(t *testing.T) {
	paths := platformChromiumPaths()
	if len(paths) == 0 {
		t.Fatalf("no browser locations declared for %s", runtime.GOOS)
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) && runtime.GOOS != "windows" {
			t.Errorf("path %q is not absolute", path)
		}
	}
}

func TestBrowserCacheGlobsAreDeclared(t *testing.T) {
	globs := browserCacheGlobs()
	if len(globs) == 0 {
		t.Fatalf("no browser cache locations declared for %s", runtime.GOOS)
	}
	for _, glob := range globs {
		if !filepath.IsAbs(glob) {
			t.Errorf("cache glob %q is not absolute", glob)
		}
	}
}

func TestIsRunnableFile(t *testing.T) {
	dir := t.TempDir()

	executable := filepath.Join(dir, "browser")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if runtime.GOOS != "windows" && !isRunnableFile(executable) {
		t.Error("an executable file was rejected")
	}

	plain := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if runtime.GOOS != "windows" && isRunnableFile(plain) {
		t.Error("a non-executable file was accepted")
	}

	if isRunnableFile(dir) {
		t.Error("a directory was accepted")
	}
	if isRunnableFile(filepath.Join(dir, "nope")) {
		t.Error("a missing path was accepted")
	}
}

// TestChromiumCandidatesIncludeEdge documents why Edge is in the list: a stock
// Windows machine has no Chrome, but it does have a Chromium.
func TestChromiumCandidatesIncludeEdge(t *testing.T) {
	found := false
	for _, name := range chromiumCandidates {
		if name == "msedge" {
			found = true
		}
	}
	if !found {
		t.Error("msedge is not among the candidate names; Windows machines without Chrome would not crawl")
	}
}

func TestErrNoBrowserIsDistinguishable(t *testing.T) {
	if ErrNoBrowser == nil || ErrNoBrowser.Error() == "" {
		t.Fatal("ErrNoBrowser is not usable as a sentinel")
	}
}
