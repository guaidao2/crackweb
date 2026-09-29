package passive

import (
	"strings"
	"testing"
)

func TestLibraryIdentifiedFromItsOwnAddress(t *testing.T) {
	tg := responseTarget(t, "http://example.com/static/js/jquery_1.10.2/jquery.min.js",
		"application/javascript", "/* jQuery 1.10.2 */")

	findings := runPassive(t, vulnerableLibrary{}, tg)
	// 1.10.2 falls inside two published ranges, and each is its own finding.
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	titles := findings[0].Title + " " + findings[1].Title
	for _, want := range []string{"jQuery 1.10.2", "CVE-2020-11022", "CVE-2019-11358"} {
		if !strings.Contains(titles, want) {
			t.Errorf("the title is missing %q: %s", want, titles)
		}
	}
	if findings[0].CWE != "CWE-1395" {
		t.Errorf("CWE = %q, want CWE-1395", findings[0].CWE)
	}
}

func TestLibraryIdentifiedFromItsVersionBanner(t *testing.T) {
	// 3.4.1 is inside the 1.0.3–3.5.0 range and outside the 1.0.0–3.4.0 one, which is
	// exactly the boundary worth pinning down.
	tg := responseTarget(t, "http://example.com/assets/lib.js", "application/javascript",
		"/*! jQuery v3.4.1 | (c) OpenJS Foundation and other contributors */\nvar e=function(){};")

	findings := runPassive(t, vulnerableLibrary{}, tg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Title, "CVE-2020-11022") {
		t.Errorf("wrong advisory: %s", findings[0].Title)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "fixed in 3.5.0") {
		t.Errorf("the fix version is missing from the evidence: %v", findings[0].Evidence.Matches)
	}
}

func TestLibraryIdentifiedFromAPagesScriptTag(t *testing.T) {
	tg := responseTarget(t, "http://example.com/", "text/html",
		`<html><head><script src="/static/js/jquery-1.10.2.min.js"></script>`+
			`<link rel="stylesheet" href="/assets/bootstrap-4.3.1.min.css"></head></html>`)

	titles := ""
	for _, f := range runPassive(t, vulnerableLibrary{}, tg) {
		titles += f.Title + " "
	}
	for _, want := range []string{"jQuery 1.10.2", "Bootstrap 4.3.1"} {
		if !strings.Contains(titles, want) {
			t.Errorf("the page's %s was not reported: %s", want, titles)
		}
	}
}

func TestFixedVersionsAreNotReported(t *testing.T) {
	for _, address := range []string{
		"http://example.com/jquery-3.5.0.min.js",
		"http://example.com/jquery-3.6.4.min.js",
		"http://example.com/bootstrap-4.3.2.min.js",
		"http://example.com/bootstrap-5.3.0.min.js",
		"http://example.com/lodash-4.17.21.min.js",
		"http://example.com/moment-2.29.4.min.js",
	} {
		tg := responseTarget(t, address, "application/javascript", "// library")
		if findings := runPassive(t, vulnerableLibrary{}, tg); len(findings) != 0 {
			t.Errorf("%s was reported: %s", address, findings[0].Title)
		}
	}
}

func TestLibrariesWithoutAVersionAreLeftAlone(t *testing.T) {
	// A file name with no version says nothing about which release it is, and guessing
	// would be inventing a finding.
	for _, address := range []string{
		"http://example.com/jquery.min.js",
		"http://example.com/static/js/lodash.js",
		"http://example.com/app.bundle.js",
	} {
		tg := responseTarget(t, address, "application/javascript", "// no version banner here")
		if findings := runPassive(t, vulnerableLibrary{}, tg); len(findings) != 0 {
			t.Errorf("%s was reported: %s", address, findings[0].Title)
		}
	}
}

func TestSiblingLibrariesAreNotConfusedForEachOther(t *testing.T) {
	// jquery-ui and bootstrap-select carry their own version numbers, and reading those as
	// the parent library would report the wrong release.
	tg := responseTarget(t, "http://example.com/static/jquery-ui-1.12.1.min.js",
		"application/javascript", "/*! jQuery UI - v1.12.1 */")
	if findings := runPassive(t, vulnerableLibrary{}, tg); len(findings) != 0 {
		t.Errorf("jquery-ui was read as jQuery: %s", findings[0].Title)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10.2", "3.5.0", -1},
		{"3.5.0", "3.5.0", 0},
		{"3.5.1", "3.5.0", 1},
		{"1.10", "1.10.0", 0},
		// Numeric, not lexicographic: 2.9 precedes 2.10.
		{"2.9.0", "2.10.0", -1},
		{"10.0.0", "9.9.9", 1},
		// A prerelease suffix belongs to the release line its digits name.
		{"1.0.0-beta", "1.0.0", 0},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
