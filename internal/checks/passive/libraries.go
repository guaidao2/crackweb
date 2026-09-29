package passive

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// A front-end library carries its own version wherever it is served from, and a page that
// loads an old one has the old one's flaws on every page it appears on — including the
// pages nobody thought to test, because the defect is not in their code. The version is
// the whole finding: what to do about it is a package upgrade, not a code change.

// libraryAdvisory is one published vulnerability in a front-end library: the range of
// versions it affects, and where to read about it.
type libraryAdvisory struct {
	// Library is the name as it is commonly written.
	Library string
	// Introduced and FixedIn bracket the affected versions, half-open: a version is
	// affected when Introduced <= version < FixedIn.
	Introduced string
	FixedIn    string
	Severity   finding.Severity
	// ID is the CVE identifier, and Reference where the fix was announced.
	ID        string
	Reference string
}

// libraryAdvisories are the published vulnerabilities worth matching a page against.
//
// The table is deliberately short, and deliberately not exhaustive. A complete one would
// have to be a database kept current somewhere else, and a subtly wrong entry is worse than
// a missing one: a version reported as vulnerable when it is not costs a team a day of
// chasing. Every range here is one whose boundaries are unambiguous, and a library with no
// entry is left alone rather than guessed at.
var libraryAdvisories = []libraryAdvisory{
	{
		Library: "jQuery", Introduced: "1.0.3", FixedIn: "3.5.0",
		Severity: finding.SeverityMedium, ID: "CVE-2020-11022",
		Reference: "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/",
	},
	{
		Library: "jQuery", Introduced: "1.0.0", FixedIn: "3.4.0",
		Severity: finding.SeverityMedium, ID: "CVE-2019-11358",
		Reference: "https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/",
	},
	{
		Library: "Bootstrap", Introduced: "3.0.0", FixedIn: "3.4.1",
		Severity: finding.SeverityMedium, ID: "CVE-2019-8331",
		Reference: "https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
	},
	{
		Library: "Bootstrap", Introduced: "4.0.0", FixedIn: "4.3.2",
		Severity: finding.SeverityMedium, ID: "CVE-2019-8331",
		Reference: "https://blog.getbootstrap.com/2019/02/13/bootstrap-4-3-1-and-3-4-1/",
	},
	{
		Library: "Lodash", Introduced: "0.0.0", FixedIn: "4.17.21",
		Severity: finding.SeverityMedium, ID: "CVE-2021-23337",
		Reference: "https://github.com/lodash/lodash/releases/tag/4.17.21",
	},
	{
		Library: "Moment.js", Introduced: "0.0.0", FixedIn: "2.29.4",
		Severity: finding.SeverityMedium, ID: "CVE-2022-31129",
		Reference: "https://github.com/moment/moment/releases/tag/2.29.4",
	},
}

// libraryPatterns match a library and its version as they are written in a file name, in a
// URL path, or in the version banner a build leaves at the top of the file.
var libraryPatterns = []struct {
	library string
	pattern *regexp.Regexp
}{
	{"jQuery", regexp.MustCompile(`(?i)jquery[\s._-]*v?(\d+\.\d+(?:\.\d+)?)`)},
	{"Bootstrap", regexp.MustCompile(`(?i)bootstrap[\s._-]*v?(\d+\.\d+(?:\.\d+)?)`)},
	{"Lodash", regexp.MustCompile(`(?i)lodash[\s._-]*v?(\d+\.\d+(?:\.\d+)?)`)},
	{"Moment.js", regexp.MustCompile(`(?i)moment[\s._-]*v?(\d+\.\d+(?:\.\d+)?)`)},
}

// maxVersionBannerBytes bounds how much of a file is read looking for its version banner.
// Every library that ships one puts it in the first few lines.
const maxVersionBannerBytes = 4096

// vulnerableLibrary reports a page loading a front-end library at a version with a
// published vulnerability.
type vulnerableLibrary struct{}

func (vulnerableLibrary) ID() string { return "passive-vulnerable-library" }
func (vulnerableLibrary) TitleKey() i18n.Key {
	return i18n.KeyCheckLibraryTitle
}
func (vulnerableLibrary) DescriptionKey() i18n.Key {
	return i18n.KeyCheckLibraryDesc
}
func (vulnerableLibrary) RemediationKey() i18n.Key {
	return i18n.KeyCheckLibraryFix
}
func (vulnerableLibrary) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (vulnerableLibrary) Tags() []string {
	return []string{"passive", "assets", "supply-chain", "dependency"}
}
func (vulnerableLibrary) Passive() bool { return true }

func (vulnerableLibrary) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || t.Request == nil {
		return nil
	}

	body := bodyForScan(t.Response.Body)
	seen := map[string]bool{}
	var findings []*finding.Finding

	// The response is the library itself when a crawler followed a script tag to it, and it
	// is a page when it is the document that loads one. Both carry an address to read.
	if library, version, ok := identifyLibrary(body, t.Request.URLString()); ok {
		findings = append(findings, advisoriesFor(library, version, t, seen)...)
	}
	if isHTML(t.Response) {
		for _, reference := range assetReferences(body) {
			library, version, ok := identifyLibrary("", reference)
			if !ok {
				continue
			}
			findings = append(findings, advisoriesFor(library, version, t, seen)...)
		}
	}
	return findings
}

// identifyLibrary reads a library and version out of an address or out of the beginning of
// a file.
func identifyLibrary(content, reference string) (string, string, bool) {
	if library, version, ok := matchLibrary(reference); ok {
		return library, version, true
	}
	if len(content) > maxVersionBannerBytes {
		content = content[:maxVersionBannerBytes]
	}
	return matchLibrary(content)
}

// matchLibrary looks for any known library and version in a string.
func matchLibrary(text string) (string, string, bool) {
	if text == "" {
		return "", "", false
	}
	for _, candidate := range libraryPatterns {
		if match := candidate.pattern.FindStringSubmatch(text); match != nil {
			return candidate.library, match[1], true
		}
	}
	return "", "", false
}

// advisoriesFor returns one finding per published vulnerability the version falls into.
func advisoriesFor(library, version string, t *checks.Target, seen map[string]bool) []*finding.Finding {
	var findings []*finding.Finding
	for _, advisory := range libraryAdvisories {
		if advisory.Library != library {
			continue
		}
		if compareVersions(version, advisory.Introduced) < 0 || compareVersions(version, advisory.FixedIn) >= 0 {
			continue
		}
		key := library + " " + version + " " + advisory.ID
		if seen[key] {
			continue
		}
		seen[key] = true

		f := checks.NewFinding(vulnerableLibrary{}, t,
			i18n.KeyCheckLibraryTitle, i18n.KeyCheckLibraryDesc, i18n.KeyCheckLibraryFix)
		// The title names the library, the version and the advisory: none of the three is
		// prose, and a reader needs all three before deciding whether to care.
		f.Title = fmt.Sprintf("%s %s (%s)", library, version, advisory.ID)
		f.Severity = advisory.Severity
		f.Confidence = finding.ConfidenceCertain
		// Site-wide by nature: the same script tag appears on every page that includes it.
		f.DedupHostOnly = true
		f.DedupExtra = key
		f.CWE = "CWE-1395"
		f.References = []string{advisory.Reference}
		f.Evidence.Matches = []string{
			fmt.Sprintf("%s %s is affected by %s; fixed in %s", library, version, advisory.ID, advisory.FixedIn),
		}
		f.Evidence.Response = headBytes(t.Response, 4096)
		findings = append(findings, f)
	}
	return findings
}

// assetReferences returns the addresses a page loads scripts and stylesheets from.
func assetReferences(body string) []string {
	var out []string
	for _, match := range assetTagRe.FindAllStringSubmatch(body, maxAssetsScanned) {
		element, attrs := strings.ToLower(match[1]), match[2]
		if element == "link" && !strings.Contains(strings.ToLower(relAttr(attrs)), "stylesheet") {
			continue
		}
		if address := tagURL(attrs); address != "" {
			out = append(out, address)
		}
	}
	return out
}

// compareVersions orders two dotted version strings by their numeric parts, returning -1,
// 0 or 1.
//
// A missing part counts as zero, so 1.10 and 1.10.0 are the same version. A part carrying
// a suffix contributes the digits it starts with, because those are what decide which
// release line the build belongs to.
func compareVersions(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r int
		if i < len(left) {
			l = leadingInt(left[i])
		}
		if i < len(right) {
			r = leadingInt(right[i])
		}
		if l != r {
			if l < r {
				return -1
			}
			return 1
		}
	}
	return 0
}

// leadingInt reads the digits a version part starts with, so "10-beta" and "10" agree.
func leadingInt(part string) int {
	end := 0
	for end < len(part) && part[end] >= '0' && part[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	value, err := strconv.Atoi(part[:end])
	if err != nil {
		return 0
	}
	return value
}
