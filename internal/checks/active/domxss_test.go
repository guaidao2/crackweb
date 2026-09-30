package active

import (
	"context"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// fakeBrowser answers as a browser would that had just loaded the page: it reports the
// planted element present exactly when the address it was given carries the marker.
type fakeBrowser struct {
	embedded bool
	asked    []string
	// evalResult is what Eval answers, and evalFor limits that answer to addresses
	// carrying it — a page reaches runtime state only after the value arrives.
	evalResult string
	evalFor    string
}

func (f *fakeBrowser) Probe(_ context.Context, target, marker string) (bool, string, error) {
	f.asked = append(f.asked, target)
	if !f.embedded || !strings.Contains(target, marker) {
		return false, "", nil
	}
	return true, "<body> <img src=x id=" + marker + ">", nil
}

// Eval answers with the value the test set, and records the address like Probe.
func (f *fakeBrowser) Eval(_ context.Context, target, expression string) (string, error) {
	f.asked = append(f.asked, target)
	if f.evalResult != "" && f.evalFor != "" && !strings.Contains(target, f.evalFor) {
		return "", nil
	}
	return f.evalResult, nil
}

func domTarget(t *testing.T, rawURL string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return &checks.Target{Request: request, Response: &httpmsg.Response{Status: 200, Body: []byte("<html></html>")}}
}

func TestDOMXSSFiresWhenThePlantedElementAppears(t *testing.T) {
	h := newHarness(t)
	probe := &fakeBrowser{embedded: true}
	h.ctx.Browser = probe

	findings := runRequestLevel(t, h, domXSS{}, domTarget(t, "http://example.com/page?q=1"))
	if len(findings) == 0 {
		t.Fatal("a page that put the value into the document was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79", f.CWE)
	}
	if string(f.Severity) != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if !strings.Contains(f.Payload, "<img") {
		t.Errorf("the payload is not the markup that was planted: %q", f.Payload)
	}
	if len(f.Evidence.Diff) == 0 {
		t.Error("the element the browser built has to be in the evidence")
	}
	if len(probe.asked) == 0 {
		t.Fatal("the browser was never asked")
	}
}

func TestDOMXSSIsSilentWithoutABrowser(t *testing.T) {
	// No browser, no answer: the response cannot tell either way, and a check that guessed
	// would be exactly the kind of finding this scanner exists not to produce.
	h := newHarness(t)
	if findings := runRequestLevel(t, h, domXSS{}, domTarget(t, "http://example.com/page?q=1")); len(findings) != 0 {
		t.Errorf("a finding was produced without a browser: %v", findings[0].Evidence.Matches)
	}
}

func TestDOMXSSIgnoresAPageThatEscapedTheValue(t *testing.T) {
	h := newHarness(t)
	h.ctx.Browser = &fakeBrowser{embedded: false}
	if findings := runRequestLevel(t, h, domXSS{}, domTarget(t, "http://example.com/page?q=1")); len(findings) != 0 {
		t.Errorf("a page that displayed the value as text was reported: %v", findings[0].Evidence.Matches)
	}
}

func TestDOMXSSIsOptIn(t *testing.T) {
	// Loading a page in a browser runs every script it carries, writes included, so this is
	// never something a default scan does.
	if !checks.IsUnsafe(domXSS{}) {
		t.Error("dom-xss has to be opt-in")
	}
	if checks.IsUnsafe(accessControlVariants{}) {
		t.Error("access-control-variants sends ordinary requests and must not be opt-in")
	}
}

func TestDOMCandidatesCarryTheValueInTheFragmentAndParameters(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.com/page?q=1&lang=en")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	candidates := domCandidates(request, domProbe)
	// The fragment, the hashbang, the path, then one per query parameter.
	if len(candidates) != 5 {
		t.Fatalf("got %d candidates, want 5", len(candidates))
	}

	fragment := candidates[0]
	if fragment.name != "url fragment" {
		t.Errorf("the fragment is not tested first: %q", fragment.name)
	}
	if !strings.Contains(fragment.url, "#<img") {
		t.Errorf("the fragment payload was encoded before it was sent: %s", fragment.url)
	}
	// The other two carriers of the value: a router's `#!` and the path the page
	// routes on. Neither is encoded, for the same reason as the fragment.
	if got := candidates[1]; got.name != "hashbang fragment" || !strings.Contains(got.url, "#!<img") {
		t.Errorf("hashbang candidate = %q %s", got.name, got.url)
	}
	if got := candidates[2]; got.name != "url path" || !strings.Contains(got.url, "/<img") {
		t.Errorf("path candidate = %q %s", got.name, got.url)
	}

	for _, candidate := range candidates[3:] {
		if !strings.Contains(candidate.url, candidate.marker) {
			t.Errorf("candidate %q does not carry its marker: %s", candidate.name, candidate.url)
		}
	}
	// Each candidate needs its own marker, or one page's answer would be read as another's.
	if candidates[0].marker == candidates[1].marker {
		t.Error("two candidates share a marker")
	}
}

func TestDOMCandidatesAreBounded(t *testing.T) {
	// Every candidate is a browser load, and a page with thirty parameters would otherwise
	// cost thirty of them.
	rawURL := "http://example.com/page?" + strings.Repeat("p=1&", 40)
	request, err := httpmsg.NewRequest("GET", strings.TrimSuffix(rawURL, "&"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if got := len(domCandidates(request, domProbe)); got > maxDOMCandidates {
		t.Errorf("got %d candidates, want at most %d", got, maxDOMCandidates)
	}
}

func TestDOMProbeIsInert(t *testing.T) {
	probe := domProbe("crackwebprobeabc")
	if !strings.HasPrefix(probe, "<img") {
		t.Errorf("the probe is not markup: %q", probe)
	}
	// Nothing may be fetched or executed to make the element appear, or a page that merely
	// failed to reach a resource would look vulnerable.
	for _, forbidden := range []string{"onerror", "onload", "src=http", "javascript:"} {
		if strings.Contains(probe, forbidden) {
			t.Errorf("the probe carries %q: %s", forbidden, probe)
		}
	}
	if !strings.Contains(probe, `id=crackwebprobeabc`) {
		t.Errorf("the probe does not carry the marker as an unquoted id: %s", probe)
	}
}
