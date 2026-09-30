package active

import (
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

func cstiTarget(t *testing.T) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", "http://example.com/page?q=hello")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return &checks.Target{
		Request:  request,
		Response: &httpmsg.Response{Status: 200, Body: []byte("<html><body>page</body></html>")},
	}
}

// TestCSTIFiresWhenTheValueIsCompiled: the rendered document shows the product, which only
// an evaluation produces.
func TestCSTIFiresWhenTheValueIsCompiled(t *testing.T) {
	h := newHarness(t)
	h.ctx.Browser = &fakeBrowser{evalResult: "evaluated", evalFor: "1999"}

	findings := runRequestLevel(t, h, csti{}, cstiTarget(t))
	if len(findings) == 0 {
		t.Fatal("a page that compiled a value from the address was not reported")
	}
	if findings[0].CWE != "CWE-1336" {
		t.Errorf("CWE = %q, want CWE-1336", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "1999*1999") {
		t.Errorf("payload = %q, want the interpolation", findings[0].Payload)
	}
}

// TestCSTIStaysQuietWhenTheProductIsAlreadyThere: a page that shows the number without any
// probe cannot be used as evidence.
func TestCSTIStaysQuietWhenTheProductIsAlreadyThere(t *testing.T) {
	h := newHarness(t)
	// Every address answers, the control included.
	h.ctx.Browser = &fakeBrowser{evalResult: "evaluated"}

	if findings := runRequestLevel(t, h, csti{}, cstiTarget(t)); len(findings) != 0 {
		t.Errorf("a page that already showed the product was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCSTIIsSilentWithoutABrowser: without one there is nothing to ask.
func TestCSTIIsSilentWithoutABrowser(t *testing.T) {
	h := newHarness(t)
	if findings := runRequestLevel(t, h, csti{}, cstiTarget(t)); len(findings) != 0 {
		t.Errorf("a check without a browser reported something: %v", findings)
	}
}

// TestCSTIIsOptIn keeps the guard rails aligned with the other browser checks.
func TestCSTIIsOptIn(t *testing.T) {
	if !checks.IsUnsafe(csti{}) {
		t.Error("client-template-injection runs the page in a browser and must be opt-in")
	}
	if !checks.RequiresBrowser(csti{}) {
		t.Error("client-template-injection cannot be answered without a browser")
	}
	if !checks.IsRequestLevel(csti{}) {
		t.Error("client-template-injection is about the address, not about one parameter")
	}
}

// TestCSTICandidatesCarryTheProbeInTheFragmentAndParameters: the fragment first, then one
// per query parameter, and the probe is not encoded — the compiler has to recognise it.
func TestCSTICandidatesCarryTheProbeInTheFragmentAndParameters(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.com/page?q=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	candidates := cstiCandidates(request, "{{1999*1999}}")
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (fragment plus one parameter)", len(candidates))
	}
	if candidates[0].name != "url fragment" || !strings.Contains(candidates[0].url, "#{{1999*1999}}") {
		t.Errorf("fragment candidate = %q %s", candidates[0].name, candidates[0].url)
	}
	// The braces arrive encoded, which is what a query parameter requires; the
	// server decodes them back into the interpolation.
	if !strings.Contains(candidates[1].url, "%7B%7B1999%2A1999%7D%7D") {
		t.Errorf("parameter candidate does not carry the probe: %s", candidates[1].url)
	}
}
