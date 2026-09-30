package active

import (
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

func pollutionTarget(t *testing.T) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", "http://example.com/page?theme=dark")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return &checks.Target{
		Request:  request,
		Response: &httpmsg.Response{Status: 200, Body: []byte("<html><body>page</body></html>")},
	}
}

// TestPrototypePollutionFiresOnAMergeThatCopiesProto: the injected property shows up on a
// brand-new object, which is the flaw stated exactly.
func TestPrototypePollutionFiresOnAMergeThatCopiesProto(t *testing.T) {
	h := newHarness(t)
	h.ctx.Browser = &fakeBrowser{evalResult: pollutionValue, evalFor: "__proto__"}

	findings := runRequestLevel(t, h, prototypePollution{}, pollutionTarget(t))
	if len(findings) == 0 {
		t.Fatal("a query string that reached the prototype was not reported")
	}
	if findings[0].CWE != "CWE-1321" {
		t.Errorf("CWE = %q, want CWE-1321", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "__proto__") {
		t.Errorf("payload = %q, want the injected key", findings[0].Payload)
	}
}

// TestPrototypePollutionStaysQuietWhenThePropertyIsAlreadyVisible: a page that answers yes
// before anything was injected is answering about something of its own, and the finding
// would be about that instead.
func TestPrototypePollutionStaysQuietWhenThePropertyIsAlreadyVisible(t *testing.T) {
	h := newHarness(t)
	// Every address answers with the value, the control included.
	h.ctx.Browser = &fakeBrowser{evalResult: pollutionValue}

	if findings := runRequestLevel(t, h, prototypePollution{}, pollutionTarget(t)); len(findings) != 0 {
		t.Errorf("a page that already carried the property was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestPrototypePollutionIsSilentWithoutABrowser: without one there is nothing to ask.
func TestPrototypePollutionIsSilentWithoutABrowser(t *testing.T) {
	h := newHarness(t)
	if findings := runRequestLevel(t, h, prototypePollution{}, pollutionTarget(t)); len(findings) != 0 {
		t.Errorf("a check without a browser reported something: %v", findings)
	}
}

// TestPrototypePollutionIsOptIn keeps the guard rails: running the page is more than
// sending the request, so it is never selected by default.
func TestPrototypePollutionIsOptIn(t *testing.T) {
	if !checks.IsUnsafe(prototypePollution{}) {
		t.Error("prototype-pollution runs the page in a browser and must be opt-in")
	}
	if !checks.RequiresBrowser(prototypePollution{}) {
		t.Error("prototype-pollution cannot be answered without a browser")
	}
	if !checks.IsRequestLevel(prototypePollution{}) {
		t.Error("prototype-pollution is about the address, not about one parameter")
	}
}
