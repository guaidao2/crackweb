package active

import (
	"strings"
	"testing"
)

// TestMarkerThatOnlyClosesATagIsNotExecutable: filtering the opening tag out of
// `<script>alert(1)</script>` leaves `alert(1)</script>` in the page. A parser
// drops that closing tag and runs nothing, so treating it as executable would
// report every page that strips tags — the false positive this predicate exists
// to prevent.
func TestMarkerThatOnlyClosesATagIsNotExecutable(t *testing.T) {
	body := "<html><body><p>no results for alert(1)</script></p></body></html>"
	marker := "alert(1)</script>"
	if executableContext(body, marker) {
		t.Error("a payload carrying only a closing tag was called executable")
	}
}

// TestChildDocumentPayloadsAreExecutable: the shapes that run from one parse —
// an `srcdoc` value, a `data:` URL, an animation event, `eval(src)` — all open an
// element, so a page that echoes them unencoded is reported.
func TestChildDocumentPayloadsAreExecutable(t *testing.T) {
	for _, marker := range []string{
		`<iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;">`,
		`<iframe src="data:text/html,<script>alert(document.domain)</script>">`,
		`<object data="data:text/html,<script>alert(document.domain)</script>">`,
		`<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>`,
		`<img src=x:alert(1) onerror=eval(src)>`,
	} {
		body := "<html><body><p>no results for " + marker + "</p></body></html>"
		if !executableContext(body, marker) {
			t.Errorf("payload %q was not recognised as executable", marker)
		}
	}
}

// TestInertMarkerStaysInert guards the other direction: a value that only landed
// in a text node without opening anything is not a finding.
func TestInertMarkerStaysInert(t *testing.T) {
	marker := `alert(document.domain)`
	body := "<html><body><p>no results for " + marker + "</p></body></html>"
	if executableContext(body, marker) {
		t.Error("a bare expression in a text node was called executable")
	}
	if !strings.Contains(body, marker) {
		t.Fatal("fixture is wrong")
	}
}
