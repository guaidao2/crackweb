package passive

import (
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
)

// cspCase builds a page whose only interesting property is the policy it sends.
func cspCase(t *testing.T, header, value string) *checks.Target {
	t.Helper()
	target := responseTarget(t, "https://app.example.com/", "text/html", "<html><body>page</body></html>")
	if header != "" && value != "" {
		target.Response.Header.Set(header, value)
	}
	return target
}

// TestCSPFiresOnUnsafeInline: the permission an injected script needs.
func TestCSPFiresOnUnsafeInline(t *testing.T) {
	findings := runPassive(t, cspWeaknesses{}, cspCase(t, "Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'"))
	if len(findings) == 0 {
		t.Fatal("a policy permitting inline script was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "'unsafe-inline'") {
		t.Errorf("evidence does not name the source: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPStaysQuietWithANonce is the accuracy case: the specification says a nonce makes the
// browser ignore `'unsafe-inline'` in the same list, so a policy written that way is doing
// the right thing while looking like one that is not.
func TestCSPStaysQuietWithANonce(t *testing.T) {
	if findings := runPassive(t, cspWeaknesses{}, cspCase(t, "Content-Security-Policy",
		"script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'")); len(findings) != 0 {
		t.Errorf("a policy pinned by a nonce was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPFiresOnWildcardAndEval: a script directive that names every origin, or allows
// evaluation.
func TestCSPFiresOnWildcardAndEval(t *testing.T) {
	findings := runPassive(t, cspWeaknesses{}, cspCase(t, "Content-Security-Policy",
		"default-src 'self'; script-src * 'unsafe-eval'"))
	if len(findings) == 0 {
		t.Fatal("a policy granting every origin and evaluation was not reported")
	}
	joined := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(joined, "*") || !strings.Contains(joined, "'unsafe-eval'") {
		t.Errorf("evidence does not name both problems: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPReadsTheScriptDirectiveNotTheDefaultOne: once script-src exists, the
// specification says script answers to it alone, so a wide `default-src` is not a statement
// about script and reporting it here would be reporting the wrong directive.
func TestCSPReadsTheScriptDirectiveNotTheDefaultOne(t *testing.T) {
	findings := runPassive(t, cspWeaknesses{}, cspCase(t, "Content-Security-Policy",
		"default-src *; script-src 'self'"))
	if len(findings) != 0 {
		t.Errorf("a wide default-src was read as a statement about script: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPFiresOnReportOnly: a policy that is reported on and never enforced.
func TestCSPFiresOnReportOnly(t *testing.T) {
	findings := runPassive(t, cspWeaknesses{}, cspCase(t, "Content-Security-Policy-Report-Only",
		"default-src 'self'; script-src 'self'"))
	if len(findings) == 0 {
		t.Fatal("a report-only policy was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "Report-Only") {
		t.Errorf("evidence does not explain the header: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPStaysQuietOnATightPolicy: nothing to say about a policy that does its job.
func TestCSPStaysQuietOnATightPolicy(t *testing.T) {
	if findings := runPassive(t, cspWeaknesses{}, cspCase(t, "Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'")); len(findings) != 0 {
		t.Errorf("a tight policy was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPStaysQuietWithoutAPolicy: a missing header is the other check's business, and
// reporting it twice would double every finding.
func TestCSPStaysQuietWithoutAPolicy(t *testing.T) {
	if findings := runPassive(t, cspWeaknesses{}, cspCase(t, "", "")); len(findings) != 0 {
		t.Errorf("a page without a policy was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCSPStaysQuietOnNonHTML: a policy governs a document, and a JSON body is not one.
func TestCSPStaysQuietOnNonHTML(t *testing.T) {
	target := responseTarget(t, "https://app.example.com/api", "application/json", `{"ok":true}`)
	target.Response.Header.Set("Content-Security-Policy", "default-src *")
	if findings := runPassive(t, cspWeaknesses{}, target); len(findings) != 0 {
		t.Errorf("a non-HTML response was reported: %v", findings[0].Evidence.Matches)
	}
}
