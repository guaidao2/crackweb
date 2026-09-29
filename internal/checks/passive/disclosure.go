package passive

import (
	"context"
	"regexp"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// maxScanBytes bounds how much of a body the content checks read. A response larger than
// this is a download rather than a page, and reading all of it would cost more than the
// check is worth.
const maxScanBytes = 256 << 10

// errorSignatures are fragments that appear when an application failed and told the
// visitor why.
//
// They are deliberately specific. The word "error" is one pages use in ordinary prose; an
// exception class name, a stack frame or a database's own wording is not. Each one names
// the runtime it came from, so a finding tells the reader what is behind the page without
// anyone having to guess.
var errorSignatures = []struct {
	text  string
	label string
}{
	{"traceback (most recent call last)", "Python traceback"},
	{"goroutine 1 [running]:", "Go panic"},
	{"exception in thread", "Java exception"},
	{"java.lang.", "Java exception class"},
	{"org.springframework.", "Spring stack frame"},
	{"at org.apache.", "Java stack frame"},
	{"system.nullreferenceexception", ".NET exception"},
	{"system.web.httpexception", ".NET exception"},
	{"fatal error:", "PHP fatal error"},
	{"parse error:", "PHP parse error"},
	{"undefined index", "PHP undefined index"},
	{"undefined variable", "PHP undefined variable"},
	{"warning: mysql", "MySQL warning"},
	{"whitelabel error page", "Spring Boot error page"},
	{"template syntax error", "Template engine error"},
	{"jinja2.exceptions", "Jinja2 exception"},
	{"django.core.exceptions", "Django exception"},
	{"actioncontroller::", "Rails exception"},
	{"sqlstate[", "SQLSTATE error"},
	{"you have an error in your sql syntax", "MySQL syntax error"},
	{"unclosed quotation mark", "SQL Server syntax error"},
	{"unhandled exception", "Unhandled exception"},
	{"stack trace:", "Stack trace"},
}

// errorDisclosure reports a response that carries the application's own failure detail.
//
// It looks at the body only, and only for fragments that a working page has no reason to
// contain — so what it finds is a page that failed while someone was watching, which is
// both a leak in itself and a sign that the failure path is reachable without any
// injection at all.
type errorDisclosure struct{}

func (errorDisclosure) ID() string               { return "passive-error-disclosure" }
func (errorDisclosure) TitleKey() i18n.Key       { return i18n.KeyCheckErrorDisclosureTitle }
func (errorDisclosure) DescriptionKey() i18n.Key { return i18n.KeyCheckErrorDisclosureDesc }
func (errorDisclosure) RemediationKey() i18n.Key { return i18n.KeyCheckErrorDisclosureFix }
func (errorDisclosure) Severity() finding.Severity {
	return finding.SeverityLow
}
func (errorDisclosure) Tags() []string { return []string{"passive", "disclosure", "error"} }
func (errorDisclosure) Passive() bool  { return true }

func (errorDisclosure) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || len(t.Response.Body) == 0 {
		return nil
	}
	body := strings.ToLower(bodyForScan(t.Response.Body))

	var matches []string
	for _, signature := range errorSignatures {
		if strings.Contains(body, signature.text) {
			matches = append(matches, signature.label)
		}
	}
	if len(matches) == 0 {
		return nil
	}

	f := checks.NewFinding(errorDisclosure{}, t,
		i18n.KeyCheckErrorDisclosureTitle, i18n.KeyCheckErrorDisclosureDesc,
		i18n.KeyCheckErrorDisclosureFix)
	// Firm rather than certain: a page that documents these very strings would match too.
	f.Confidence = finding.ConfidenceFirm
	f.DedupHostOnly = true
	f.DedupExtra = strings.Join(matches, ",")
	f.CWE = "CWE-209"
	f.References = []string{"https://cwe.mitre.org/data/definitions/209.html"}
	f.Evidence.Matches = matches
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// Patterns for the detail a response can leak about the deployment behind it.
var (
	privateIPv4Re = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}` +
		`|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}` +
		`|192\.168\.\d{1,3}\.\d{1,3})\b`)
	unixPathRe    = regexp.MustCompile(`(?:/(?:home|Users)/[A-Za-z0-9._-]{3,}|/(?:var|srv|opt)/www/)`)
	windowsPathRe = regexp.MustCompile(`\b[A-Za-z]:\\(?:[A-Za-z0-9._-]+\\?){2,}`)
	mailboxRe     = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b`)
)

// contentDisclosure reports detail a response reveals about the machine behind it: an
// internal address, a server-side path, or a mailbox.
//
// None of the three is a vulnerability on its own, which is why they are reported at the
// lowest severity and deduplicated per host. What makes them worth collecting is that
// together they describe an infrastructure precisely enough to aim at it, and they are
// the kind of thing that leaks from a debug leftover rather than from a decision.
type contentDisclosure struct{}

func (contentDisclosure) ID() string               { return "passive-content-disclosure" }
func (contentDisclosure) TitleKey() i18n.Key       { return i18n.KeyCheckContentDisclosureTitle }
func (contentDisclosure) DescriptionKey() i18n.Key { return i18n.KeyCheckContentDisclosureDesc }
func (contentDisclosure) RemediationKey() i18n.Key { return i18n.KeyCheckContentDisclosureFix }
func (contentDisclosure) Severity() finding.Severity {
	return finding.SeverityLow
}
func (contentDisclosure) Tags() []string {
	return []string{"passive", "disclosure", "information"}
}
func (contentDisclosure) Passive() bool { return true }

func (contentDisclosure) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || len(t.Response.Body) == 0 {
		return nil
	}
	body := bodyForScan(t.Response.Body)

	var kinds []string
	if match := privateIPv4Re.FindString(body); match != "" {
		kinds = append(kinds, "internal address: "+match)
	}
	if match := unixPathRe.FindString(body); match != "" {
		kinds = append(kinds, "server-side path: "+match)
	} else if match := windowsPathRe.FindString(body); match != "" {
		kinds = append(kinds, "server-side path: "+match)
	}
	// Only the domain of a mailbox is kept. A published address is somebody's personal
	// data, and the report has no need for it to make its point.
	if match := mailboxRe.FindStringSubmatch(body); match != nil {
		kinds = append(kinds, "mailbox at "+match[1])
	}
	if len(kinds) == 0 {
		return nil
	}

	f := checks.NewFinding(contentDisclosure{}, t,
		i18n.KeyCheckContentDisclosureTitle, i18n.KeyCheckContentDisclosureDesc,
		i18n.KeyCheckContentDisclosureFix)
	f.Confidence = finding.ConfidenceFirm
	f.DedupHostOnly = true
	f.DedupExtra = strings.Join(kinds, ";")
	f.CWE = "CWE-200"
	f.References = []string{"https://cwe.mitre.org/data/definitions/200.html"}
	f.Evidence.Matches = kinds
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// privateKeyMarkers are the PEM headers a served key begins with. One of these in a
// response body is not ambiguous: nobody serves a private key on purpose.
var privateKeyMarkers = []string{
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN DSA PRIVATE KEY-----",
	"-----BEGIN EC PRIVATE KEY-----",
	"-----BEGIN OPENSSH PRIVATE KEY-----",
	"-----BEGIN PRIVATE KEY-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	"-----BEGIN PGP PRIVATE KEY BLOCK-----",
}

// privateKey reports a key served over HTTP.
type privateKey struct{}

func (privateKey) ID() string               { return "passive-private-key" }
func (privateKey) TitleKey() i18n.Key       { return i18n.KeyCheckPrivateKeyTitle }
func (privateKey) DescriptionKey() i18n.Key { return i18n.KeyCheckPrivateKeyDesc }
func (privateKey) RemediationKey() i18n.Key { return i18n.KeyCheckPrivateKeyFix }
func (privateKey) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (privateKey) Tags() []string { return []string{"passive", "disclosure", "crypto"} }
func (privateKey) Passive() bool  { return true }

func (privateKey) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || len(t.Response.Body) == 0 {
		return nil
	}
	body := bodyForScan(t.Response.Body)

	for _, marker := range privateKeyMarkers {
		if !strings.Contains(body, marker) {
			continue
		}
		f := checks.NewFinding(privateKey{}, t,
			i18n.KeyCheckPrivateKeyTitle, i18n.KeyCheckPrivateKeyDesc, i18n.KeyCheckPrivateKeyFix)
		f.Confidence = finding.ConfidenceCertain
		f.CWE = "CWE-321"
		f.References = []string{"https://cwe.mitre.org/data/definitions/321.html"}
		f.Evidence.Matches = []string{marker}
		// The key itself is never reproduced: it is live material, and a report is the
		// last place it should be copied to.
		f.Evidence.Response = nil
		return []*finding.Finding{f}
	}
	return nil
}

// bodyForScan returns the part of a response body the content checks look at.
func bodyForScan(body []byte) string {
	if len(body) > maxScanBytes {
		body = body[:maxScanBytes]
	}
	return string(body)
}
