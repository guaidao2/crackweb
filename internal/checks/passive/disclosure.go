package passive

import (
	"context"
	"net"
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
	// internal marks the signatures that carry the application's own structure — a class name, a
	// file path, a framework frame — rather than only the fact that something failed. Those are
	// what tell a reader which library and which version to look up, and where in the source the
	// failure came from.
	internal bool
}{
	{"traceback (most recent call last)", "Python traceback", true},
	{"goroutine 1 [running]:", "Go panic", true},
	{"exception in thread", "Java exception", true},
	{"java.lang.", "Java exception class", true},
	{"org.springframework.", "Spring stack frame", true},
	{"at org.apache.", "Java stack frame", true},
	{"system.nullreferenceexception", ".NET exception", true},
	{"system.web.httpexception", ".NET exception", true},
	{"fatal error:", "PHP fatal error", false},
	{"parse error:", "PHP parse error", false},
	{"undefined index", "PHP undefined index", false},
	{"undefined variable", "PHP undefined variable", false},
	{"warning: mysql", "MySQL warning", false},
	{"whitelabel error page", "Spring Boot error page", false},
	{"template syntax error", "Template engine error", false},
	{"jinja2.exceptions", "Jinja2 exception", true},
	{"django.core.exceptions", "Django exception", true},
	{"actioncontroller::", "Rails exception", true},
	{"sqlstate[", "SQLSTATE error", false},
	{"you have an error in your sql syntax", "MySQL syntax error", false},
	{"unclosed quotation mark", "SQL Server syntax error", false},
	{"unhandled exception", "Unhandled exception", true},
	{"stack trace:", "Stack trace", true},
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
	structural := false
	for _, signature := range errorSignatures {
		if strings.Contains(body, signature.text) {
			matches = append(matches, signature.label)
			if signature.internal {
				structural = true
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}

	f := checks.NewFinding(errorDisclosure{}, t,
		i18n.KeyCheckErrorDisclosureTitle, i18n.KeyCheckErrorDisclosureDesc,
		i18n.KeyCheckErrorDisclosureFix)
	// A failure that names its own internals is worth more than one that only says it failed: the
	// class, the frame and the file are what lead to the version and to the line.
	if structural {
		f.Severity = finding.SeverityMedium
	}
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
	// The domain may be a single label: `ops@gateway` names a host on the local network, and
	// an address that uses one is deployment detail in a way a public domain never is.
	//
	// It has to start with a letter, though. A domain is a hostname, and `@400px` in a
	// stylesheet is not one — without this, every rule that writes `@` followed by a number
	// reads as a mailbox on a private host.
	mailboxRe = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@([A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*)\b`)
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

// internalDomainSuffixes name a private network rather than a public one.
var internalDomainSuffixes = []string{
	".local", ".internal", ".lan", ".corp", ".intranet", ".localdomain", ".home", ".private",
}

// isInternalDomain reports whether a domain names something on a private network.
//
// A public domain — 126.com, gmail.com, the site's own — says nothing about the deployment
// behind the site, and an address that uses one is contact information.
// isAllDigits reports whether a string is nothing but digits.
func isAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isInternalDomain(domain string) bool {
	lower := strings.ToLower(domain)
	for _, suffix := range internalDomainSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	// A domain that is an address is not a public name.
	if net.ParseIP(lower) != nil {
		return true
	}
	// One label with no dot is a hostname on the local network — but a bare number is not a
	// hostname. The regular expression above already refuses those; this is the second belt.
	if !strings.Contains(lower, ".") {
		return !isAllDigits(lower)
	}
	return false
}

func (contentDisclosure) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || len(t.Response.Body) == 0 {
		return nil
	}
	body := bodyForScan(t.Response.Body)

	var kinds []string
	// Where the application lives on disk is worth more than the other two: a path names the
	// layout a file-read or a traversal would have to reach, and it is the difference between
	// knowing a host has an internal network and knowing what to ask that host for.
	serverPath := false
	if match := privateIPv4Re.FindString(body); match != "" {
		kinds = append(kinds, "internal address: "+match)
	}
	if match := unixPathRe.FindString(body); match != "" {
		kinds = append(kinds, "server-side path: "+match)
		serverPath = true
	} else if match := windowsPathRe.FindString(body); match != "" {
		kinds = append(kinds, "server-side path: "+match)
		serverPath = true
	}
	// Only the domain of a mailbox is kept. A published address is somebody's personal
	// data, and the report has no need for it to make its point.
	//
	// And only when that domain is plainly internal. Almost every site publishes a contact
	// address, and reporting each one makes the check's real finding — an address, a path —
	// disappear into a list the reader learns to skip.
	if match := mailboxRe.FindStringSubmatch(body); match != nil && isInternalDomain(match[1]) {
		kinds = append(kinds, "mailbox at "+match[1])
	}
	if len(kinds) == 0 {
		return nil
	}

	f := checks.NewFinding(contentDisclosure{}, t,
		i18n.KeyCheckContentDisclosureTitle, i18n.KeyCheckContentDisclosureDesc,
		i18n.KeyCheckContentDisclosureFix)
	// A path is worth more than the other two kinds. It names where the application lives on
	// disk, which is what a file-read or a traversal would have to reach; an internal address
	// says only that a private network exists, and a mailbox domain says who runs the site.
	if serverPath {
		f.Severity = finding.SeverityMedium
	}
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
