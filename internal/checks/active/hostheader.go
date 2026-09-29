package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// hostCanary is a domain that cannot resolve. A value that cannot be a real host
// appearing in a response is evidence the application echoed what it was given,
// rather than a coincidence.
const hostCanary = "crackweb-host-check.invalid"

// hostInjectionHeaders are the fields an application might trust in place of, or
// in addition to, the Host header.
//
// A reverse proxy usually forwards the original host in one of these, and an
// application that reads them without validation is just as exposed as one that
// trusts Host directly.
var hostInjectionHeaders = []string{
	"Host",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Host",
	"X-Original-Host",
	"X-Rewrite-URL",
	"Forwarded",
	"X-Forwarded-For",
}

// hostHeader detects an application that builds URLs from a request header it
// was given rather than from its own configuration.
//
// The test is reflection: send a host that cannot exist, and see whether it comes
// back in the page, in a link, or in a redirect. That is the mechanism behind
// password-reset poisoning and cache poisoning — both of which hinge on the
// attacker's value surviving into a link the victim will click.
//
// It is a request-level check because the injection point is a header, not a
// parameter: a request with no parameters at all — a plain GET on a login page —
// is exactly where this matters most.
type hostHeader struct{}

func (hostHeader) ID() string                 { return "host-header" }
func (hostHeader) TitleKey() i18n.Key         { return i18n.KeyCheckHostHeaderTitle }
func (hostHeader) DescriptionKey() i18n.Key   { return i18n.KeyCheckHostHeaderDesc }
func (hostHeader) RemediationKey() i18n.Key   { return i18n.KeyCheckHostHeaderFix }
func (hostHeader) Severity() finding.Severity { return finding.SeverityMedium }
func (hostHeader) Tags() []string {
	return []string{"active", "host-header", "misconfiguration"}
}
func (hostHeader) Passive() bool { return false }

// IsRequestLevel marks this as a check that works on the request as a whole.
func (hostHeader) IsRequestLevel() bool { return true }

func (hostHeader) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// A response that already mentions the canary cannot be used as evidence.
	baseline := string(t.Response.Body)
	if strings.Contains(baseline, hostCanary) {
		return nil
	}

	for _, header := range hostInjectionHeaders {
		mutated := t.Request.Clone()
		switch header {
		case "Forwarded":
			mutated.Header.Set(header, "host="+hostCanary)
		case "X-Forwarded-For":
			mutated.Header.Set(header, "127.0.0.1")
		default:
			mutated.Header.Set(header, hostCanary)
		}

		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil {
			continue
		}

		location := response.Header.Get("Location")
		body := string(response.Body)
		reflectedInBody := strings.Contains(body, hostCanary)
		reflectedInLocation := strings.Contains(location, hostCanary)
		if !reflectedInBody && !reflectedInLocation {
			continue
		}
		// A page that prints the request it received is not a page that used the value.
		// Developer consoles, error handlers and debug endpoints routinely dump the whole
		// request, headers and all, and the reflected canary inside such a dump is the page
		// quoting itself — the most common way this check produces a finding that has to be
		// dismissed by hand.
		if reflectedInBody && !reflectedInLocation && echoOnlyInBody(body, header, hostCanary) {
			continue
		}

		f := checks.NewFinding(hostHeader{}, t,
			i18n.KeyCheckHostHeaderTitle, i18n.KeyCheckHostHeaderDesc, i18n.KeyCheckHostHeaderFix)
		f.Severity = finding.SeverityMedium
		// Certain when the value came back verbatim in a header the browser acts
		// on; firm when it only appeared in the page.
		if reflectedInLocation {
			f.Confidence = finding.ConfidenceCertain
		} else {
			f.Confidence = finding.ConfidenceFirm
		}
		f.CWE = "CWE-644"
		f.References = []string{
			"https://portswigger.net/web-security/host-header",
			"https://cwe.mitre.org/data/definitions/644.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{header + ": " + hostCanary}
		if reflectedInLocation {
			f.Evidence.Matches = append(f.Evidence.Matches, "Location: "+location)
			f.Evidence.Diff = extractAround(location, hostCanary, 120)
		} else {
			f.Evidence.Diff = extractAround(body, hostCanary, 200)
		}
		return []*finding.Finding{f}
	}
	return nil
}

// echoOnlyInBody reports whether every appearance of the canary in the body sits right
// after the header name it was sent in — which is what a page looks like when it printed
// its own request, and what an application that merely reports the header it received
// looks like too. Anything else means the value reached a place the application built
// itself, which is the finding worth reporting.
func echoOnlyInBody(body, header, canary string) bool {
	seen := false
	rest := body
	for {
		index := strings.Index(rest, canary)
		if index < 0 {
			return seen
		}
		seen = true
		if !prefixedByHeaderName(rest[:index], header) {
			return false
		}
		rest = rest[index+len(canary):]
	}
}

// prefixedByHeaderName reports whether the text immediately before a value reads
// "<header>:" at the start of its line.
func prefixedByHeaderName(before, header string) bool {
	lineStart := strings.LastIndexAny(before, "\r\n") + 1
	line := before[lineStart:]
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(line[:colon]), header)
}

// Ensure httpmsg stays referenced by the clone helper above.
var _ = httpmsg.OriginReplay
