package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// corsOrigin reports a site that answers with a cross-origin policy naming an origin it was
// told to, rather than one it decided on.
//
// The passive check reads the policy on a response the scanner already had, which only says
// anything when the request carried an `Origin` — and a crawler's requests do not, so the
// interesting case is invisible to it. This one asks: it sends an `Origin` no correct
// configuration would accept, and reads the answer. A policy that echoes it back grants that
// site the ability to read these responses, and if credentials are allowed it grants that to
// any site at all — the caller's identity travelling with the request.
//
// The variants are the shapes a hand-written check gets wrong: a host name used as a suffix,
// the same name used as a prefix, the same host over plain HTTP, and `null`, which sandboxed
// frames and local files send.
type corsOrigin struct{}

func (corsOrigin) ID() string                 { return "cors-origin" }
func (corsOrigin) TitleKey() i18n.Key         { return i18n.KeyCheckCORSOriginTitle }
func (corsOrigin) DescriptionKey() i18n.Key   { return i18n.KeyCheckCORSOriginDesc }
func (corsOrigin) RemediationKey() i18n.Key   { return i18n.KeyCheckCORSOriginFix }
func (corsOrigin) Severity() finding.Severity { return finding.SeverityHigh }
func (corsOrigin) Tags() []string {
	return []string{"active", "cors", "misconfiguration", "owasp-top10"}
}
func (corsOrigin) Passive() bool { return false }

// IsRequestLevel marks this as a check about the page rather than about one parameter.
func (corsOrigin) IsRequestLevel() bool { return true }

// corsOriginVariants returns the origins to ask with, for a given host.
func corsOriginVariants(host string) []string {
	return originVariants("crackweb-cors.example", host)
}

// originVariants returns the origins a correct policy refuses, each written to slip past a
// comparison that is not an exact one.
//
// Every one of these is a spelling of "somewhere else": a name that is not the site at all, the
// literal `null` that a sandboxed frame and a local file both send, the site's own name glued to
// the front of another domain or to the back of one, and the same host over plain HTTP. A policy
// that answers with any of them is not comparing, it is matching a substring — and the mistake
// is the same whether the answer comes back in `Access-Control-Allow-Origin` or as a completed
// WebSocket handshake, which is why both checks work from this list.
//
// The host is passed without its port. A comparison written against the authority — the host and
// port together — is therefore not covered, and neither is one that parses the origin before
// comparing it; both are recorded here rather than guessed at.
func originVariants(domain, host string) []string {
	out := []string{
		"https://" + domain,
		"null",
	}
	if host != "" {
		out = append(out,
			"https://"+domain+"."+host, // host used as a suffix
			"https://"+host+"."+domain, // host used as a prefix
			"http://"+host,             // the same host, in the clear
		)
	}
	return out
}

func (corsOrigin) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	host := ""
	if t.Request.URL != nil {
		host = t.Request.Hostname()
	}

	for _, origin := range corsOriginVariants(host) {
		mutated := t.Request.Clone()
		mutated.Header.Set("Origin", origin)
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil {
			continue
		}
		allowed := response.Header.Get("Access-Control-Allow-Origin")
		// The policy has to name the origin that was asked with: an answer of `*` or of some
		// other site is not this site trusting the caller.
		if allowed == "" || !strings.EqualFold(strings.TrimSpace(allowed), origin) {
			continue
		}
		withCredentials := strings.EqualFold(
			strings.TrimSpace(response.Header.Get("Access-Control-Allow-Credentials")), "true")

		f := checks.NewFinding(corsOrigin{}, t,
			i18n.KeyCheckCORSOriginTitle, i18n.KeyCheckCORSOriginDesc, i18n.KeyCheckCORSOriginFix)
		if withCredentials {
			// Any site on the internet can read this site's responses with the visitor's
			// own credentials attached.
			f.Severity = finding.SeverityCritical
		} else {
			f.Severity = finding.SeverityMedium
		}
		f.Confidence = finding.ConfidenceCertain
		f.Method = mutated.Method
		f.URL = mutated.URLString()
		f.Payload = "Origin: " + origin
		f.DedupHostOnly = true
		f.DedupExtra = origin
		f.CWE = "CWE-942"
		f.References = []string{
			"https://portswigger.net/web-security/cors",
			"https://cwe.mitre.org/data/definitions/942.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Body, 4096)
		f.Evidence.Matches = []string{
			"the policy named the origin the request carried: Access-Control-Allow-Origin: " +
				allowed,
			describeCORSRisk(origin, withCredentials),
		}
		return []*finding.Finding{f}
	}
	return nil
}

// describeCORSRisk says what the policy grants, in the terms of the origin that was accepted.
func describeCORSRisk(origin string, withCredentials bool) string {
	switch {
	case !withCredentials:
		return "any page that can make the request read this site's responses; no credentials " +
			"are allowed, so what it exposes depends on what these responses carry"
	case origin == "null":
		return "`null` is sent by sandboxed frames and local files, so a document the attacker " +
			"controls can read these responses with the visitor's credentials"
	default:
		return "the allowed origin is the caller's to choose, so any site can read these " +
			"responses with the visitor's credentials attached"
	}
}
