package active

import (
	"context"
	"regexp"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// redirectCanary is a domain that cannot resolve and would never legitimately
// appear in a redirect target, so a match cannot be a coincidence.
const redirectCanary = "crackweb-open-redirect.invalid"

// redirectSeeds exercise the ways a naive "does it start with /" check is
// defeated.
//
// Encoded spellings are not listed: the mutation engine derives them, and a seed
// that is already encoded would be encoded again before it was sent.
var redirectSeeds = []string{
	"https://" + redirectCanary + "/",
	"//" + redirectCanary + "/",
	"https:/" + redirectCanary,
	"////" + redirectCanary,
	"/\\" + redirectCanary,
	"https://" + redirectCanary + "@legitimate.invalid/",
	"http://" + redirectCanary + "/",
	"https://" + redirectCanary + ":443/",
	"//" + redirectCanary + "/?next=//" + redirectCanary,
}

// openRedirect detects redirect targets taken from user input.
//
// The judgement looks at the Location header rather than the body, and the
// mutation engine is what makes the canary survive a filter that would strip a
// plain absolute URL: a variant that is encoded, or that uses a scheme-relative
// form, reaches the same redirect with different bytes.
type openRedirect struct{}

func (openRedirect) ID() string                 { return "open-redirect" }
func (openRedirect) TitleKey() i18n.Key         { return i18n.KeyCheckRedirectTitle }
func (openRedirect) DescriptionKey() i18n.Key   { return i18n.KeyCheckRedirectDesc }
func (openRedirect) RemediationKey() i18n.Key   { return i18n.KeyCheckRedirectFix }
func (openRedirect) Severity() finding.Severity { return finding.SeverityMedium }
func (openRedirect) Tags() []string {
	return []string{"active", "redirect", "misconfiguration"}
}
func (openRedirect) Passive() bool { return false }

func (openRedirect) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	var location string
	attempt, err := c.SendVariants(ctx, t, payload.Redirect, "open-redirect", redirectSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			location = redirectTarget(resp)
			return location != ""
		})
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(openRedirect{}, t,
		i18n.KeyCheckRedirectTitle, i18n.KeyCheckRedirectDesc, i18n.KeyCheckRedirectFix)
	f.Severity = finding.SeverityMedium
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-601"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
		"https://cwe.mitre.org/data/definitions/601.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{"redirects to: " + location, variantNote(c, attempt)}
	return []*finding.Finding{f}
}

// redirectSinks are the constructs that actually send a browser somewhere.
//
// They are patterns rather than bare words, and that distinction is the whole
// reason this check is usable. A word like "location" or "url=" appears in pages
// for a dozen innocent reasons — a link, a field label, an error message that
// quotes a request — and treating any of them as a redirect turns every echoing
// page into a finding. What is left here are the two things that move a user:
// a script assigning to location, and a refresh directive, whether it arrives in
// a header or in a meta tag.
var redirectSinks = []*regexp.Regexp{
	// window.location = "…" / location.href = "…" / location.replace("…")
	regexp.MustCompile(`(?is)(window\s*\.\s*)?location\s*(\.\s*(href|replace|assign)\s*[=(]|=)`),
	// <meta http-equiv="refresh" content="0;url=…"> and the Refresh header.
	regexp.MustCompile(`(?is)http-equiv\s*=\s*["']?\s*refresh`),
	regexp.MustCompile(`(?is)refresh\s*[:=]\s*["']?\s*\d`),
}

// redirectTarget reports where a response sends the visitor, if it canary is
// redirected to at all.
//
// A redirect is not only a 3xx with a Location header. The same thing is
// expressed with a Refresh header, with a meta refresh in the document, and with
// a script that assigns to location — and a target that only writes one of the
// less common forms is not a target without an open redirect, it is a target an
// incomplete check misses.
//
// A bare occurrence of the canary in the body does not count, because a page
// that echoes its input would then look like every other page. What counts is
// the canary appearing near a word that marks the spot as a destination, which
// is why the search looks at the text around each occurrence rather than at the
// response as a whole.
func redirectTarget(resp *httpmsg.Response) string {
	if resp == nil {
		return ""
	}
	if location := resp.Header.Get("Location"); strings.Contains(location, redirectCanary) {
		return location
	}
	if refresh := resp.Header.Get("Refresh"); strings.Contains(refresh, redirectCanary) {
		return "Refresh: " + refresh
	}
	if len(resp.Body) == 0 || !strings.Contains(string(resp.Body), redirectCanary) {
		return ""
	}
	body := string(resp.Body)
	for offset := 0; ; {
		index := strings.Index(body[offset:], redirectCanary)
		if index < 0 {
			return ""
		}
		index += offset
		offset = index + len(redirectCanary)

		// A canary in a relative path stays on the same site: "/crackweb-…"
		// sends the browser to a page of the target's own, which is not an open
		// redirect whatever construct carries it.
		if index > 0 && body[index-1] == '/' {
			continue
		}
		// The window is short on purpose. A redirect names its destination right
		// after the construct that performs it — url=…, location.href = … — so
		// the canary has to sit close to the sink to count. A wider window was
		// tried and produced false findings on every page that both echoes its
		// input and happens to contain an unrelated refresh somewhere: the two
		// facts are unrelated, but a 240-byte search happily joins them.
		start := index - 48
		if start < 0 {
			start = 0
		}
		window := body[start:index]
		for _, sink := range redirectSinks {
			if sink.MatchString(window) {
				return extractAround(body, redirectCanary, 120)
			}
		}
	}
}

// crlfHeaderName is the header the injection tries to introduce. A name that does
// not exist in the wild means a match is conclusive.
const crlfHeaderName = "X-Crackweb-Injected"

// crlfSeeds carry the CRLF sequence in the forms a filter might not catch.
//
// They are written as real control characters rather than as percent escapes:
// the mutation engine encodes them once for transport, which is what a request
// requires, and derives the double-encoded forms that defeat a filter which
// normalises before matching. Writing `%0d%0a` by hand would produce `%250d%250a`
// on the wire — a literal percent sequence the application never decodes.
var crlfSeeds = []string{
	"\r\n" + crlfHeaderName + ": crlf",
	"\n" + crlfHeaderName + ": crlf",
	"\r\n " + crlfHeaderName + ": crlf",
	"\r\n\t" + crlfHeaderName + ": crlf",
	"\n " + crlfHeaderName + ": crlf",
	"\r\n" + crlfHeaderName + ":%20crlf",
}

// crlfInjection detects header injection through an unescaped parameter.
type crlfInjection struct{}

func (crlfInjection) ID() string                 { return "crlf-injection" }
func (crlfInjection) TitleKey() i18n.Key         { return i18n.KeyCheckCRLFTitle }
func (crlfInjection) DescriptionKey() i18n.Key   { return i18n.KeyCheckCRLFDesc }
func (crlfInjection) RemediationKey() i18n.Key   { return i18n.KeyCheckCRLFFix }
func (crlfInjection) Severity() finding.Severity { return finding.SeverityMedium }
func (crlfInjection) Tags() []string             { return []string{"active", "injection", "crlf"} }
func (crlfInjection) Passive() bool              { return false }

func (crlfInjection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	var injected string
	attempt, err := c.SendVariants(ctx, t, payload.CRLF, "crlf-injection", crlfSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			// The injected header has to arrive as a header. A payload reflected
			// in the body is a reflected-input issue, not header injection.
			value := resp.Header.Get(crlfHeaderName)
			if value == "" {
				return false
			}
			injected = value
			return true
		})
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(crlfInjection{}, t,
		i18n.KeyCheckCRLFTitle, i18n.KeyCheckCRLFDesc, i18n.KeyCheckCRLFFix)
	f.Severity = finding.SeverityMedium
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-113"
	f.References = []string{
		"https://owasp.org/www-community/vulnerabilities/HTTP_Response_Splitting",
		"https://cwe.mitre.org/data/definitions/113.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{crlfHeaderName + ": " + injected, variantNote(c, attempt)}
	return []*finding.Finding{f}
}
