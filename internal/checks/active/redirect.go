package active

import (
	"context"
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
			redirect := resp.Header.Get("Location")
			if !resp.IsRedirect() || !strings.Contains(redirect, redirectCanary) {
				return false
			}
			location = redirect
			return true
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
	f.Evidence.Matches = []string{"Location: " + location, variantNote(c, attempt)}
	return []*finding.Finding{f}
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
