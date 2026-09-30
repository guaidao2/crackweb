package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// contentTypeBypass reports a request whose protection is attached to one Content-Type.
//
// The mistake is a guard written inside a branch: the form handler checks the token, and the
// other branches — added later, for a JSON client, or for a body the framework was not sure
// how to read — assume somebody else does. The request that reaches them is the same request,
// with the token removed and a different label on the body.
//
// So the test is two requests rather than one. The first keeps the request's own Content-Type
// and drops the token: if that is still accepted there is no protection to get around, which
// makes this somebody else's finding rather than this one's. Only when the token's absence is
// refused does the second request mean anything — the same body, the same missing token, and a
// Content-Type the guard does not cover.
type contentTypeBypass struct{}

func (contentTypeBypass) ID() string                 { return "content-type-bypass" }
func (contentTypeBypass) TitleKey() i18n.Key         { return i18n.KeyCheckContentTypeBypassTitle }
func (contentTypeBypass) DescriptionKey() i18n.Key   { return i18n.KeyCheckContentTypeBypassDesc }
func (contentTypeBypass) RemediationKey() i18n.Key   { return i18n.KeyCheckContentTypeBypassFix }
func (contentTypeBypass) Severity() finding.Severity { return finding.SeverityMedium }
func (contentTypeBypass) Tags() []string {
	return []string{"active", "csrf", "access-control", "owasp-top10"}
}
func (contentTypeBypass) Passive() bool { return false }

// IsRequestLevel marks this as a check about the endpoint rather than about one parameter.
func (contentTypeBypass) IsRequestLevel() bool { return true }

// contentTypeSimpleTypes are the types a browser will send cross-site without asking first. A
// guard that misses one of these is the difference between a request an attacker cannot send and
// one they can.
var contentTypeSimpleTypes = []string{"text/plain"}

// contentTypeSpellings are label changes that leave the body exactly as it was: another type a
// browser can send, the form type under another spelling, and a type written with the case a
// strict comparison does not match.
var contentTypeSpellings = []string{
	"Application/X-WWW-Form-Urlencoded",
	"application/x-www-form-urlencoded; charset=UTF-8",
}

func (contentTypeBypass) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	// A request-level check is dispatched once for the target, and that visit has no single
	// parameter attached to it: the check is about the request, and the field it is looking for
	// is one it finds itself.
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	if t.Request.IsSafeMethod() || t.Response.Status >= 400 || !t.Request.HasBody() {
		return nil
	}
	token := findTokenParam(t.Request)
	if token == nil {
		return nil
	}

	original := t.Request.ContentType()
	if original == "" {
		return nil
	}
	forged := forgeToken(token.Value)
	mutated, err := checks.Mutate(t.Request, *token, forged, checks.EncodeNone)
	if err != nil {
		return nil
	}

	// The reference: the same request with the token removed, sent the way it is normally sent.
	// If this is accepted, there is no guard for the next request to get around.
	reference, err := c.Do(ctx, mutated)
	if err != nil || reference == nil || reference.Status < 400 {
		return nil
	}

	for _, candidate := range append(append([]string{}, contentTypeSimpleTypes...), contentTypeSpellings...) {
		if strings.EqualFold(candidate, original) {
			continue
		}
		attempt := mutated.Clone()
		attempt.Header.Set("Content-Type", candidate)
		response, err := c.Do(ctx, attempt)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}

		f := checks.NewFinding(contentTypeBypass{}, t,
			i18n.KeyCheckContentTypeBypassTitle, i18n.KeyCheckContentTypeBypassDesc,
			i18n.KeyCheckContentTypeBypassFix)
		// A type a browser sends without a preflight is reachable from another site, so the
		// guard being absent there is a cross-site request rather than only a local one.
		f.Severity = finding.SeverityMedium
		if containsFold(contentTypeSimpleTypes, candidate) {
			f.Severity = finding.SeverityHigh
		}
		f.Confidence = finding.ConfidenceFirm
		f.Method = attempt.Method
		f.URL = t.Request.URLString()
		f.DedupHostOnly = true
		f.DedupExtra = candidate
		f.Payload = "Content-Type: " + candidate
		f.CWE = "CWE-352"
		f.References = []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/352.html",
		}
		f.Evidence.Request = attempt.Raw()
		f.Evidence.Response = truncate(response.Body, 4096)
		f.Evidence.Baseline = truncate(reference.Body, 2048)
		f.Evidence.Matches = []string{
			"with the request's own Content-Type (" + original + ") and a token the server cannot " +
				"have issued, the request was refused",
			"with the body unchanged and Content-Type set to " + candidate + ", the same request " +
				"was accepted",
			"the guard is attached to one Content-Type, so a caller chooses whether it applies",
		}
		f.Evidence.Diff = extractAround(string(response.Body), firstLine(response.Body), 200)
		return []*finding.Finding{f}
	}
	return nil
}

// containsFold reports whether the list holds the value, ignoring case.
func containsFold(list []string, value string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

// firstLine returns the first line of the body, which is what the diff is centred on when the
// finding is about the request rather than about a string the response carries.
func firstLine(body []byte) string {
	line := strings.SplitN(string(body), "\n", 2)[0]
	if len(line) > 64 {
		line = line[:64]
	}
	return strings.TrimSpace(line)
}
