package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// tokenParamNames are the fragments that identify an anti-CSRF field. They are
// fragments rather than exact names because the field is spelled differently by
// every framework: csrf_token, _csrf, authenticity_token, __RequestVerificationToken.
var tokenParamNames = []string{
	"csrf", "xsrf", "token", "nonce", "authenticity", "requestverification",
}

// csrfSimilarity is how alike a forged request's response must be to the genuine
// one for the token to be considered unenforced.
const csrfSimilarity = 0.95

// csrf detects state-changing requests whose anti-CSRF token is not actually
// checked.
//
// This is one of the few checks that can be conclusive without guessing, because
// the experiment is direct: send the request once as it was captured, then send
// it again with the token replaced by nonsense. If the application answers the
// same way both times, the token was decoration.
//
// The missing-token case is reported separately and more cautiously. A request
// with no token at all may be an API that authenticates with a header instead,
// so that finding is tentative — it points at something worth a look rather than
// asserting a vulnerability.
type csrf struct{}

func (csrf) ID() string                 { return "csrf" }
func (csrf) TitleKey() i18n.Key         { return i18n.KeyCheckCSRFTitle }
func (csrf) DescriptionKey() i18n.Key   { return i18n.KeyCheckCSRFDesc }
func (csrf) RemediationKey() i18n.Key   { return i18n.KeyCheckCSRFFix }
func (csrf) Severity() finding.Severity { return finding.SeverityMedium }
func (csrf) Tags() []string {
	return []string{"active", "csrf", "session", "owasp-top10"}
}
func (csrf) Passive() bool { return false }

func (csrf) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// Only requests that change something are worth protecting. A GET that
	// mutates state is its own bug, reported elsewhere.
	if t.Request.IsSafeMethod() {
		return nil
	}
	// A response that already failed cannot be a baseline: there is no
	// difference to measure when the request does not work in the first place.
	if t.Response.Status >= 400 {
		return nil
	}

	token := findTokenParam(t.Request)
	if token == nil {
		return nil
	}

	// Replace the token with a value the server cannot have issued, keeping its
	// length and alphabet so a length check cannot pass by accident.
	forged := forgeToken(token.Value)

	base := c.BaselineFingerprint(t)
	mutated, response, err := c.InjectEncoded(ctx, t, forged, checks.EncodeNone)
	if err != nil || response == nil {
		return nil
	}
	// A rejection is the correct behaviour, and means there is nothing to report.
	if response.Status >= 400 {
		return nil
	}
	similarity := diff.CompareFingerprints(base, c.Fingerprint(response)).Score
	if similarity < csrfSimilarity {
		return nil
	}

	f := checks.NewFinding(csrf{}, t,
		i18n.KeyCheckCSRFTitle, i18n.KeyCheckCSRFDesc, i18n.KeyCheckCSRFFix)
	f.Severity = finding.SeverityMedium
	f.Confidence = finding.ConfidenceFirm
	f.Payload = forged
	f.CWE = "CWE-352"
	f.References = []string{
		"https://owasp.org/www-community/attacks/csrf",
		"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		"https://cwe.mitre.org/data/definitions/352.html",
	}
	f.Evidence.Request = mutated.Raw()
	f.Evidence.Response = truncate(response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"the token field " + token.Name + " was replaced with a value the server never issued, and the request still succeeded",
	}
	f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceBoolean, round3(similarity), round3(similarity), round3(1))
	return []*finding.Finding{f}
}

// findTokenParam returns the request's anti-CSRF field, if it has one.
func findTokenParam(req *httpmsg.Request) *httpmsg.Param {
	params := req.Params()
	for i := range params {
		name := strings.ToLower(params[i].Name)
		for _, fragment := range tokenParamNames {
			if strings.Contains(name, fragment) {
				return &params[i]
			}
		}
	}
	return nil
}

// forgeToken produces a same-shaped value that the server cannot have issued.
//
// Length and character class are preserved deliberately: a server that checks
// the format before the value would reject an obviously malformed token, and the
// test would wrongly conclude the token is verified. Replacing every character
// means the forged value can never collide with a real one.
func forgeToken(original string) string {
	if original == "" {
		return "crackweb-forged-token"
	}
	var b strings.Builder
	b.Grow(len(original))
	for i := 0; i < len(original); i++ {
		c := original[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte('0' + (c-'0'+5)%10)
		case c >= 'a' && c <= 'z':
			b.WriteByte('a' + (c-'a'+13)%26)
		case c >= 'A' && c <= 'Z':
			b.WriteByte('A' + (c-'A'+13)%26)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
