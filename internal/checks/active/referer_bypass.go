package active

import (
	"context"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// refererBypass reports a request whose protection is a promise the browser did not make.
//
// A guard written on the `Referer` header assumes the header is always there and always from the
// application. Neither holds: the browser omits it when the referring page is a secure one and
// the target is not, when the page's policy says not to send it, and when the user has asked for
// privacy — and an attacker's page sends its own URL, which is the one value the attacker cannot
// choose but does not need to.
//
// The test is the one the Content-Type check makes, moved to another header: the request is sent
// the way it normally is with a token the server cannot have issued, and if that is refused the
// same request is sent with the header removed, and again with it pointing somewhere else. A
// guard that only holds when the header is present and correct is not a guard.
type refererBypass struct{}

func (refererBypass) ID() string                 { return "referer-bypass" }
func (refererBypass) TitleKey() i18n.Key         { return i18n.KeyCheckRefererBypassTitle }
func (refererBypass) DescriptionKey() i18n.Key   { return i18n.KeyCheckRefererBypassDesc }
func (refererBypass) RemediationKey() i18n.Key   { return i18n.KeyCheckRefererBypassFix }
func (refererBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (refererBypass) Tags() []string {
	return []string{"active", "csrf", "access-control", "owasp-top10"}
}
func (refererBypass) Passive() bool { return false }

// IsRequestLevel marks this as a check about the endpoint rather than about one parameter.
func (refererBypass) IsRequestLevel() bool { return true }

// refererBypassProbes are the header states tried against the refusal the correct header
// produces: absent, and naming somewhere else.
const refererBypassExternal = "https://crackweb-referer.example/"

func (refererBypass) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
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
	forged := forgeToken(token.Value)
	mutated, err := checks.Mutate(t.Request, *token, forged, checks.EncodeNone)
	if err != nil {
		return nil
	}

	// The reference: the same request with a forged token, sent the way it is normally sent. A
	// request that is accepted here has no guard for the probes to get around, which makes this
	// somebody else's finding rather than this one's.
	reference, err := c.Do(ctx, mutated)
	if err != nil || reference == nil || reference.Status < 400 {
		return nil
	}

	probes := []struct {
		label string
		apply func(*checks.Target) *httpmsg.Request
	}{
		{"the Referer header removed", func(*checks.Target) *httpmsg.Request {
			out := mutated.Clone()
			out.Header.Del("Referer")
			return out
		}},
		{"the Referer header naming another site", func(*checks.Target) *httpmsg.Request {
			out := mutated.Clone()
			out.Header.Set("Referer", refererBypassExternal)
			return out
		}},
	}
	for _, probe := range probes {
		attempt := probe.apply(t)
		response, err := c.Do(ctx, attempt)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}

		f := checks.NewFinding(refererBypass{}, t,
			i18n.KeyCheckRefererBypassTitle, i18n.KeyCheckRefererBypassDesc,
			i18n.KeyCheckRefererBypassFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Method = attempt.Method
		f.URL = t.Request.URLString()
		f.Payload = probe.label
		f.CWE = "CWE-352"
		f.DedupHostOnly = true
		f.DedupExtra = probe.label
		f.References = []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/352.html",
		}
		f.Evidence.Request = attempt.Raw()
		f.Evidence.Response = truncate(response.Body, 4096)
		f.Evidence.Baseline = truncate(reference.Body, 2048)
		f.Evidence.Matches = []string{
			"with the request as it is normally sent and a token the server cannot have issued, " +
				"the request was refused",
			"with the token still forged and " + probe.label + ", the same request was accepted",
			"the guard rests on a header the browser may omit and a caller may point elsewhere",
		}
		f.Evidence.Diff = extractAround(string(response.Body), firstLine(response.Body), 200)
		return []*finding.Finding{f}
	}
	return nil
}
