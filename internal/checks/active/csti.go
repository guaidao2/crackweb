package active

import (
	"context"
	"strconv"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// csti reports a page that hands a value from the URL to a template compiler.
//
// It is the client-side twin of the server-side template check, and it needs the same
// thing that one does — the value has to be evaluated — but the evaluation happens in the
// browser and leaves nothing in the response. The page returns the same bytes whether it
// compiles the value or escapes it, so the question is asked of the rendered document:
// the probe is an expression, and the answer is the number it evaluates to.
//
// A distinct product is used rather than a boolean, for the reason the server-side check
// uses one: any page may contain "true", but no page contains the product of two
// four-digit numbers by accident.
type csti struct{}

const cstiProduct = "3996001"

func (csti) ID() string                 { return "client-template-injection" }
func (csti) TitleKey() i18n.Key         { return i18n.KeyCheckCSTITitle }
func (csti) DescriptionKey() i18n.Key   { return i18n.KeyCheckCSTIDesc }
func (csti) RemediationKey() i18n.Key   { return i18n.KeyCheckCSTIFix }
func (csti) Severity() finding.Severity { return finding.SeverityHigh }
func (csti) Tags() []string {
	return []string{"active", "injection", "client-side", "template", "owasp-top10"}
}
func (csti) Passive() bool { return false }

// IsRequestLevel marks this as a check about the page rather than about one parameter.
func (csti) IsRequestLevel() bool { return true }

// NeedsBrowser marks this as a check a response cannot answer.
func (csti) NeedsBrowser() bool { return true }

// IsUnsafe marks this as more than a request: the page is loaded in a real browser, which
// runs every script it carries.
func (csti) IsUnsafe() bool { return true }

// cstiProbeShapes are the interpolations the common client-side compilers evaluate. The
// spaced form is separate because a filter written against `{{` may only look for the
// unspaced one, and the `$` form because a page built on a different compiler evaluates
// none of the brace forms.
var cstiProbeShapes = []string{
	"{{1999*1999}}",
	"{{ 1999*1999 }}",
	"${1999*1999}",
}

// maxCSTICandidates bounds how many addresses one page is loaded with. Each is a browser
// load, and the fragment plus the first parameters is where a value reaches a compiler.
const maxCSTICandidates = 5

// cstiExpression answers whether the rendered document carries the product. It reads the
// text a person would see rather than the markup, so a page that shows the value encoded
// is not counted.
func cstiExpression() string {
	quoted := strconv.Quote(cstiProduct)
	return `(function () { try { var text = (document.body && document.body.innerText) || "";` +
		` return text.indexOf(` + quoted + `) >= 0 ? "evaluated" : ""; } catch (e) { return ""; } })()`
}

func (csti) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if c.Browser == nil || t == nil || t.Request == nil || t.Request.URL == nil {
		return nil
	}
	expression := cstiExpression()

	// The page as it is. A page that already shows the product cannot be used as
	// evidence, for the same reason the server-side check refuses such a baseline.
	if answer, err := c.Browser.Eval(ctx, t.Request.URLString(), expression); err != nil || answer != "" {
		return nil
	}

	for _, shape := range cstiProbeShapes {
		for _, candidate := range cstiCandidates(t.Request, shape) {
			answer, err := c.Browser.Eval(ctx, candidate.url, expression)
			if err != nil || answer == "" {
				continue
			}

			f := checks.NewFinding(csti{}, t,
				i18n.KeyCheckCSTITitle, i18n.KeyCheckCSTIDesc, i18n.KeyCheckCSTIFix)
			f.Severity = finding.SeverityHigh
			// Firm rather than certain: the expression was evaluated, which is what a
			// template compiler does. Whether the value could equally have been crafted
			// to run code depends on the compiler, which this check does not fingerprint.
			f.Confidence = finding.ConfidenceFirm
			f.Method = "GET"
			f.URL = candidate.url
			f.Payload = shape
			f.DedupExtra = candidate.name
			f.CWE = "CWE-1336"
			f.References = []string{
				"https://portswigger.net/web-security/server-side-template-injection",
				"https://cwe.mitre.org/data/definitions/1336.html",
			}
			f.Evidence.Request = []byte("GET " + candidate.url + " HTTP/1.1\r\nHost: " +
				t.Request.Host() + "\r\n\r\n")
			f.Evidence.Matches = []string{
				candidate.name + ": " + shape + " evaluated in the browser and the page shows " + cstiProduct,
				"the value reached a template compiler — the same input class that carries code " +
					"in this compiler's syntax",
			}
			f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceRenderedText, cstiProduct)
			return []*finding.Finding{f}
		}
	}
	return nil
}

// cstiCandidate is one address that carries the probe, and the marker that names it in the
// report.
type cstiCandidate struct {
	name string
	url  string
}

// cstiCandidates returns the addresses worth loading: the fragment, which the server never
// sees, and each query parameter, which the page reads back for itself.
func cstiCandidates(req *httpmsg.Request, shape string) []cstiCandidate {
	out := []cstiCandidate{{
		name: "url fragment",
		// The fragment is appended as written: encoding it would deliver a string the
		// compiler no longer recognises, and recognising it is the point.
		url: req.URLString() + "#" + shape,
	}}
	for _, param := range req.QueryParams() {
		if len(out) >= maxCSTICandidates {
			break
		}
		mutated, err := checks.Mutate(req, param, shape, checks.EncodeURL)
		if err != nil || mutated == nil || mutated.URL == nil {
			continue
		}
		out = append(out, cstiCandidate{
			name: string(param.In) + ":" + param.Name,
			url:  mutated.URLString(),
		})
	}
	return out
}
