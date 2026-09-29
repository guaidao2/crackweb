package active

import (
	"context"
	"fmt"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// A parameter that reaches ORDER BY is invisible to every other SQL check. The
// position accepts an expression but not a quoted string, so breaking it with a
// quote yields an error page the error check can get from a WHERE clause just as
// easily; it accepts no UNION, so the union check has nothing to extend; and a
// column name cannot be bound, which is why the flaw survives frameworks that
// parameterise everything else.
//
// What the position does accept is a comma — another term in the list — and what
// it rejects, and only it rejects, is a term naming a column the result set does
// not have. Those two answers are the evidence this check is built on:
//
//	in range      `,1`  — the statement still runs and the result is unchanged
//	past the end  `,99` — the sort list names a column that is not there, so the
//	                      query fails
//
// `ORDER BY 99` is an error in every engine there is. `WHERE name='x,99'` is a
// string, and accepts the term without noticing; `WHERE id=x,99` fails on `,1`
// first; a value that never reaches a query accepts both. So the pair is the
// sorting position's own signature, and neither a quoted string nor "the page
// changed" is needed to reach it — which is what an earlier version of this
// check mistook for evidence, and reported on every parameter the application
// happened to react to.
//
// Nothing here is decided from the parameter's name. A sort column is called
// `order`, `sortby`, `col`, `f`, `by`, `key`, `_s` or anything else its author
// chose, and a check that only looked where the word "order" appears would miss
// the injection in the rest — a scanner's coverage cannot be a guess about
// naming. The cost of asking every parameter is bounded instead by the order the
// questions are asked in: a parameter that is not a sort term is refused by the
// first term below and never reaches the second.
type sqliOrderBy struct{}

func (sqliOrderBy) ID() string                 { return "sqli-order-by" }
func (sqliOrderBy) TitleKey() i18n.Key         { return i18n.KeyCheckSQLiOrderByTitle }
func (sqliOrderBy) DescriptionKey() i18n.Key   { return i18n.KeyCheckSQLiOrderByDesc }
func (sqliOrderBy) RemediationKey() i18n.Key   { return i18n.KeyCheckSQLiOrderByFix }
func (sqliOrderBy) Severity() finding.Severity { return finding.SeverityHigh }
func (sqliOrderBy) Tags() []string {
	return []string{"active", "injection", "sqli", "blind", "owasp-top10"}
}
func (sqliOrderBy) Passive() bool { return false }

// inRangeTerms are appended terms any query can accept: a constant in the sort
// list. Appended to a sorting clause they leave the result order untouched,
// because one more constant term cannot reorder equal keys; appended to a value
// used as a string they change nothing at all.
var inRangeTerms = []string{",1", ",2"}

// outOfRangeTerms name a column position no ordinary result set has.
//
// A sorting clause refuses them — the error is about the ORDER BY list itself —
// while every other context either accepts them as text or has already failed on
// the in-range terms above. Two values rather than one because the bound is not
// knowable in advance: a query can legitimately have up to ninety-nine columns,
// and the check has to see both of them refused rather than take the first
// refusal as a verdict.
var outOfRangeTerms = []string{",99", ",999"}

func (sqliOrderBy) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Param == nil || t.Response == nil {
		return nil
	}
	// A session cookie selects which session the request is served as, so
	// changing its value changes the page for a reason that has nothing to do
	// with any query. A session identifier is not a sort column either.
	if t.Param.In == httpmsg.LocCookie && isSessionCookie(t.Param.Name) {
		return nil
	}
	// Every term below is appended to the value the caller already supplied, so a
	// parameter with nothing in it gives nothing to append to: `ORDER BY ,1` is
	// not a sort term, and an endpoint that takes no value at all has no position
	// this method can address. That is a limit of the technique, not a judgement
	// about which parameters are worth testing.
	if strings.TrimSpace(t.Param.Value) == "" {
		return nil
	}

	base := c.BaselineFingerprint(t)
	if base == nil || base.NormLen == 0 {
		return nil
	}
	c.ProbeWAF(ctx, t)

	// baseUnder returns the baseline fingerprinted the way a probe is: a page
	// that echoes the parameter value has to be compared against the value it
	// echoed, not against the payload. The restore list goes on both sides of
	// every comparison below, and that symmetry is the point — a replacement that
	// also matches text the page wrote for its own reasons (`1"` inside
	// `size="1"`) then shortens both fingerprints equally, where applying it to
	// one side only manufactures a difference that is not there.
	baseUnder := func(value string) *diff.Fingerprint {
		return c.Fingerprint(t.Response, echoRestore(value, t.Param.Value)...)
	}

	probe := func(suffix string) (string, *httpmsg.Request, *httpmsg.Response, *diff.Fingerprint, bool) {
		value := t.Param.Value + suffix
		request, response, err := c.InjectEncoded(ctx, t, value, checks.EncodeURL)
		if err != nil || request == nil || response == nil {
			return "", nil, nil, nil, false
		}
		// A refusal from something in front of the application is not the query
		// answering. These terms carry no quote, so a firewall has little to
		// recognise, but a target that answers 403 to anything still must not be
		// read as a clause that reacted.
		if c.WAF.IsBlocked(request.Hostname(), response) {
			return "", nil, nil, nil, false
		}
		return value, request, response, c.Fingerprint(response, echoRestore(value, t.Param.Value)...), true
	}

	// accepted reports whether a term was taken and the page is the page. The
	// status has to stand still as well: a term that makes the application fail
	// is a term it refused, whatever the body says.
	accepted := func(suffix string) bool {
		value, _, response, fp, ok := probe(suffix)
		if !ok || response.Status != t.Response.Status {
			return false
		}
		return fp.NormHash == baseUnder(value).NormHash
	}

	// refused reports whether a term was not taken, with the request and response
	// that showed it for the evidence.
	refused := func(suffix string) (*httpmsg.Request, *httpmsg.Response, *diff.Fingerprint, bool) {
		value, request, response, fp, ok := probe(suffix)
		if !ok {
			return nil, nil, nil, false
		}
		if fp.NormHash == baseUnder(value).NormHash {
			return nil, nil, nil, false
		}
		return request, response, fp, true
	}

	// In range first, because it is the cheap half: a numeric context, a
	// whitelist and a value the application never uses all fail it, and a target
	// that is not a sort list therefore costs one request rather than four.
	if !accepted(inRangeTerms[0]) {
		return nil
	}
	// Past the end. Everything except a sort list accepts this one too — a string
	// context as text, an ignored value by not caring — so an acceptance here
	// ends the check.
	pastEndRequest, pastEndResponse, pastEndFP, ok := refused(outOfRangeTerms[0])
	if !ok {
		return nil
	}
	pastEndValue := t.Param.Value + outOfRangeTerms[0]

	// The second in-range term is what tells the two shapes of a sorting clause
	// apart, and neither answer contradicts the position. A result set of two
	// columns or more has room for it; a single-column one does not, and its
	// refusal is the boundary itself — the same failure the far bound produces.
	// Assuming room for it would quietly exclude every one-column query, which is
	// a shape real endpoints have.
	if accepted(inRangeTerms[1]) {
		// Two or more columns: confirm the far bound too, so that one flaky
		// response cannot carry the finding.
		if _, _, _, ok := refused(outOfRangeTerms[1]); !ok {
			return nil
		}
	} else {
		boundaryRequest, boundaryResponse, boundaryFP, ok := refused(inRangeTerms[1])
		if !ok {
			return nil
		}
		// The boundary the second term hit has to be the same one the far bound
		// hit, or the refusal came from something other than the column list.
		if boundaryFP.NormHash != pastEndFP.NormHash {
			return nil
		}
		pastEndRequest, pastEndResponse, pastEndFP = boundaryRequest, boundaryResponse, boundaryFP
		pastEndValue = t.Param.Value + inRangeTerms[1]
	}

	f := checks.NewFinding(sqliOrderBy{}, t,
		i18n.KeyCheckSQLiOrderByTitle, i18n.KeyCheckSQLiOrderByDesc, i18n.KeyCheckSQLiOrderByFix)
	f.Severity = finding.SeverityHigh
	// Firm rather than certain: the position is provably a sort list, and what it
	// would execute beyond a column number is not something this check goes on to
	// demonstrate.
	f.Confidence = finding.ConfidenceFirm
	// The value that produced the evidence, not the first one in a list: a report
	// whose payload does not reproduce its own finding is worse than no report.
	f.Payload = pastEndValue
	f.CWE = "CWE-89"
	f.References = sqlReferences
	f.Evidence.Request = pastEndRequest.Raw()
	f.Evidence.Response = truncate(pastEndResponse.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		fmt.Sprintf("a term in range (%q) was accepted: the page did not change", inRangeTerms[0]),
		fmt.Sprintf("a column position past the end of the result set (%q) was refused: the "+
			"sorting clause is built from the value", pastEndValue),
	}
	f.Evidence.Diff = renderLineDiff(baseUnder(pastEndValue).NormText, pastEndFP.NormText, 20)
	return []*finding.Finding{f}
}

// renderLineDiff renders what a probe rendered that the baseline did not, which
// is what a reader wants to see when the evidence is "the query failed": an
// empty result set where there were rows.
func renderLineDiff(baseText, curText string, maxLines int) string {
	lines := diff.Text(baseText, curText, maxLines)
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for _, line := range lines {
		switch line.Kind {
		case diff.LineRemoved:
			b.WriteString("- " + line.Text + "\n")
		case diff.LineAdded:
			b.WriteString("+ " + line.Text + "\n")
		default:
			fmt.Fprintf(&b, "… %d more line(s)\n", line.Elided)
		}
	}
	return strings.TrimSpace(b.String())
}

// sessionCookieNames are cookie names whose value identifies a session rather than carrying
// data the application parses. Changing one changes who the request is served as, not what
// it asks for.
var sessionCookieNames = []string{
	"phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid", "sessionid",
	"session", "sessid", "sid", "connect.sid", "laravel_session", "ci_session",
	"_session_id", "rack.session", "csrf", "xsrf",
}

// isSessionCookie reports whether a cookie name identifies a session.
func isSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, known := range sessionCookieNames {
		if strings.Contains(lower, known) {
			return true
		}
	}
	return false
}
