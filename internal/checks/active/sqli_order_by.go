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

// orderByFamilies are conditions that a sorting clause must treat alike.
//
// A parameter that reaches ORDER BY (or LIMIT, or GROUP BY) is invisible to
// every other SQL check. The position accepts an expression but not a quoted
// string, so a quote only ever produces a syntax error; it accepts no UNION, so
// the union check has nothing to extend; and the column list cannot be
// parameterised, which is precisely why the flaw exists. What it does accept is
// a comma — another term in the list — and that is the opening these use.
//
// The judgement applies the same equivalence idea as the boolean check, but only
// to the accepted forms: `(select 1)` and `(select 2)` must render the same page
// as each other and as the baseline. The rejected forms are only required to
// differ from it, because an error page quotes the input that caused it.
//
// The false forms are syntax breaks rather than arithmetic ones. `1/0` looked
// like a portable way to force an error and is not: SQLite returns NULL for it,
// so the page never changes and the probe proves nothing. A stray quote breaks
// the statement in every engine there is.
var orderByFamilies = []struct {
	name        string
	trueValues  []string
	falseValues []string
}{
	{
		name:        "appended term",
		trueValues:  []string{",(select 1)", ",(select 2)"},
		falseValues: []string{"'", `"`},
	},
	{
		name:        "after a direction",
		trueValues:  []string{" ASC,(select 1)", " ASC,(select 2)"},
		falseValues: []string{" ASC'", ` ASC"`},
	},
	{
		name:        "appended literal",
		trueValues:  []string{",1", ",2"},
		falseValues: []string{"'", `"`},
	},
}

// sqliOrderBy detects injection into a sorting or limiting clause.
//
// It exists because the position is a blind spot for the other checks rather
// than a rare case: any list view with a sortable column has one, and the usual
// remedy — binding the value — does not apply to a column name, so the flaw
// survives frameworks that parameterise everything else.
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

func (sqliOrderBy) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Param == nil || t.Response == nil {
		return nil
	}

	base := c.BaselineFingerprint(t)
	if base == nil || base.NormLen == 0 {
		return nil
	}
	c.ProbeWAF(ctx, t)

	prefix := t.Param.Value
	if strings.TrimSpace(prefix) == "" {
		prefix = "1"
	}

	for _, family := range orderByFamilies {
		probe := func(suffix string) (string, *httpmsg.Request, *httpmsg.Response, bool) {
			value := prefix + suffix
			request, response, err := c.InjectEncoded(ctx, t, value, checks.EncodeURL)
			if err != nil || request == nil || response == nil {
				return "", nil, nil, false
			}
			// A refusal from something in front of the application is not the query
			// answering. The difference it makes belongs to whatever refused it, and taking
			// it for evidence is how a defended target produces findings: these terms carry
			// quotes, a signature-based firewall refuses those, and the resulting difference
			// looks exactly like a query that noticed.
			if c.WAF.IsBlocked(request.Hostname(), response) {
				return "", nil, nil, false
			}
			return value, request, response, true
		}

		trueOne, trueReq, trueResp, ok := probe(family.trueValues[0])
		if !ok {
			continue
		}
		_, _, secondTrue, ok := probe(family.trueValues[1])
		if !ok {
			continue
		}
		_, _, firstFalse, ok := probe(family.falseValues[0])
		if !ok {
			continue
		}
		falseTwo, _, secondFalse, ok := probe(family.falseValues[1])
		if !ok {
			continue
		}

		fp := func(value string, resp *httpmsg.Response) *diff.Fingerprint {
			return c.Fingerprint(resp, echoRestore(value, t.Param.Value)...)
		}
		a, b := fp(trueOne, trueResp), fp(family.trueValues[1], secondTrue)
		cc, d := fp(family.falseValues[0], firstFalse), fp(falseTwo, secondFalse)

		// The same equivalence test the boolean check applies: conditions that
		// evaluate alike must render alike, or the difference is not the query.
		// The equivalence test goes on the accepted forms, which is where it is
		// clean: two valid terms must render the same page as each other and as
		// the baseline.
		if a.NormHash != b.NormHash || a.NormHash != base.NormHash {
			continue
		}
		// The rejected forms only have to diverge from it, not from each other.
		// Error text quotes whatever broke it — SQLite says which token was
		// unexpected — so two different broken inputs legitimately produce two
		// different error pages, and requiring them to agree would reject every
		// real finding.
		if cc.NormHash == base.NormHash && d.NormHash == base.NormHash {
			continue
		}

		f := checks.NewFinding(sqliOrderBy{}, t,
			i18n.KeyCheckSQLiOrderByTitle, i18n.KeyCheckSQLiOrderByDesc, i18n.KeyCheckSQLiOrderByFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Payload = family.falseValues[0]
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = trueReq.Raw()
		f.Evidence.Response = truncate(firstFalse.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			"a valid term appended to the clause (" + trueOne + ") left the page unchanged",
			"an invalid one (" + family.falseValues[0] + ") did not, and equivalents of each " +
				"reproduced their group",
		}
		return []*finding.Finding{f}
	}
	return nil
}
