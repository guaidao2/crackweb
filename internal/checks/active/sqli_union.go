package active

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// unionMarkerBase starts a run of numbers used as column values. They are large
// and consecutive so that finding one in a page is not an accident, and so that
// how many of them were echoed says how many columns were visible.
const unionMarkerBase = 918273645

// unionMarkerRe recognises any of the marker numbers, in a form that survives
// the mutators: a keyword-splitting or case-swapping rewrite changes the SQL
// around the numbers but not the numbers themselves.
var unionMarkerRe = regexp.MustCompile(`9182736[0-9]{2}`)

// maxUnionColumns bounds the search. Beyond a dozen columns the guesswork costs
// more requests than the finding is worth, and real result sets that wide are
// usually reached a different way.
const maxUnionColumns = 12

// unionStability is how alike two back-to-back requests must be before their
// answers can be compared.
const unionStability = 0.98

// unionSeeds builds one payload per candidate column count.
//
// The column count has to be discovered because it cannot be guessed: a UNION
// whose arms disagree on width is a syntax error in every database, so the
// scanner asks for one column, then two, and so on, until the page stops
// complaining. The seeds go through the mutation engine afterwards, so a
// keyword filter in front of the query is defeated the same way it is for any
// other payload.
func unionSeeds() []string {
	seeds := make([]string, 0, maxUnionColumns)
	for columns := 1; columns <= maxUnionColumns; columns++ {
		values := make([]string, columns)
		for i := range values {
			values[i] = strconv.Itoa(unionMarkerBase + i)
		}
		seeds = append(seeds, "1' UNION SELECT "+strings.Join(values, ",")+"-- -")
	}
	return seeds
}

// unionColumnsIn reports how many marker numbers a payload carries, which is the
// column count it was built for.
func unionColumnsIn(sent string) int {
	return len(unionMarkerRe.FindAllString(sent, -1))
}

// unionTextNodeRe captures the text between tags.
//
// Searching the whole body is not enough, and the reason is the one this check
// exists to handle: a form that takes a search term prints it back into its own
// input field, so the payload — markers and all — is present in every response
// whether or not anything was injected. What separates the two is where the
// numbers appear. A value written into `value="…"` is the page handing the
// input back; a value sitting between tags is the page showing a result. Only
// the second is evidence.
var unionTextNodeRe = regexp.MustCompile(`>([^<>]*)<`)

// unionMarkersInText returns the marker numbers a page rendered as data.
//
// The test is: a marker appears in a text node that carries no SQL of its own.
// The second half matters for pages that render "no results for <term>" — there
// the term is text, but so is the statement that carried it, and a query result
// never arrives with the query attached.
func unionMarkersInText(body string) []string {
	var found []string
	for _, match := range unionTextNodeRe.FindAllStringSubmatch(body, -1) {
		text := match[1]
		if strings.Contains(strings.ToUpper(text), "UNION") {
			// The statement came back with the numbers, so this is a rendering
			// of the input rather than a rendering of the result.
			continue
		}
		found = append(found, unionMarkerRe.FindAllString(text, -1)...)
	}
	return found
}

// unionMarkersLanded reports whether any marker was rendered as data.
func unionMarkersLanded(body, sent string) bool {
	return len(unionMarkersInText(body)) > 0
}

// unionMarkersAboveEcho reports whether the page rendered more markers than it renders for
// the same number sent as plain input.
//
// A negative echo count means the probe could not be sent, and the check falls back to the
// plain test: it is worse to miss an injection than to report one this page already shows.
func unionMarkersAboveEcho(body string, echoed int) bool {
	landed := len(unionMarkersInText(body))
	if echoed < 0 {
		return landed > 0
	}
	return landed > echoed
}

// sqliUnion detects SQL injection by extending the query's result set.
//
// It exists because the other three SQL checks each need something a hardened
// target may withhold: an error message, a response that tracks a boolean, or
// enough time to notice. A page that simply prints the rows it was given gives
// away nothing to any of them, and everything to this one.
type sqliUnion struct{}

func (sqliUnion) ID() string                 { return "sqli-union" }
func (sqliUnion) TitleKey() i18n.Key         { return i18n.KeyCheckSQLiUnionTitle }
func (sqliUnion) DescriptionKey() i18n.Key   { return i18n.KeyCheckSQLiUnionDesc }
func (sqliUnion) RemediationKey() i18n.Key   { return i18n.KeyCheckSQLiUnionFix }
func (sqliUnion) Severity() finding.Severity { return finding.SeverityCritical }
func (sqliUnion) Tags() []string {
	return []string{"active", "injection", "sqli", "owasp-top10"}
}
func (sqliUnion) Passive() bool { return false }

func (sqliUnion) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Param == nil || t.Response == nil {
		return nil
	}

	// The judgement is "the page gained numbers", so the page has to be steady
	// enough for that to mean anything.
	baseline := c.StableBaseline(ctx, t.Request, unionStability)
	if baseline == nil {
		return nil
	}
	// A page that already contains the marker cannot be used to detect it.
	if unionMarkerRe.MatchString(string(baseline.Body)) {
		return nil
	}

	c.ProbeWAF(ctx, t)

	// A page that echoes the term back renders the marker whether or not anything was
	// injected — this one puts it in the page title and again in a heading, both of them text
	// nodes. The literal test inside unionMarkersInText catches the echo when the statement
	// comes back with the marker, but a payload written to get past a filter does not carry
	// that literal: `UN/**/ION` is still a UNION to the database and not one to a substring
	// search, which is exactly why the mutation engine produced it.
	//
	// So measure the echo instead of guessing at it. Asking for the marker as ordinary input
	// shows what this page does with any value it is handed; only a count above that is the
	// query answering with rows of its own.
	echoed := -1
	if _, response, err := c.InjectEncoded(ctx, t, strconv.Itoa(unionMarkerBase), checks.EncodeURL); err == nil && response != nil {
		echoed = len(unionMarkersInText(string(response.Body)))
	}

	attempt, err := c.SendVariants(ctx, t, payload.SQLi, "sqli-union", unionSeeds(),
		func(_ *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool {
			return unionMarkersAboveEcho(string(resp.Body), echoed)
		})
	if err != nil || attempt == nil {
		return nil
	}

	columns := unionColumnsIn(attempt.Variant.Value)
	// The same function that accepted the evidence reports it, so the count in
	// the finding is the count that was judged rather than a broader one.
	landed := unionMarkersInText(string(attempt.Response.Body))

	f := checks.NewFinding(sqliUnion{}, t,
		i18n.KeyCheckSQLiUnionTitle, i18n.KeyCheckSQLiUnionDesc, i18n.KeyCheckSQLiUnionFix)
	f.Severity = finding.SeverityCritical
	// Firm, not certain: the rows are demonstrably caller-controlled, but a page
	// could in principle be replaying a stored value rather than a fresh query.
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-89"
	f.References = sqlReferences
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(baseline.Body, 4096)
	f.Evidence.Matches = []string{
		fmt.Sprintf("a %d-column UNION SELECT was accepted", columns),
		fmt.Sprintf("%d injected value(s) appeared in the page as data: %s",
			len(landed), strings.Join(landed, " ")),
		variantNote(c, attempt),
	}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), fmt.Sprintf("%d", unionMarkerBase), 240)
	return []*finding.Finding{f}
}
