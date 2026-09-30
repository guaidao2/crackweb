package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// prototypePollution reports a page whose query string reaches an object merge that
// copies `__proto__`.
//
// Every response-level test is blind to this: the bytes are identical whether the page
// merges safely or not, and what changes is only the runtime. So the page is loaded, the
// same page is loaded again with a property named after a random marker, and a fresh
// object is asked whether it has that property. A property that a brand-new object can see
// did not come from the object — it came from the prototype everything shares, which is
// the whole of the flaw: what one request installs, every later piece of code inherits.
//
// The control matters as much as the probe. A page that answers yes *without* the injected
// property is answering about something else — its own global, a framework's default — and
// reporting that would be reporting the wrong thing.
type prototypePollution struct{}

func (prototypePollution) ID() string { return "prototype-pollution" }
func (prototypePollution) TitleKey() i18n.Key {
	return i18n.KeyCheckPrototypePollutionTitle
}
func (prototypePollution) DescriptionKey() i18n.Key {
	return i18n.KeyCheckPrototypePollutionDesc
}
func (prototypePollution) RemediationKey() i18n.Key {
	return i18n.KeyCheckPrototypePollutionFix
}
func (prototypePollution) Severity() finding.Severity { return finding.SeverityHigh }
func (prototypePollution) Tags() []string {
	return []string{"active", "injection", "client-side", "prototype-pollution", "owasp-top10"}
}
func (prototypePollution) Passive() bool { return false }

// IsRequestLevel marks this as a check about the page rather than about one parameter: the
// carrier is the address's own query string.
func (prototypePollution) IsRequestLevel() bool { return true }

// NeedsBrowser marks this as a check a response cannot answer.
func (prototypePollution) NeedsBrowser() bool { return true }

// IsUnsafe marks this as more than a request: the page is loaded in a real browser, which
// runs every script it carries.
func (prototypePollution) IsUnsafe() bool { return true }

// pollutionValue is what the injected property is set to. A value that matches the marker
// proves the property came from this request rather than from the page's own code.
const pollutionValue = "crackwebpolluted"

// prototypePollutionPayloads are the spellings a query parser turns into a nested
// assignment. Which one lands depends on the parsing library and on how its recursion
// handles a name it does not expect, so all three are sent.
var prototypePollutionPayloads = []string{
	"__proto__[%s]=%s",
	"constructor[prototype][%s]=%s",
	"__proto__.%s=%s",
}

// pollutionExpression asks a freshly created object whether it carries the property. The
// lookup follows the prototype chain, which is exactly what is being tested: if a new
// object can see the property, `Object.prototype` was written to.
func pollutionExpression(marker string) string {
	quoted := strconv.Quote(marker)
	return `(function () { try { var fresh = {}; if (typeof fresh[` + quoted + `] !== "undefined") {` +
		` return String(fresh[` + quoted + `]); } var proto = Object.getPrototypeOf(fresh);` +
		` if (proto && typeof proto[` + quoted + `] !== "undefined") { return String(proto[` + quoted + `]); }` +
		` if (Object.prototype && typeof Object.prototype[` + quoted + `] !== "undefined") {` +
		` return String(Object.prototype[` + quoted + `]); } } catch (e) {} return ""; })()`
}

// pollutionMarker returns a property name nothing else would be using.
func pollutionMarker() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "crackwebprobe"
	}
	return "crackwebprobe" + hex.EncodeToString(raw[:])
}

func (prototypePollution) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if c.Browser == nil || t == nil || t.Request == nil || t.Request.URL == nil {
		return nil
	}
	marker := pollutionMarker()
	expression := pollutionExpression(marker)

	// The page as it is, before anything is injected. A property that is already visible
	// here belongs to the page, and every later answer would be about it.
	control, err := c.Browser.Eval(ctx, t.Request.URLString(), expression)
	if err != nil || strings.Contains(control, pollutionValue) {
		return nil
	}

	for _, shape := range prototypePollutionPayloads {
		injection := fmt.Sprintf(shape, marker, pollutionValue)
		target := pollutionAddress(t.Request, injection)

		answer, err := c.Browser.Eval(ctx, target, expression)
		if err != nil || !strings.Contains(answer, pollutionValue) {
			continue
		}

		f := checks.NewFinding(prototypePollution{}, t,
			i18n.KeyCheckPrototypePollutionTitle, i18n.KeyCheckPrototypePollutionDesc,
			i18n.KeyCheckPrototypePollutionFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Method = "GET"
		f.URL = target
		f.Payload = injection
		f.CWE = "CWE-1321"
		f.References = []string{
			"https://owasp.org/www-community/vulnerabilities/Prototype_Pollution",
			"https://cwe.mitre.org/data/definitions/1321.html",
		}
		f.Evidence.Request = []byte("GET " + target + " HTTP/1.1\r\nHost: " +
			t.Request.Host() + "\r\n\r\n")
		f.Evidence.Matches = []string{
			"the query string reached an object merge: " + injection,
			"a brand-new object carries the property, so it is on Object.prototype and every " +
				"later piece of code inherits it",
		}
		f.Evidence.Diff = "new {}[" + marker + "] === " + pollutionValue
		return []*finding.Finding{f}
	}
	return nil
}

// pollutionAddress appends an injection to the address's query string. The brackets are
// left as written: they are legal in a query, and a parser that expects the nested form
// reads them either way.
func pollutionAddress(req *httpmsg.Request, injection string) string {
	base := req.URLString()
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + injection
}
