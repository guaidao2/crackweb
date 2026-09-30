package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// jsonp reports an endpoint that hands its response to whatever callback name a caller asks for.
//
// The request is the whole test: a marker this scan invented is sent as the callback, and the
// response has to come back wrapped in it. A page that merely echoes its parameters contains the
// marker too, so the marker alone is not the evidence — it has to be followed by the parenthesis
// that makes it a call, which is a shape only a page building a callback produces.
//
// What that exposes depends on what the endpoint returns, which is why the confidence is firm
// rather than certain and the severity is low: the fact being reported is that the response can
// be read by any site that asks for it this way, and a reader who knows what the endpoint serves
// is the one who can say what that is worth.
type jsonp struct{}

func (jsonp) ID() string                 { return "jsonp" }
func (jsonp) TitleKey() i18n.Key         { return i18n.KeyCheckJSONPTitle }
func (jsonp) DescriptionKey() i18n.Key   { return i18n.KeyCheckJSONPDesc }
func (jsonp) RemediationKey() i18n.Key   { return i18n.KeyCheckJSONPFix }
func (jsonp) Severity() finding.Severity { return finding.SeverityLow }
func (jsonp) Tags() []string {
	return []string{"active", "disclosure", "owasp-top10", "misconfiguration"}
}
func (jsonp) Passive() bool { return false }

// IsRequestLevel marks this as a check about the endpoint rather than about one parameter.
func (jsonp) IsRequestLevel() bool { return true }

// jsonpMarker is the callback name asked for. It is not a word a page would produce on its own.
const jsonpMarker = "crackwebJsonpCallback"

// jsonpParameterNames are the names frameworks read a callback from. Each costs one request, so
// the list is the ones in use rather than every spelling of them.
var jsonpParameterNames = []string{"callback", "jsonp", "cb"}

func (jsonp) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil || t.Request.URL == nil {
		return nil
	}
	// A page that already wraps something in this marker has nothing to do with the probe.
	if jsonpWrappedIn(t.Response.Body, jsonpMarker) {
		return nil
	}

	for _, name := range jsonpParameterNames {
		request := t.Request.Clone()
		request.Method = "GET"
		request.Body = nil
		request.Header.Del("Content-Type")
		request.Header.Del("Content-Length")
		address := *t.Request.URL
		address.RawQuery = name + "=" + jsonpMarker
		if t.Request.URL.RawQuery != "" {
			address.RawQuery = t.Request.URL.RawQuery + "&" + address.RawQuery
		}
		address.Fragment = ""
		request.URL = &address

		response, err := c.Do(ctx, request)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		if !jsonpWrappedIn(response.Body, jsonpMarker) {
			continue
		}

		f := checks.NewFinding(jsonp{}, t,
			i18n.KeyCheckJSONPTitle, i18n.KeyCheckJSONPDesc, i18n.KeyCheckJSONPFix)
		f.Severity = finding.SeverityLow
		f.Confidence = finding.ConfidenceFirm
		f.Method = "GET"
		f.Payload = name + "=" + jsonpMarker
		f.CWE = "CWE-346"
		f.References = []string{
			"https://owasp.org/www-community/attacks/Cross_Site_Script_Inclusion",
			"https://cwe.mitre.org/data/definitions/346.html",
		}
		f.Evidence.Request = request.Raw()
		f.Evidence.Response = truncate(response.Body, 4096)
		f.Evidence.Baseline = truncate(t.Response.Body, 2048)
		f.Evidence.Matches = []string{
			"the response was wrapped in the callback name the request asked for (" + name + ")",
			"the same address without that parameter answers with the data itself, so the " +
				"endpoint is building the callback rather than echoing a name it was given",
			"any site can read this response by loading it as a script",
		}
		f.Evidence.Diff = extractAround(string(response.Body), jsonpMarker, 240)
		return []*finding.Finding{f}
	}
	return nil
}

// jsonpWrappedIn reports whether the body calls the callback: the name followed by the
// parenthesis that opens the argument list. An echo of the name on its own does not count, and
// the comparison ignores case because a page may print the name as it likes.
func jsonpWrappedIn(body []byte, marker string) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, strings.ToLower(marker)+"(")
}
