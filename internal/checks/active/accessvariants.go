package active

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// accessControlVariants asks whether a refusal survives a change in how the request is
// addressed.
//
// A rule that protects a resource is usually written against one spelling of it: a path as
// the router sees it, or a method as the edge sees it. When the layer enforcing the rule
// and the layer serving the resource disagree about either one — the edge matches /admin
// while the application normalises //admin, or the rule covers GET while the framework
// also answers POST — the refusal is real but incomplete, and the resource is reachable
// anyway.
//
// The check runs only on a request that was actually refused with 401 or 403. That
// baseline is what keeps it honest: a variant answering 200 is only interesting next to an
// original that answered "no". Everything else — a missing page, a redirect, a page that
// simply does not implement a method — is left alone.
type accessControlVariants struct{}

func (accessControlVariants) ID() string { return "access-control-variants" }
func (accessControlVariants) TitleKey() i18n.Key {
	return i18n.KeyCheckAccessVariantsTitle
}
func (accessControlVariants) DescriptionKey() i18n.Key {
	return i18n.KeyCheckAccessVariantsDesc
}
func (accessControlVariants) RemediationKey() i18n.Key {
	return i18n.KeyCheckAccessVariantsFix
}
func (accessControlVariants) Severity() finding.Severity { return finding.SeverityHigh }
func (accessControlVariants) Tags() []string {
	return []string{"active", "authorization", "access-control", "owasp-top10"}
}
func (accessControlVariants) Passive() bool { return false }

// IsRequestLevel marks this as a check about the request as a whole: the question is
// whether the resource is reachable, which does not depend on any one parameter.
func (accessControlVariants) IsRequestLevel() bool { return true }

// variantDistinct is how different a variant's response has to be from the refusal before
// it counts as the resource being served. A variant that returns the same refusal page is
// still being refused, whatever its status line says.
const variantDistinct = 0.95

// methodVariants are the methods worth re-asking with.
//
// Only the two that read or submit are tried. DELETE, PUT and PATCH are deliberately
// absent: the check would be asking the target to change state in the hope of being
// refused, and on the one target where the attempt succeeds that is a change nobody
// authorised. A read method answering where another read method was refused is already the
// signal.
var methodVariants = []string{"GET", "POST"}

func (accessControlVariants) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Request == nil || t.Response == nil || t.Request.URL == nil {
		return nil
	}
	if !isRefusal(t.Response) {
		return nil
	}
	base := c.BaselineFingerprint(t)
	if base == nil {
		return nil
	}

	for _, method := range methodVariants {
		if strings.EqualFold(method, t.Request.Method) {
			continue
		}
		mutated := methodRequest(t.Request, method)
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil || !servedVariant(c, base, response) {
			continue
		}
		return []*finding.Finding{variantFinding(c, t, mutated, response, "method "+method)}
	}

	for _, variant := range pathVariants(t.Request.URL) {
		mutated := t.Request.Clone()
		mutated.URL = variant.url
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil || !servedVariant(c, base, response) {
			continue
		}
		return []*finding.Finding{variantFinding(c, t, mutated, response, variant.name)}
	}
	return nil
}

// isRefusal reports whether a response is an explicit "you may not", as opposed to "there
// is nothing here". Only the explicit one is a baseline: a 404 says the resource is not
// reachable at all, which is not a rule to bypass.
func isRefusal(resp *httpmsg.Response) bool {
	if resp == nil {
		return false
	}
	return resp.Status == 401 || resp.Status == 403
}

// servedVariant reports whether a variant got the resource rather than the refusal.
//
// Only a 2xx counts. A redirect is not the resource: it is as likely to be the standard
// "you are not signed in, go and log in" detour as it is to be the page itself, and
// telling those apart from one response is guesswork. A variant that answers with the
// refusal page under a different status line is not being served either, which is what the
// similarity check rules out.
func servedVariant(c *checks.Context, base *diff.Fingerprint, resp *httpmsg.Response) bool {
	if resp == nil || resp.Status < 200 || resp.Status >= 300 || len(resp.Body) == 0 {
		return false
	}
	return diff.CompareFingerprints(base, c.Fingerprint(resp)).Score < variantDistinct
}

// methodRequest rebuilds a request under a different method. A method that carries no body
// loses the one it had: a GET with an entity body is a request no browser sends, and some
// servers reject it before the application ever sees it.
func methodRequest(req *httpmsg.Request, method string) *httpmsg.Request {
	out := req.Clone()
	out.Method = method
	if !methodCarriesBody(method) {
		out.Body = nil
		out.Header.Del("Content-Length")
		out.Header.Del("Content-Type")
	}
	return out
}

// methodCarriesBody reports whether an HTTP method is defined to carry a body.
func methodCarriesBody(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// pathVariant is one alternative spelling of a path.
type pathVariant struct {
	name string
	url  *url.URL
}

// pathVariants returns the spellings of a path that different layers are known to
// normalise differently. Each one is a way of writing the same resource, not a different
// resource: the point is that a rule may only recognise one of them.
func pathVariants(u *url.URL) []pathVariant {
	base := u.Path
	if base == "" {
		base = "/"
	}

	var out []pathVariant
	add := func(name, path, rawPath string) {
		clone := *u
		clone.Path = path
		clone.RawPath = rawPath
		out = append(out, pathVariant{name: name, url: &clone})
	}

	// A trailing slash: many routers treat the collection and the item as different
	// resources, and a rule written for one may not cover the other.
	if !strings.HasSuffix(base, "/") {
		add("trailing slash", base+"/", "")
	}
	// A repeated separator: some front ends collapse it before matching, some pass it
	// through, and the application may collapse it again.
	if strings.HasPrefix(base, "/") && !strings.HasPrefix(base, "//") {
		add("repeated separator", "//"+strings.TrimPrefix(base, "/"), "")
	}
	// Case: a rule matched case-sensitively at the edge may match a case-insensitive
	// router behind it.
	if upper := strings.ToUpper(base); upper != base {
		add("upper case", upper, "")
	}
	// A dot segment inside the path, which a normaliser resolves before matching.
	if index := strings.LastIndex(base, "/"); index > 0 {
		add("dot segment", base[:index]+"/."+base[index:], "")
	} else if base != "/" {
		add("dot segment", "/."+base, "")
	}
	// One character percent-encoded, so the layer matching the rule sees an escape while
	// the layer serving the resource sees the letter.
	if encoded, ok := encodePathCharacter(base); ok {
		add("percent-encoded character", base, encoded)
	}
	return out
}

// encodePathCharacter percent-encodes the first letter of the last path segment, returning
// the encoded spelling for RawPath. The decoded path is unchanged, since the escape stands
// for that very letter.
func encodePathCharacter(path string) (string, bool) {
	index := strings.LastIndex(path, "/")
	if index < 0 || index+1 >= len(path) {
		return "", false
	}
	letter := path[index+1]
	if !isASCIILetter(letter) {
		return "", false
	}
	return path[:index+1] + fmt.Sprintf("%%%02x", letter) + path[index+2:], true
}

// isASCIILetter reports whether a byte is a letter of the basic alphabet.
func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// variantFinding builds the finding for a variant that got through.
func variantFinding(c *checks.Context, t *checks.Target, mutated *httpmsg.Request, response *httpmsg.Response, variant string) *finding.Finding {
	f := checks.NewFinding(accessControlVariants{}, t,
		i18n.KeyCheckAccessVariantsTitle, i18n.KeyCheckAccessVariantsDesc,
		i18n.KeyCheckAccessVariantsFix)
	f.Severity = finding.SeverityHigh
	// Firm rather than certain: the comparison shows the refusal did not survive, and a
	// target that answers a variant from an unrelated route would look the same.
	f.Confidence = finding.ConfidenceFirm
	f.Method = mutated.Method
	f.URL = mutated.URLString()
	f.Payload = variant
	f.DedupExtra = variant
	f.CWE = "CWE-863"
	f.References = []string{
		"https://cwe.mitre.org/data/definitions/863.html",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
	}
	f.Evidence.Request = mutated.Raw()
	f.Evidence.Response = truncate(response.Raw(), 8192)
	f.Evidence.Baseline = truncate(t.Response.Raw(), 4096)
	f.Evidence.Matches = []string{c.Bundle.T(i18n.KeyEvidenceAccessRule,
		t.Response.Status, variant, response.Status)}
	return f
}
