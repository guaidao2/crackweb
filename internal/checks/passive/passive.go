// Package passive holds the checks that analyse traffic crackweb already has,
// without sending a single extra request.
//
// That property is what makes them useful: they can run against production,
// they work the instant the proxy is switched on (before any crawling or
// injection has happened), and they cannot damage anything. Most real-world
// findings from a review start here.
package passive

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// init registers every passive check.
func init() {
	checks.Register(securityHeaders{})
	checks.Register(cookieFlags{})
	checks.Register(corsPolicy{})
	checks.Register(infoDisclosure{})
	checks.Register(mixedContent{})
	checks.Register(cacheControl{})
	checks.Register(directoryListing{})
	checks.Register(cleartextPassword{})
	checks.Register(subresourceIntegrity{})
	checks.Register(errorDisclosure{})
	checks.Register(contentDisclosure{})
	checks.Register(privateKey{})
	checks.Register(cspWeaknesses{})
	checks.Register(insecureTransport{})
	checks.Register(vulnerableLibrary{})
}

// isHTML reports whether a response is HTML, which most passive checks care
// about.
func isHTML(resp *httpmsg.Response) bool {
	if resp == nil {
		return false
	}
	ct := resp.ContentType()
	return ct == "text/html" || ct == "application/xhtml+xml"
}

// isHTTPS reports whether the request that produced the response was encrypted.
func isHTTPS(req *httpmsg.Request) bool {
	return req != nil && req.Scheme() == "https"
}

// securityHeaders reports the hardening headers a response is missing.
type securityHeaders struct{}

func (securityHeaders) ID() string { return "passive-security-headers" }
func (securityHeaders) TitleKey() i18n.Key {
	return i18n.KeyCheckSecHeadersTitle
}
func (securityHeaders) DescriptionKey() i18n.Key {
	return i18n.KeyCheckSecHeadersDesc
}
func (securityHeaders) RemediationKey() i18n.Key {
	return i18n.KeyCheckSecHeadersFix
}
func (securityHeaders) Severity() finding.Severity { return finding.SeverityLow }
func (securityHeaders) Tags() []string             { return []string{"passive", "headers", "hardening"} }
func (securityHeaders) Passive() bool              { return true }
func (securityHeaders) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if !isHTML(t.Response) {
		return nil
	}
	header := t.Response.Header
	csp := header.Get("Content-Security-Policy")
	if csp == "" {
		csp = header.Get("Content-Security-Policy-Report-Only")
	}

	var missing []string
	if csp == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if header.Get("X-Content-Type-Options") == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	// X-Frame-Options is redundant when the policy already sets frame-ancestors.
	if header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		missing = append(missing, "X-Frame-Options")
	}
	if header.Get("Referrer-Policy") == "" {
		missing = append(missing, "Referrer-Policy")
	}
	if header.Get("Permissions-Policy") == "" {
		missing = append(missing, "Permissions-Policy")
	}
	// HSTS is only meaningful, and only sent, over TLS.
	if isHTTPS(t.Request) && header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	if len(missing) == 0 {
		return nil
	}

	f := checks.NewFinding(securityHeaders{}, t,
		i18n.KeyCheckSecHeadersTitle, i18n.KeyCheckSecHeadersDesc, i18n.KeyCheckSecHeadersFix)
	f.Confidence = finding.ConfidenceCertain
	f.DedupHostOnly = true
	f.Evidence.Matches = missing
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// cookieFlags reports cookies set without their security attributes.
type cookieFlags struct{}

func (cookieFlags) ID() string                 { return "passive-cookie-flags" }
func (cookieFlags) TitleKey() i18n.Key         { return i18n.KeyCheckCookieFlagsTitle }
func (cookieFlags) DescriptionKey() i18n.Key   { return i18n.KeyCheckCookieFlagsDesc }
func (cookieFlags) RemediationKey() i18n.Key   { return i18n.KeyCheckCookieFlagsFix }
func (cookieFlags) Severity() finding.Severity { return finding.SeverityMedium }
func (cookieFlags) Tags() []string             { return []string{"passive", "cookies", "session"} }
func (cookieFlags) Passive() bool              { return true }
func (cookieFlags) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil {
		return nil
	}

	var findings []*finding.Finding
	for _, raw := range t.Response.Header.Values("Set-Cookie") {
		name, attributes := parseSetCookie(raw)
		if name == "" {
			continue
		}
		problems := cookieProblems(name, cookieAttributes(attributes))
		if len(problems) == 0 {
			continue
		}

		f := checks.NewFinding(cookieFlags{}, t,
			i18n.KeyCheckCookieFlagsTitle, i18n.KeyCheckCookieFlagsDesc, i18n.KeyCheckCookieFlagsFix)
		f.Confidence = finding.ConfidenceCertain
		f.DedupHostOnly = true
		f.DedupExtra = name
		f.Evidence.Matches = problems
		f.Evidence.Response = headBytes(t.Response, 4096)
		findings = append(findings, f)
	}
	return findings
}

// cookieAttributeRe matches one attribute of a Set-Cookie header.
//
// Attributes are read as attributes rather than searched for as substrings: a cookie whose
// *value* contains the word "httponly" is not an HttpOnly cookie, and `;Secure` written
// without a space is still Secure.
var cookieAttributeRe = regexp.MustCompile(`(?i)(?:^|;)\s*([a-z][a-z0-9-]*)(?:\s*=\s*([^;]*))?`)

// cookieAttributes parses the attribute list of a Set-Cookie header, lower-casing the names.
func cookieAttributes(attributes string) map[string]string {
	out := map[string]string{}
	for _, match := range cookieAttributeRe.FindAllStringSubmatch(attributes, 32) {
		name := strings.ToLower(strings.TrimSpace(match[1]))
		out[name] = strings.TrimSpace(match[2])
	}
	return out
}

// cookieProblems lists what is wrong with one cookie: the flags it is missing, and the
// combinations a browser refuses.
//
// The second kind matters because it is invisible in a header somebody skimmed. A cookie
// with `SameSite=None` and no `Secure` is not a weaker cookie, it is one browsers drop; a
// `__Host-` name that also carries a Domain attribute is rejected for the same reason the
// prefix exists. A page that relies on the cookie then simply does not have it — which is a
// different problem from the one the missing flag suggests, and worth saying.
func cookieProblems(name string, attrs map[string]string) []string {
	_, secure := attrs["secure"]
	_, httpOnly := attrs["httponly"]
	sameSite, hasSameSite := attrs["samesite"]

	var problems []string
	if !secure {
		problems = append(problems, name+": missing Secure")
	}
	if !httpOnly {
		problems = append(problems, name+": missing HttpOnly")
	}
	if !hasSameSite {
		problems = append(problems, name+": missing SameSite")
	}

	if hasSameSite {
		switch strings.ToLower(sameSite) {
		case "none":
			if !secure {
				problems = append(problems, name+
					": SameSite=None without Secure, which browsers reject outright")
			}
		case "strict", "lax":
		default:
			problems = append(problems, name+": SameSite="+sameSite+
				" is not one of Strict, Lax or None, so browsers fall back to their own default")
		}
	}

	// The name prefixes are a contract, and violating it makes the cookie invalid rather
	// than merely weaker.
	switch {
	case strings.HasPrefix(name, "__Host-"):
		if !secure {
			problems = append(problems, name+": the __Host- prefix requires Secure")
		}
		if _, hasDomain := attrs["domain"]; hasDomain {
			problems = append(problems, name+": the __Host- prefix forbids a Domain attribute")
		}
		if path := attrs["path"]; path != "/" {
			problems = append(problems, name+": the __Host- prefix requires Path=/")
		}
	case strings.HasPrefix(name, "__Secure-"):
		if !secure {
			problems = append(problems, name+": the __Secure- prefix requires Secure")
		}
	}
	return problems
}

// parseSetCookie splits a Set-Cookie value into its name and its attribute list.
func parseSetCookie(raw string) (name, attributes string) {
	first, rest, _ := strings.Cut(raw, ";")
	name, _, _ = strings.Cut(strings.TrimSpace(first), "=")
	return strings.TrimSpace(name), rest
}

// corsPolicy reports cross-origin configurations that let any site read the
// response.
type corsPolicy struct{}

func (corsPolicy) ID() string                 { return "passive-cors" }
func (corsPolicy) TitleKey() i18n.Key         { return i18n.KeyCheckCORSTitle }
func (corsPolicy) DescriptionKey() i18n.Key   { return i18n.KeyCheckCORSDesc }
func (corsPolicy) RemediationKey() i18n.Key   { return i18n.KeyCheckCORSFix }
func (corsPolicy) Severity() finding.Severity { return finding.SeverityHigh }
func (corsPolicy) Tags() []string             { return []string{"passive", "cors", "misconfiguration"} }
func (corsPolicy) Passive() bool              { return true }
func (corsPolicy) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil {
		return nil
	}
	allowOrigin := t.Response.Header.Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		return nil
	}
	credentials := strings.EqualFold(t.Response.Header.Get("Access-Control-Allow-Credentials"), "true")
	requestOrigin := t.Request.Header.Get("Origin")

	var reason string
	severity := finding.SeverityLow

	switch {
	case allowOrigin == "*" && credentials:
		// Browsers reject this combination, but a server that emits it is
		// confused in a way that usually hides a worse setting nearby.
		reason = "Access-Control-Allow-Origin: * with credentials allowed"
		severity = finding.SeverityMedium
	case requestOrigin != "" && allowOrigin == requestOrigin:
		reason = "Origin reflected: " + allowOrigin
		if credentials {
			severity = finding.SeverityHigh
		} else {
			severity = finding.SeverityMedium
		}
	case allowOrigin == "*":
		// A wildcard without credentials is ordinary for a public API, so it is
		// reported as informational rather than as a problem.
		reason = "Access-Control-Allow-Origin: *"
		severity = finding.SeverityInfo
	default:
		return nil
	}

	f := checks.NewFinding(corsPolicy{}, t,
		i18n.KeyCheckCORSTitle, i18n.KeyCheckCORSDesc, i18n.KeyCheckCORSFix)
	f.Severity = severity
	f.Confidence = finding.ConfidenceCertain
	f.DedupHostOnly = true
	f.DedupExtra = reason
	f.Evidence.Matches = []string{reason}
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// versionRe matches a header value that carries a version number.
var versionRe = regexp.MustCompile(`\d+\.\d+`)

// disclosureHeaders are headers that give away the technology stack.
var disclosureHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Generator",
	"X-Drupal-Cache",
	"X-Runtime",
	"X-Version",
}

// infoDisclosure reports headers that advertise the stack and its version.
type infoDisclosure struct{}

func (infoDisclosure) ID() string                 { return "passive-info-disclosure" }
func (infoDisclosure) TitleKey() i18n.Key         { return i18n.KeyCheckInfoDisclosureTitle }
func (infoDisclosure) DescriptionKey() i18n.Key   { return i18n.KeyCheckInfoDisclosureDesc }
func (infoDisclosure) RemediationKey() i18n.Key   { return i18n.KeyCheckInfoDisclosureFix }
func (infoDisclosure) Severity() finding.Severity { return finding.SeverityInfo }
func (infoDisclosure) Tags() []string {
	return []string{"passive", "disclosure", "fingerprint"}
}
func (infoDisclosure) Passive() bool { return true }
func (infoDisclosure) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil {
		return nil
	}
	// A banner on an error page describes the server, not the application's configuration,
	// and it is the same banner every 404 from that server carries. Reporting it here turns
	// one fact into a finding per failed URL.
	if t.Response.Status >= 400 {
		return nil
	}

	var disclosed []string
	for _, name := range disclosureHeaders {
		value := t.Response.Header.Get(name)
		if value == "" {
			continue
		}
		// A bare product name is close to meaningless; a version number is what
		// an attacker actually uses.
		if versionRe.MatchString(value) || strings.Contains(value, "/") {
			disclosed = append(disclosed, name+": "+value)
		}
	}
	if len(disclosed) == 0 {
		return nil
	}

	f := checks.NewFinding(infoDisclosure{}, t,
		i18n.KeyCheckInfoDisclosureTitle, i18n.KeyCheckInfoDisclosureDesc, i18n.KeyCheckInfoDisclosureFix)
	f.Confidence = finding.ConfidenceCertain
	f.DedupHostOnly = true
	f.Evidence.Matches = disclosed
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// mixedContentPatterns pair the elements that can carry a plain-HTTP address with what
// mixing them costs.
//
// The distinction is the browser's own: a script, an iframe, a stylesheet or a form target
// has to be trusted — the bytes run, or they decide where the page goes — and a browser
// blocks those rather than running them, so on a modern client the page is broken and on an
// older or laxer one it is executing an attacker's code. An image or a media file is
// tampered with rather than executed, which is a different claim and a different severity.
var mixedContentPatterns = []struct {
	element string
	plain   string
	active  bool
	re      *regexp.Regexp
}{
	{"script", "script", true, regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*["'](http://[^"'\s>]+)`)},
	{"iframe", "iframe", true, regexp.MustCompile(`(?is)<iframe\b[^>]*\bsrc\s*=\s*["'](http://[^"'\s>]+)`)},
	{"stylesheet", "stylesheet", true, regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["']?stylesheet[^>]*\bhref\s*=\s*["'](http://[^"'\s>]+)`)},
	{"form action", "form", true, regexp.MustCompile(`(?is)<form\b[^>]*\baction\s*=\s*["'](http://[^"'\s>]+)`)},
	{"embed", "embed", true, regexp.MustCompile(`(?is)<embed\b[^>]*\bsrc\s*=\s*["'](http://[^"'\s>]+)`)},
	{"object data", "object", true, regexp.MustCompile(`(?is)<object\b[^>]*\bdata\s*=\s*["'](http://[^"'\s>]+)`)},
	{"image", "image", false, regexp.MustCompile(`(?is)<img\b[^>]*\bsrc\s*=\s*["'](http://[^"'\s>]+)`)},
	{"media", "media", false, regexp.MustCompile(`(?is)<(?:audio|video|source|track)\b[^>]*\bsrc\s*=\s*["'](http://[^"'\s>]+)`)},
}

// mixedContent reports plain-HTTP subresources on an HTTPS page.
type mixedContent struct{}

func (mixedContent) ID() string                 { return "passive-mixed-content" }
func (mixedContent) TitleKey() i18n.Key         { return i18n.KeyCheckMixedContentTitle }
func (mixedContent) DescriptionKey() i18n.Key   { return i18n.KeyCheckMixedContentDesc }
func (mixedContent) RemediationKey() i18n.Key   { return i18n.KeyCheckMixedContentFix }
func (mixedContent) Severity() finding.Severity { return finding.SeverityMedium }
func (mixedContent) Tags() []string             { return []string{"passive", "tls", "content"} }
func (mixedContent) Passive() bool              { return true }
func (mixedContent) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if !isHTML(t.Response) || !isHTTPS(t.Request) {
		return nil
	}

	body := bodyForScan(t.Response.Body)
	seen := map[string]bool{}
	var active, passive []string
	for _, pattern := range mixedContentPatterns {
		for _, match := range pattern.re.FindAllStringSubmatch(body, 5) {
			if len(match) < 2 || seen[match[1]] {
				continue
			}
			seen[match[1]] = true
			line := pattern.element + " loads " + match[1]
			if pattern.active {
				active = append(active, line)
			} else {
				passive = append(passive, line)
			}
		}
	}
	if len(active) == 0 && len(passive) == 0 {
		return nil
	}

	f := checks.NewFinding(mixedContent{}, t,
		i18n.KeyCheckMixedContentTitle, i18n.KeyCheckMixedContentDesc, i18n.KeyCheckMixedContentFix)
	// Active content is the stronger claim, and it decides the severity: a resource that
	// runs is a different problem from one that is merely tampered with.
	if len(active) > 0 {
		f.Severity = finding.SeverityHigh
		f.Evidence.Matches = append(active, passive...)
		f.Evidence.Diff = "active mixed content: " + strings.Join(active, "; ")
	} else {
		f.Severity = finding.SeverityLow
		f.Evidence.Matches = passive
		f.Evidence.Diff = "passive mixed content only: " + strings.Join(passive, "; ")
	}
	f.Confidence = finding.ConfidenceCertain
	f.Evidence.Response = headBytes(t.Response, 8192)
	return []*finding.Finding{f}
}

// cacheControl reports a response that belongs to one user and may be stored by a cache
// that serves everybody.
//
// Two things have to be true, and the second is the one worth being careful about. The
// response has to belong to somebody — it sets a cookie, or it answers a request that
// carried one, or an Authorization header. And a cache has to be told it may keep it: that
// is what `public` and `s-maxage` say. Without one of those, a shared cache is not required
// to store the response at all, and calling the absence of a prohibition a permission is how
// this check would fill a report with static pages. A response that explicitly says `private`
// or `no-store` is doing the right thing and is not reported.
type cacheControl struct{}

func (cacheControl) ID() string                 { return "passive-cache-control" }
func (cacheControl) TitleKey() i18n.Key         { return i18n.KeyCheckCacheTitle }
func (cacheControl) DescriptionKey() i18n.Key   { return i18n.KeyCheckCacheDesc }
func (cacheControl) RemediationKey() i18n.Key   { return i18n.KeyCheckCacheFix }
func (cacheControl) Severity() finding.Severity { return finding.SeverityInfo }
func (cacheControl) Tags() []string {
	return []string{"passive", "cookies", "session"}
}
func (cacheControl) Passive() bool { return true }

// cacheSharingDirectives are the Cache-Control directives that tell a shared cache, in so
// many words, that it may keep the response.
var cacheSharingDirectives = []string{"public", "s-maxage"}

// cacheDirectives splits a Cache-Control header into its directives, lower-cased.
func cacheDirectives(header string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(header, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(strings.ToLower(part)), "=")
		if name != "" {
			out[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
	}
	return out
}

func (cacheControl) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || t.Request == nil {
		return nil
	}
	// Whose response is it? A session being established, a session being answered, or an
	// authenticated request: any of the three makes the response one user's.
	belongsToSomebody := t.Response.Header.Get("Set-Cookie") != "" ||
		t.Request.Header.Get("Cookie") != "" || t.Request.Header.Get("Authorization") != ""
	if !belongsToSomebody {
		return nil
	}

	directives := cacheDirectives(t.Response.Header.Get("Cache-Control"))
	if _, private := directives["private"]; private {
		return nil
	}
	if _, noStore := directives["no-store"]; noStore {
		return nil
	}

	shareable := false
	for _, name := range cacheSharingDirectives {
		if _, ok := directives[name]; ok {
			shareable = true
			break
		}
	}

	matches := []string{"Cache-Control: " + orNone(t.Response.Header.Get("Cache-Control"))}
	confidence := finding.ConfidenceTentative
	if shareable {
		confidence = finding.ConfidenceFirm
		matches = append(matches, "the response is marked shareable (`public` or `s-maxage`), so a "+
			"cache that serves everybody is entitled to keep this user's response")
		// `Vary` is what a cache uses to tell users apart. Without Cookie or Authorization
		// in it, one user's response is a candidate for the next user's request.
		vary := strings.ToLower(t.Response.Header.Get("Vary"))
		if !strings.Contains(vary, "cookie") && !strings.Contains(vary, "authorization") && vary != "*" {
			matches = append(matches, "Vary does not name Cookie or Authorization, so a shared "+
				"cache has nothing to distinguish one user from another")
		}
	} else {
		matches = append(matches, "nothing forbids a shared cache from storing it, and nothing "+
			"tells one to keep it either")
	}

	f := checks.NewFinding(cacheControl{}, t,
		i18n.KeyCheckCacheTitle, i18n.KeyCheckCacheDesc, i18n.KeyCheckCacheFix)
	f.Confidence = confidence
	f.DedupHostOnly = true
	f.Evidence.Matches = matches
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// directoryListingMarkers are the strings servers put in generated indexes.
var directoryListingMarkers = []string{
	"<title>Index of /",
	"<title>Directory listing for",
	"Index of /</h1>",
	"Parent Directory</a>",
	"[To Parent Directory]",
}

// directoryListing reports auto-generated directory indexes.
type directoryListing struct{}

func (directoryListing) ID() string                 { return "passive-directory-listing" }
func (directoryListing) TitleKey() i18n.Key         { return i18n.KeyCheckDirListingTitle }
func (directoryListing) DescriptionKey() i18n.Key   { return i18n.KeyCheckDirListingDesc }
func (directoryListing) RemediationKey() i18n.Key   { return i18n.KeyCheckDirListingFix }
func (directoryListing) Severity() finding.Severity { return finding.SeverityMedium }
func (directoryListing) Tags() []string             { return []string{"passive", "disclosure"} }
func (directoryListing) Passive() bool              { return true }

// directoryListingSensitive are the names whose presence turns an index from a list of what the
// site serves into a list of what it should not have served: repository metadata, credential
// files, database exports, editor backups. A reader who finds these can ask for the file itself,
// and the file is the whole history or the whole database.
var directoryListingSensitive = []string{
	".git", ".svn", ".hg", ".env", ".htpasswd", ".ssh", "id_rsa", "id_dsa", "id_ecdsa",
	"backup", "dump", "database", "export", ".sql", ".bak", ".old", ".orig", ".swp",
	".zip", ".tar", ".tgz", ".gz", ".7z", ".rar",
	"wp-config", "config.php", "settings.py", "application.properties", "credentials",
	"users.csv", "passwords", ".pem", ".key", ".pfx", ".jks", ".keystore", "shadow",
}

func (directoryListing) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Response == nil || t.Response.Status != 200 {
		return nil
	}
	body := string(t.Response.Body)
	for _, marker := range directoryListingMarkers {
		if !strings.Contains(body, marker) {
			continue
		}
		f := checks.NewFinding(directoryListing{}, t,
			i18n.KeyCheckDirListingTitle, i18n.KeyCheckDirListingDesc, i18n.KeyCheckDirListingFix)
		f.Confidence = finding.ConfidenceCertain
		matches := []string{marker}

		// What the index happens to list is what decides how much this is worth: an index of
		// images is a directory the site meant to serve, and an index of a database export is
		// the database.
		lower := strings.ToLower(body)
		var sensitive []string
		for _, name := range directoryListingSensitive {
			if strings.Contains(lower, name) {
				sensitive = append(sensitive, name)
			}
		}
		if len(sensitive) > 0 {
			f.Severity = finding.SeverityHigh
			matches = append(matches,
				"the index names "+strings.Join(sensitive, ", ")+
					", so the file can be asked for directly")
		}
		f.Evidence.Matches = matches
		f.Evidence.Response = headBytes(t.Response, 4096)
		return []*finding.Finding{f}
	}
	return nil
}

// headBytes renders the response head, plus a little body, as evidence.
func headBytes(resp *httpmsg.Response, maxBody int) []byte {
	if resp == nil {
		return nil
	}
	raw := resp.Raw()
	if len(raw) > maxBody {
		return raw[:maxBody]
	}
	return raw
}

// orNone renders an empty value readably.
func orNone(value string) string {
	if value == "" {
		return "(none)"
	}
	return value
}

// credentialField is one credential-bearing field, wherever it was found.
type credentialField struct {
	name  string
	where string
	value string
}

// jsonCredentialFields finds credential fields inside a JSON request body.
//
// Only the top level is inspected: that is where a login payload puts its
// fields, and walking deeper would start reporting objects that merely contain a
// key called "password" without being one.
func jsonCredentialFields(req *httpmsg.Request) []credentialField {
	if req == nil || len(req.Body) == 0 {
		return nil
	}
	if ct := req.Header.Get("Content-Type"); !strings.Contains(strings.ToLower(ct), "json") {
		return nil
	}
	var object map[string]any
	if err := json.Unmarshal(req.Body, &object); err != nil {
		return nil
	}
	var out []credentialField
	for name, raw := range object {
		if !passwordFieldNames[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, credentialField{name: name, where: "json body", value: value})
	}
	return out
}

// headRaw truncates a request's bytes for evidence.
func headRaw(raw []byte, n int) []byte {
	if len(raw) <= n {
		return raw
	}
	return raw[:n]
}

// passwordFieldNames are the field names that carry a credential.
//
// Matching is exact rather than substring-based on purpose: `pass` inside
// `passenger` or `bypass` is not a password, and reporting those would make the
// check unusable on any page that mentions them.
var passwordFieldNames = map[string]bool{
	"password":              true,
	"passwd":                true,
	"pwd":                   true,
	"pass":                  true,
	"passphrase":            true,
	"userpass":              true,
	"user_password":         true,
	"password_confirmation": true,
	"confirm_password":      true,
	"new_password":          true,
	"newpassword":           true,
	"old_password":          true,
	"oldpassword":           true,
	"secret":                true,
	"passwort":              true,
	"contrasena":            true,
}

// cleartextPassword reports a credential sent over a connection that does not
// protect it.
//
// The objection is to the transport, not to the field. A password parameter is
// ordinary, and over HTTPS it is nobody's business but the two ends. Sent over
// http:// it crosses the network in readable form, which on a shared segment —
// an office switch, a conference network, anything upstream — makes it available
// to whoever is listening. The password itself is never copied into the finding:
// the evidence names the field and shows the request line, which is enough to
// locate the problem without putting the secret in a report that gets emailed
// around.
//
// Like the other passive checks this only reads what was already captured, so it
// changes nothing about what the target sees.
type cleartextPassword struct{}

func (cleartextPassword) ID() string                 { return "passive-cleartext-password" }
func (cleartextPassword) TitleKey() i18n.Key         { return i18n.KeyCheckCleartextPasswordTitle }
func (cleartextPassword) DescriptionKey() i18n.Key   { return i18n.KeyCheckCleartextPasswordDesc }
func (cleartextPassword) RemediationKey() i18n.Key   { return i18n.KeyCheckCleartextPasswordFix }
func (cleartextPassword) Severity() finding.Severity { return finding.SeverityMedium }
func (cleartextPassword) Tags() []string {
	return []string{"passive", "credentials", "transport"}
}
func (cleartextPassword) Passive() bool { return true }

func (cleartextPassword) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil {
		return nil
	}
	// TLS protects the credential; there is nothing to report.
	if strings.EqualFold(t.Request.Scheme(), "https") {
		return nil
	}

	// The values that must not reach the report are collected first, because the
	// request line reproduced as evidence would otherwise carry them verbatim —
	// which would turn a finding about transport into a second disclosure, in a
	// document that gets attached to tickets and mailed around.
	var (
		secrets []string
		fields  []credentialField
	)
	for _, param := range t.Request.Params() {
		if !passwordFieldNames[strings.ToLower(strings.TrimSpace(param.Name))] {
			continue
		}
		if param.RawValue != "" {
			secrets = append(secrets, param.RawValue)
		}
		if param.Value != "" && param.Value != param.RawValue {
			secrets = append(secrets, param.Value)
		}
		if strings.TrimSpace(param.Value) != "" {
			fields = append(fields, credentialField{name: param.Name, where: string(param.In)})
		}
	}
	// A JSON body is not a set of parameters: the parser does not reach into it,
	// and a login endpoint that takes application/json would otherwise look like
	// a request carrying no credentials at all.
	for _, field := range jsonCredentialFields(t.Request) {
		secrets = append(secrets, field.value)
		fields = append(fields, credentialField{name: field.name, where: "json body"})
	}
	redacted := string(headRaw(t.Request.Raw(), 4096))
	for _, secret := range secrets {
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}

	var findings []*finding.Finding
	seen := map[string]bool{}
	for _, field := range fields {
		if seen[field.name] {
			continue
		}
		seen[field.name] = true

		f := checks.NewFinding(cleartextPassword{}, t,
			i18n.KeyCheckCleartextPasswordTitle, i18n.KeyCheckCleartextPasswordDesc, i18n.KeyCheckCleartextPasswordFix)
		f.Confidence = finding.ConfidenceCertain
		// The field name is what distinguishes one instance from another on the
		// same URL; the value is deliberately left out.
		f.DedupExtra = field.name
		f.Evidence.Request = []byte(redacted)
		f.Evidence.Response = headBytes(t.Response, 2048)
		// The URL is rendered in report headings and in the finding's own
		// address, so the credential has to come out of it too — not just out of
		// the request line.
		for _, secret := range secrets {
			f.URL = strings.ReplaceAll(f.URL, secret, "[redacted]")
		}
		f.Evidence.Matches = []string{
			"the field " + field.name + " carried a value over " + t.Request.Scheme() + "://" +
				t.Request.Hostname() + " (the value itself is not reproduced here)",
			"field location: " + field.where,
		}
		findings = append(findings, f)
	}
	return findings
}
