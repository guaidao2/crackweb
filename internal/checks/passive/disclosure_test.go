package passive

import (
	"context"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// responseTarget builds a Target around a request and the response it produced.
func responseTarget(t *testing.T, rawURL, contentType, body string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", rawURL)
	if err != nil {
		t.Fatalf("NewRequest(%s): %v", rawURL, err)
	}
	response := &httpmsg.Response{Status: 200, Body: []byte(body)}
	if contentType != "" {
		response.Header.Set("Content-Type", contentType)
	}
	return &checks.Target{Request: request, Response: response}
}

func runPassive(t *testing.T, c interface {
	Run(context.Context, *checks.Context, *checks.Target) []*finding.Finding
}, tg *checks.Target) []*finding.Finding {
	t.Helper()
	return c.Run(context.Background(), &checks.Context{Bundle: i18n.New(i18n.EN)}, tg)
}

func TestErrorDisclosureFiresOnAFrameworkError(t *testing.T) {
	cases := []string{
		"<html><body>Traceback (most recent call last): File \"app.py\"</body></html>",
		"<html><body>java.lang.NullPointerException at com.example.Foo.bar(Foo.java:42)</body></html>",
		"<html><body>Fatal error: Uncaught Error: Call to undefined method</body></html>",
		"<html><body>SQLSTATE[42000]: Syntax error or access violation</body></html>",
		"<html><body>Whitelabel Error Page: This application has no explicit mapping</body></html>",
	}
	for _, body := range cases {
		tg := responseTarget(t, "http://example.com/oops", "text/html", body)
		if findings := runPassive(t, errorDisclosure{}, tg); len(findings) != 1 {
			t.Errorf("no finding for %q", body)
		}
	}
}

func TestErrorDisclosureIgnoresOrdinaryPages(t *testing.T) {
	cases := []string{
		"<html><body>Welcome. If you see an error, contact support.</body></html>",
		"<html><body>Error handling in this application is documented here.</body></html>",
		"",
	}
	for _, body := range cases {
		tg := responseTarget(t, "http://example.com/", "text/html", body)
		if findings := runPassive(t, errorDisclosure{}, tg); len(findings) != 0 {
			t.Errorf("%q was reported as an exposed error", body)
		}
	}
}

func TestContentDisclosureFindsDeploymentDetail(t *testing.T) {
	cases := map[string]string{
		"internal address": "the worker at 10.20.30.40 did not answer",
		"server-side path": "failed to read /home/deploy/app/config.yml",
		"mailbox":          "contact the team at platform-operators@deploy.internal",
	}
	for name, body := range cases {
		tg := responseTarget(t, "http://example.com/", "text/html", "<html><body>"+body+"</body></html>")
		findings := runPassive(t, contentDisclosure{}, tg)
		if len(findings) != 1 {
			t.Errorf("%s: got %d findings, want 1", name, len(findings))
			continue
		}
		if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), name) {
			t.Errorf("%s: evidence does not name the kind: %v", name, findings[0].Evidence.Matches)
		}
	}
}

// TestContentDisclosureKeepsMailboxesToTheirDomain: a report is a document that travels.
// The address belongs to a person; the domain is what makes the finding actionable.
func TestContentDisclosureKeepsMailboxesToTheirDomain(t *testing.T) {
	tg := responseTarget(t, "http://example.com/", "text/html",
		"<html><body>write to alice.smith@deploy.internal</body></html>")
	findings := runPassive(t, contentDisclosure{}, tg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	evidence := strings.Join(findings[0].Evidence.Matches, " ")
	if strings.Contains(evidence, "alice.smith@") {
		t.Errorf("the full address reached the report: %s", evidence)
	}
	if !strings.Contains(evidence, "deploy.internal") {
		t.Errorf("the domain is missing from the report: %s", evidence)
	}
}

// TestContentDisclosureLeavesPublicMailboxesAlone: nearly every site publishes a contact
// address. Reporting those buries the finding that matters — an address, a path — in a list
// the reader skips.
func TestContentDisclosureLeavesPublicMailboxesAlone(t *testing.T) {
	for _, address := range []string{
		"alice.smith@example.com",
		"hello@126.com",
		"support@gmail.com",
	} {
		tg := responseTarget(t, "http://example.com/", "text/html",
			"<html><body>write to "+address+"</body></html>")
		if findings := runPassive(t, contentDisclosure{}, tg); len(findings) != 0 {
			t.Errorf("%s was reported as deployment detail", address)
		}
	}
}

// TestContentDisclosureStillCatchesPrivateHostsInAddresses: a domain that is itself a
// private name is deployment detail, whichever side of the @ it is on.
func TestContentDisclosureStillCatchesPrivateHostsInAddresses(t *testing.T) {
	for _, address := range []string{
		"ops@10.20.30.40",
		"ops@gateway",
		"ops@fileserver.lan",
	} {
		tg := responseTarget(t, "http://example.com/", "text/html",
			"<html><body>write to "+address+"</body></html>")
		if findings := runPassive(t, contentDisclosure{}, tg); len(findings) == 0 {
			t.Errorf("%s was not reported", address)
		}
	}
}

func TestContentDisclosureIgnoresPublicAddresses(t *testing.T) {
	tg := responseTarget(t, "http://example.com/", "text/html",
		"<html><body>Resolvers at 8.8.8.8 and 1.1.1.1 answer quickly.</body></html>")
	if findings := runPassive(t, contentDisclosure{}, tg); len(findings) != 0 {
		t.Errorf("a public resolver address was reported: %v", findings[0].Evidence.Matches)
	}
}

func TestPrivateKeyIsReportedWithoutReproducingTheKey(t *testing.T) {
	const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	tg := responseTarget(t, "http://example.com/id_rsa", "text/plain", key)

	findings := runPassive(t, privateKey{}, tg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	// The key is live material: it belongs in a rotation queue, not in a report that gets
	// mailed around.
	if len(findings[0].Evidence.Response) != 0 {
		t.Error("the key body was copied into the finding")
	}
	if findings[0].Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", findings[0].Confidence)
	}
}

func TestPrivateKeyIgnoresPublicKeysAndProse(t *testing.T) {
	for _, body := range []string{
		"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n-----END PUBLIC KEY-----",
		"we rotate keys with openssl genrsa every quarter",
	} {
		tg := responseTarget(t, "http://example.com/", "text/plain", body)
		if findings := runPassive(t, privateKey{}, tg); len(findings) != 0 {
			t.Errorf("%q was reported as a key", body)
		}
	}
}

func TestSubresourceIntegrityFiresForThirdPartyCode(t *testing.T) {
	tg := responseTarget(t, "http://example.com/", "text/html",
		`<html><head><script src="https://cdn.other.example/lib.js"></script></head></html>`)
	findings := runPassive(t, subresourceIntegrity{}, tg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "cdn.other.example") {
		t.Errorf("the origin is missing from the evidence: %v", findings[0].Evidence.Matches)
	}
}

func TestSubresourceIntegrityIgnoresProtectedAndLocalAssets(t *testing.T) {
	// A usable hash and a cross-origin attribute: the shape a browser actually verifies.
	digest := "sha384-+BSos/8e4xsCqkJHoUQvui/72ICE+EQQqkMNbQvUS6o/XFz8qbny+uKZB3TFcqaU"
	cases := map[string]string{
		"has a hash":             `<script src="https://cdn.other.example/lib.js" integrity="` + digest + `" crossorigin="anonymous"></script>`,
		"same origin":            `<script src="https://example.com/lib.js"></script>`,
		"relative path":          `<script src="/static/lib.js"></script>`,
		"an icon":                `<link rel="icon" href="https://cdn.other.example/favicon.ico">`,
		"stylesheet with a hash": `<link rel="stylesheet" href="https://cdn.other.example/a.css" integrity="` + digest + `" crossorigin="anonymous">`,
	}
	for name, markup := range cases {
		tg := responseTarget(t, "https://example.com/", "text/html", "<html><head>"+markup+"</head></html>")
		if findings := runPassive(t, subresourceIntegrity{}, tg); len(findings) != 0 {
			t.Errorf("%s was reported: %v", name, findings[0].Evidence.Matches)
		}
	}
}

func TestInsecureTransportFiresOnAPasswordFieldOverHTTP(t *testing.T) {
	tg := responseTarget(t, "http://example.com/login", "text/html",
		`<html><body><form><input type="password" name="pw"></form></body></html>`)
	if findings := runPassive(t, insecureTransport{}, tg); len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestInsecureTransportIgnoresTLSAndPasswordlessPages(t *testing.T) {
	tls := responseTarget(t, "https://example.com/login", "text/html",
		`<html><body><input type="password" name="pw"></body></html>`)
	if findings := runPassive(t, insecureTransport{}, tls); len(findings) != 0 {
		t.Errorf("a TLS page was reported: %v", findings[0].Evidence.Matches)
	}

	plain := responseTarget(t, "http://example.com/", "text/html",
		`<html><body><input type="text" name="q"></body></html>`)
	if findings := runPassive(t, insecureTransport{}, plain); len(findings) != 0 {
		t.Errorf("a page without a password field was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestContentDisclosureIgnoresRuntimePathsFromThirdPartyAssets: a bundled library quotes
// interpreter paths such as /usr/bin/env in its header. Reporting those would bury the
// real finding — a path that names the deployment — under noise from every vendored file.
func TestContentDisclosureIgnoresRuntimePathsFromThirdPartyAssets(t *testing.T) {
	for _, body := range []string{
		"#!/usr/bin/env node\nvar e=function(){};",
		"/usr/share/doc/highlightjs/copyright",
	} {
		tg := responseTarget(t, "http://example.com/static/lib.min.js", "application/javascript", body)
		if findings := runPassive(t, contentDisclosure{}, tg); len(findings) != 0 {
			t.Errorf("%q was reported as a deployment path: %v", body, findings[0].Evidence.Matches)
		}
	}
}

// TestContentDisclosureIgnoresAtSignsThatAreNotAddresses: `@400px` and friends are not
// mailboxes. A bare number is not a hostname either, so treating an unqualified domain as
// "internal" reported every rule that writes an at-sign before a number.
func TestContentDisclosureIgnoresAtSignsThatAreNotAddresses(t *testing.T) {
	for _, body := range []string{
		"<style>@media (min-width:400px) { }</style>",
		"<p>send to ops@400</p>",
		"<p>font-size@2x</p>",
	} {
		tg := responseTarget(t, "http://example.com/", "text/html", "<html><body>"+body+"</body></html>")
		if findings := runPassive(t, contentDisclosure{}, tg); len(findings) != 0 {
			t.Errorf("a non-address at-sign was reported in %q: %v", body, findings[0].Evidence.Matches)
		}
	}
}

// TestSubresourceIntegrityFiresOnHashesNoBrowserChecks: the attribute's presence is not the
// question. A value using an algorithm the specification does not define, an empty one from
// a deployment mistake, or a digest of the wrong length is ignored — the page reads as
// protected and the resource runs unverified.
func TestSubresourceIntegrityFiresOnHashesNoBrowserChecks(t *testing.T) {
	cases := map[string]string{
		"an algorithm outside the specification": `<script src="https://cdn.other.example/lib.js" integrity="sha1-2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" crossorigin="anonymous"></script>`,
		"an empty value":                         `<script src="https://cdn.other.example/lib.js" integrity="" crossorigin="anonymous"></script>`,
		"a digest of the wrong length":           `<script src="https://cdn.other.example/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>`,
		"no algorithm at all":                    `<script src="https://cdn.other.example/lib.js" integrity="2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" crossorigin="anonymous"></script>`,
	}
	for name, markup := range cases {
		tg := responseTarget(t, "https://example.com/", "text/html", "<html><head>"+markup+"</head></html>")
		findings := runPassive(t, subresourceIntegrity{}, tg)
		if len(findings) == 0 {
			t.Errorf("%s was not reported", name)
		}
	}
}

// TestSubresourceIntegrityFiresWithoutCrossorigin: a cross-origin response is opaque to the
// check unless the request is made with credentials mode set, so the hash does not verify
// the resource — the browser refuses the load instead.
func TestSubresourceIntegrityFiresWithoutCrossorigin(t *testing.T) {
	digest := "sha384-" + strings.Repeat("A", 64)
	markup := `<script src="https://cdn.other.example/lib.js" integrity="` + digest + `"></script>`
	tg := responseTarget(t, "https://example.com/", "text/html", "<html><head>"+markup+"</head></html>")

	findings := runPassive(t, subresourceIntegrity{}, tg)
	if len(findings) == 0 {
		t.Fatal("a cross-origin asset with a hash but no crossorigin attribute was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "crossorigin") {
		t.Errorf("evidence does not explain the missing attribute: %v", findings[0].Evidence.Matches)
	}
}

// TestSRIVerifiability is the predicate on its own: what a browser will check, and what it
// will not.
func TestSRIVerifiability(t *testing.T) {
	usable := "sha384-" + strings.Repeat("A", 64)
	verifiable := map[string]bool{
		usable:                              true,
		"sha256-" + strings.Repeat("B", 44): true,
		"sha512-" + strings.Repeat("C", 88): true,
		"sha256-" + strings.Repeat("B", 44) + " " + usable: true, // any one is enough
		"sha1-2aae6c35c94fcfb415dbe95f408b9ce91ee846ed":    false,
		"":           false,
		"sha384-abc": false,
		"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed": false,
	}
	for value, want := range verifiable {
		if got := sriIsVerifiable(value); got != want {
			t.Errorf("sriIsVerifiable(%q) = %v, want %v", value, got, want)
		}
	}
}

// mixedTarget builds an HTTPS page carrying the given markup, which is the shape this check
// is about: the page is secure and the resource is not.
func mixedTarget(t *testing.T, markup string) *checks.Target {
	t.Helper()
	return responseTarget(t, "https://example.com/", "text/html",
		"<html><head></head><body>"+markup+"</body></html>")
}

// TestMixedContentGradedByWhatTheResourceIs: the browser distinguishes a resource it has to
// trust from one it merely displays, and so does the severity.
func TestMixedContentGradedByWhatTheResourceIs(t *testing.T) {
	cases := []struct {
		name     string
		markup   string
		severity finding.Severity
	}{
		{"script", `<script src="http://cdn.other.example/a.js"></script>`, finding.SeverityHigh},
		{"iframe", `<iframe src="http://other.example.com/frame"></iframe>`, finding.SeverityHigh},
		{"stylesheet", `<link rel="stylesheet" href="http://cdn.other.example/a.css">`, finding.SeverityHigh},
		{"form action", `<form action="http://other.example.com/post"><input></form>`, finding.SeverityHigh},
		{"object data", `<object data="http://other.example.com/a.swf"></object>`, finding.SeverityHigh},
		{"image", `<img src="http://cdn.other.example/a.png">`, finding.SeverityLow},
		{"media", `<video src="http://cdn.other.example/a.mp4"></video>`, finding.SeverityLow},
	}
	for _, tc := range cases {
		findings := runPassive(t, mixedContent{}, mixedTarget(t, tc.markup))
		if len(findings) == 0 {
			t.Errorf("%s over plain HTTP was not reported", tc.name)
			continue
		}
		if findings[0].Severity != tc.severity {
			t.Errorf("%s severity = %q, want %q", tc.name, findings[0].Severity, tc.severity)
		}
	}
}

// TestMixedContentRanksActiveAbovePassive: one active resource makes the finding active, and
// the passive ones are still listed rather than dropped.
func TestMixedContentRanksActiveAbovePassive(t *testing.T) {
	findings := runPassive(t, mixedContent{}, mixedTarget(t,
		`<img src="http://cdn.other.example/a.png"><script src="http://cdn.other.example/b.js"></script>`))
	if len(findings) == 0 {
		t.Fatal("mixed content was not reported")
	}
	if findings[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high once a script is involved", findings[0].Severity)
	}
	joined := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(joined, "script") || !strings.Contains(joined, "image") {
		t.Errorf("evidence drops one of the resources: %v", findings[0].Evidence.Matches)
	}
}

// TestMixedContentStaysQuietWhenEverythingIsHTTPS: nothing is mixed.
func TestMixedContentStaysQuietWhenEverythingIsHTTPS(t *testing.T) {
	findings := runPassive(t, mixedContent{}, mixedTarget(t,
		`<script src="https://cdn.other.example/a.js"></script><img src="//cdn.other.example/a.png">`))
	if len(findings) != 0 {
		t.Errorf("a page with no plain-HTTP resource was reported: %v", findings[0].Evidence.Matches)
	}
}

// cookieTarget builds a response carrying one Set-Cookie header.
func cookieTarget(t *testing.T, header string) *checks.Target {
	t.Helper()
	tg := responseTarget(t, "https://example.com/", "text/html", "<html><body>page</body></html>")
	tg.Response.Header.Add("Set-Cookie", header)
	return tg
}

// TestCookieFlagsReadAttributesNotSubstrings: a value that contains the word is not the
// attribute, and an attribute written without a space is still the attribute.
func TestCookieFlagsReadAttributesNotSubstrings(t *testing.T) {
	// The value says httponly; the cookie is not HttpOnly, and Secure is present without a
	// leading space.
	tg := cookieTarget(t, "sid=httponly;Secure;SameSite=Lax")
	findings := runPassive(t, cookieFlags{}, tg)
	if len(findings) == 0 {
		t.Fatal("a cookie with no HttpOnly attribute was not reported")
	}
	joined := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(joined, "HttpOnly") {
		t.Errorf("the missing attribute is not reported: %v", findings[0].Evidence.Matches)
	}
	if strings.Contains(joined, "missing Secure") {
		t.Errorf("Secure was present, written without a space: %v", findings[0].Evidence.Matches)
	}
}

// TestCookieFlagsFiresOnCombinationsBrowsersReject: these are not weaker cookies, they are
// ones the browser drops, which a reader skimming the header would not see.
func TestCookieFlagsFiresOnCombinationsBrowsersReject(t *testing.T) {
	cases := map[string]struct{ header, want string }{
		"SameSite=None without Secure": {
			"sid=abc; HttpOnly; SameSite=None", "reject outright"},
		"an unknown SameSite value": {
			"sid=abc; Secure; HttpOnly; SameSite=Laxx", "not one of Strict, Lax or None"},
		"__Host- with a Domain": {
			"__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Domain=example.com; Path=/", "forbids a Domain attribute"},
		"__Host- without Path=/": {
			"__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/app", "requires Path=/"},
		"__Secure- without Secure": {
			"__Secure-sid=abc; HttpOnly; SameSite=Lax; Path=/", "requires Secure"},
	}
	for name, tc := range cases {
		findings := runPassive(t, cookieFlags{}, cookieTarget(t, tc.header))
		if len(findings) == 0 {
			t.Errorf("%s was not reported", name)
			continue
		}
		if joined := strings.Join(findings[0].Evidence.Matches, " "); !strings.Contains(joined, tc.want) {
			t.Errorf("%s: evidence does not explain why: %v", name, findings[0].Evidence.Matches)
		}
	}
}

// TestCookieFlagsStaysQuietOnAWellFormedCookie: nothing to say about a cookie that meets
// every rule, prefix included.
func TestCookieFlagsStaysQuietOnAWellFormedCookie(t *testing.T) {
	tg := cookieTarget(t, "__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/")
	if findings := runPassive(t, cookieFlags{}, tg); len(findings) != 0 {
		t.Errorf("a well-formed cookie was reported: %v", findings[0].Evidence.Matches)
	}
}

// cacheTarget builds a response with the given Cache-Control and Set-Cookie, and a request
// that may or may not carry a credential.
func cacheTarget(t *testing.T, cacheControl, setCookie, requestHeader, requestValue string) *checks.Target {
	t.Helper()
	tg := responseTarget(t, "https://example.com/account", "text/html", "<html><body>page</body></html>")
	if cacheControl != "" {
		tg.Response.Header.Set("Cache-Control", cacheControl)
	}
	if setCookie != "" {
		tg.Response.Header.Add("Set-Cookie", setCookie)
	}
	if requestHeader != "" {
		tg.Request.Header.Set(requestHeader, requestValue)
	}
	return tg
}

// TestCacheControlNeedsAResponseThatBelongsToSomebody: without a session being set or
// answered, there is nothing to leak.
func TestCacheControlNeedsAResponseThatBelongsToSomebody(t *testing.T) {
	tg := cacheTarget(t, "public, max-age=600", "", "", "")
	if findings := runPassive(t, cacheControl{}, tg); len(findings) != 0 {
		t.Errorf("an anonymous response was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCacheControlFiresOnAShareableUserResponse: `public` tells a shared cache it may keep
// this user's response, which is the flaw stated exactly.
func TestCacheControlFiresOnAShareableUserResponse(t *testing.T) {
	tg := cacheTarget(t, "public, max-age=600", "sid=abc; Secure", "", "")
	findings := runPassive(t, cacheControl{}, tg)
	if len(findings) == 0 {
		t.Fatal("a shareable response carrying a session cookie was not reported")
	}
	if findings[0].Confidence != finding.ConfidenceFirm {
		t.Errorf("confidence = %q, want firm once the response is marked shareable", findings[0].Confidence)
	}
	joined := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(joined, "shareable") {
		t.Errorf("evidence does not explain the directive: %v", findings[0].Evidence.Matches)
	}
}

// TestCacheControlRanksAbsenceBelowPermission: a response with no Cache-Control at all is
// worth a tentative note, not the same claim as one marked shareable.
func TestCacheControlRanksAbsenceBelowPermission(t *testing.T) {
	tg := cacheTarget(t, "", "sid=abc; Secure", "", "")
	findings := runPassive(t, cacheControl{}, tg)
	if len(findings) == 0 {
		t.Fatal("a session cookie with no cache directive was not reported")
	}
	if findings[0].Confidence != finding.ConfidenceTentative {
		t.Errorf("confidence = %q, want tentative when nothing permits sharing", findings[0].Confidence)
	}
}

// TestCacheControlStaysQuietWhenTheResponseIsPrivate: the directives that do the job.
func TestCacheControlStaysQuietWhenTheResponseIsPrivate(t *testing.T) {
	for _, header := range []string{"private, max-age=0", "no-store", "private"} {
		tg := cacheTarget(t, header, "sid=abc; Secure", "", "")
		if findings := runPassive(t, cacheControl{}, tg); len(findings) != 0 {
			t.Errorf("Cache-Control %q was reported: %v", header, findings[0].Evidence.Matches)
		}
	}
}

// TestCacheControlNotesAMissingVary: `Vary` is how a cache tells users apart, so a
// shareable response without it is the stronger shape.
func TestCacheControlNotesAMissingVary(t *testing.T) {
	// The request carries a credential rather than the response setting one.
	withoutVary := cacheTarget(t, "public", "", "Authorization", "Bearer token")
	findings := runPassive(t, cacheControl{}, withoutVary)
	if len(findings) == 0 {
		t.Fatal("an authenticated response marked public was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "Vary") {
		t.Errorf("the missing Vary is not mentioned: %v", findings[0].Evidence.Matches)
	}

	withVary := cacheTarget(t, "public", "", "Authorization", "Bearer token")
	withVary.Response.Header.Set("Vary", "Authorization")
	findings = runPassive(t, cacheControl{}, withVary)
	if len(findings) == 0 {
		t.Fatal("the same response was not reported once Vary named the credential")
	}
	if strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "Vary does not name") {
		t.Errorf("Vary was named and still reported as missing: %v", findings[0].Evidence.Matches)
	}
}

// TestDirectoryListingNamesWhatItExposes: an index of images is a directory the site meant to
// serve; an index that names a database export is the database. The severity follows, and so
// does the evidence — a reader should not have to open the index to find out which this is.
func TestDirectoryListingNamesWhatItExposes(t *testing.T) {
	indexBody := func(names ...string) string {
		body := "<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1>\n" +
			"<a href=\"../\">Parent Directory</a>\n"
		for _, name := range names {
			body += "<a href=\"" + name + "\">" + name + "</a>\n"
		}
		return body + "</body></html>"
	}

	exposed := runPassive(t, directoryListing{},
		responseTarget(t, "http://example.com/files/", "text/html",
			indexBody("backup.sql", "config.php.bak", "logo.png")))
	if len(exposed) == 0 {
		t.Fatal("an index naming a database export was not reported")
	}
	if exposed[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high once the index names a backup", exposed[0].Severity)
	}
	if !strings.Contains(strings.Join(exposed[0].Evidence.Matches, " "), "backup") {
		t.Errorf("the evidence does not name what was exposed: %v", exposed[0].Evidence.Matches)
	}

	// The same page, with nothing on it that was not meant to be served.
	harmless := runPassive(t, directoryListing{},
		responseTarget(t, "http://example.com/files/", "text/html", indexBody("logo.png", "readme.txt")))
	if len(harmless) == 0 {
		t.Fatal("an index of ordinary files was not reported")
	}
	if harmless[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %q, want medium for an index of ordinary files", harmless[0].Severity)
	}
	if strings.Contains(strings.Join(harmless[0].Evidence.Matches, " "), "the index names") {
		t.Errorf("the evidence claims an exposure that is not there: %v", harmless[0].Evidence.Matches)
	}
}

// TestErrorDisclosureGradesWhatItExposes: a failure that names its own internals — a class, a
// frame, a file — is what leads a reader to the version and the line, and it is worth more than
// one that only says something went wrong. Both are reported, at different weights.
func TestErrorDisclosureGradesWhatItExposes(t *testing.T) {
	structural := runPassive(t, errorDisclosure{},
		responseTarget(t, "http://example.com/oops", "text/html",
			`<html><body>Traceback (most recent call last): File "/srv/app/views.py", line 42`+
				`<br>org.springframework.web.util.NestedServletException</body></html>`))
	if len(structural) == 0 {
		t.Fatal("a stack trace was not reported")
	}
	if structural[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %q, want medium once the page names its own frames", structural[0].Severity)
	}
	if !strings.Contains(strings.Join(structural[0].Evidence.Matches, " "), "Python traceback") {
		t.Errorf("the evidence does not name what was found: %v", structural[0].Evidence.Matches)
	}

	// The same kind of page, saying only that it failed.
	message := runPassive(t, errorDisclosure{},
		responseTarget(t, "http://example.com/oops", "text/html",
			"<html><body>Fatal error: Call to undefined function</body></html>"))
	if len(message) == 0 {
		t.Fatal("a fatal error was not reported")
	}
	if message[0].Severity != finding.SeverityLow {
		t.Errorf("severity = %q, want low when nothing internal is named", message[0].Severity)
	}
}

// TestContentDisclosureGradesAPathHigher: where the application lives on disk is what a file-read
// or a traversal would have to reach, so it is worth more than knowing a private network exists.
func TestContentDisclosureGradesAPathHigher(t *testing.T) {
	withPath := runPassive(t, contentDisclosure{},
		responseTarget(t, "http://example.com/", "text/html",
			"<html><body><p>Could not load /var/www/html/index.php</p></body></html>"))
	if len(withPath) == 0 {
		t.Fatal("a server-side path was not reported")
	}
	if withPath[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %q, want medium once a path is named", withPath[0].Severity)
	}

	withAddress := runPassive(t, contentDisclosure{},
		responseTarget(t, "http://example.com/", "text/html",
			"<html><body><p>Upstream 10.20.30.40 is unreachable</p></body></html>"))
	if len(withAddress) == 0 {
		t.Fatal("an internal address was not reported")
	}
	if withAddress[0].Severity != finding.SeverityLow {
		t.Errorf("severity = %q, want low for an address alone", withAddress[0].Severity)
	}
}
