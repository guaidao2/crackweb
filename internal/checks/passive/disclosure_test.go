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
		"mailbox":          "contact the team at platform-operators@example.com",
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
		"<html><body>write to alice.smith@example.com</body></html>")
	findings := runPassive(t, contentDisclosure{}, tg)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	evidence := strings.Join(findings[0].Evidence.Matches, " ")
	if strings.Contains(evidence, "alice.smith@") {
		t.Errorf("the full address reached the report: %s", evidence)
	}
	if !strings.Contains(evidence, "example.com") {
		t.Errorf("the domain is missing from the report: %s", evidence)
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
	cases := map[string]string{
		"has a hash":             `<script src="https://cdn.other.example/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>`,
		"same origin":            `<script src="https://example.com/lib.js"></script>`,
		"relative path":          `<script src="/static/lib.js"></script>`,
		"an icon":                `<link rel="icon" href="https://cdn.other.example/favicon.ico">`,
		"stylesheet with a hash": `<link rel="stylesheet" href="https://cdn.other.example/a.css" integrity="sha384-abc">`,
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
