package active

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// harness wires a check up to a live test server.
type harness struct {
	client *httpclient.Client
	ctx    *checks.Context
}

// newHarness builds a check context pointed at a test server.
func newHarness(t *testing.T) *harness {
	t.Helper()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	normalizer, err := diff.New(diff.Options{})
	if err != nil {
		t.Fatalf("diff.New: %v", err)
	}
	engine := diff.NewEngine(diff.ThresholdsForSensitivity(3), diff.DefaultKeywords())

	return &harness{
		client: client,
		ctx:    checks.NewContext(client, i18n.New(i18n.EN), engine, normalizer),
	}
}

// run fetches the target once for a baseline, then runs one check against it.
func (h *harness) run(t *testing.T, check checks.Check, targetURL string) []*finding.Finding {
	t.Helper()

	request, err := httpmsg.NewRequest("GET", targetURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline request: %v", err)
	}

	target := &checks.Target{Request: request, Response: baseline}
	findings := check.Run(context.Background(), h.ctx, target)
	checkEvidenceCarriesPayload(t, findings)
	return findings
}

// checkEvidenceCarriesPayload holds every finding to one rule: the request it records has to be the
// one that sent the payload it names. That request is what the terminal prints as a replay command
// and what a report's curl field is built from, so a finding that records a different probe
// describes something a reader cannot reproduce.
func checkEvidenceCarriesPayload(t *testing.T, findings []*finding.Finding) {
	t.Helper()
	for _, f := range findings {
		if f.Payload == "" || len(f.Evidence.Request) == 0 {
			continue
		}
		payload := f.Payload
		// Some checks append where the payload landed — "value (header X)" — and that note is for a
		// reader, not part of what went on the wire.
		if index := strings.LastIndex(payload, " ("); index > 0 {
			payload = payload[:index]
		}
		raw := string(f.Evidence.Request)
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			decoded = raw
		}
		if strings.Contains(decoded, payload) || strings.Contains(raw, payload) {
			continue
		}
		t.Errorf("%s: the evidence request does not carry the payload %q it names:\n%s",
			f.CheckID, f.Payload, raw)
	}
}

// withParameter returns the target with its first parameter selected, which is
// what the scanner would hand a check.
func withParameter(t *testing.T, h *harness, check checks.Check, targetURL string) []*finding.Finding {
	t.Helper()

	request, err := httpmsg.NewRequest("GET", targetURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline request: %v", err)
	}

	params := request.Params()
	if len(params) == 0 {
		t.Fatal("test URL has no parameters")
	}
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}
	findings := check.Run(context.Background(), h.ctx, target)
	checkEvidenceCarriesPayload(t, findings)
	return findings
}

func TestSQLiErrorFiresOnDatabaseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, `'"`) {
			fmt.Fprintf(w, `<html>You have an error in your SQL syntax near '%s' at line 1</html>`, id)
			return
		}
		fmt.Fprint(w, `<html><h1>Article</h1><p>`+strings.Repeat("body text ", 40)+`</p></html>`)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, sqliError{}, server.URL+"/?id=1")

	if len(findings) == 0 {
		t.Fatal("SQL error was not detected")
	}
	f := findings[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
	if f.Payload == "" {
		t.Error("no payload recorded")
	}
	if len(f.Evidence.Request) == 0 || len(f.Evidence.Response) == 0 {
		t.Error("evidence is incomplete")
	}
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q", f.CWE)
	}
}

func TestSQLiErrorStaysQuietOnCleanTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><h1>Article</h1><p>`+strings.Repeat("body text ", 40)+`</p></html>`)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, sqliError{}, server.URL+"/?id=1"); len(findings) != 0 {
		t.Errorf("clean target produced %d finding(s)", len(findings))
	}
}

func TestXSSReflectedFiresOnUnencodedEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Echo the value verbatim: the classic reflection.
		fmt.Fprintf(w, `<html><body><p>Results for: %s</p></body></html>`, r.URL.Query().Get("q"))
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, xssReflected{}, server.URL+"/?q=hello&page=1")

	if len(findings) == 0 {
		t.Fatal("unencoded reflection was not detected")
	}
	if findings[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
}

// TestXSSReflectedStaysQuietWhenEncoded is the check that keeps this finding
// trustworthy: a page that escapes the value is not vulnerable.
func TestXSSReflectedStaysQuietWhenEncoded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		escaped := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").
			Replace(r.URL.Query().Get("q"))
		fmt.Fprintf(w, `<html><body><p>Results for: %s</p></body></html>`, escaped)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, xssReflected{}, server.URL+"/?q=hello&page=1"); len(findings) != 0 {
		t.Errorf("an escaped reflection was reported as XSS: %+v", findings)
	}
}

func TestPathTraversalFiresOnFileContents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n")
			return
		}
		fmt.Fprint(w, "<html><body>file not found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/?file=readme.txt")

	if len(findings) == 0 {
		t.Fatal("file disclosure was not detected")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "root:x:0:0") {
		t.Errorf("evidence does not include the file contents: %v", findings[0].Evidence.Matches)
	}
}

// TestPathTraversalFiresWhenTheIncludeAppendsAnExtension covers the inclusion that writes the
// extension itself: `include($page . ".php")` resolves an absolute path to a file that does not
// exist, and the application's own script is still readable when it is named without the extension.
func TestPathTraversalFiresWhenTheIncludeAppendsAnExtension(t *testing.T) {
	source := "<?php\n// Entry point.\ninclude($_GET['page'] . '.php');\n"
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		page := r.URL.Query().Get("page")
		seen = append(seen, page)
		const wrapper = "php://filter/convert.base64-encode/resource="
		// Only the name without the extension is read: the application appends `.php` to
		// whatever it is given, so `index.php` would be opened as `index.php.php`, and a
		// path to a system file would be opened as a name that does not exist.
		if strings.TrimPrefix(page, wrapper) == "index" {
			// The application reads its own script and prints it base64-encoded.
			fmt.Fprintf(w, "<html><body><hr/><br/>%s</body></html>",
				base64.StdEncoding.EncodeToString([]byte(source)))
			return
		}
		// Everything else is a page that does not exist.
		fmt.Fprint(w, "<html><body><hr/><br/></body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/?page=login")

	if len(findings) == 0 {
		t.Fatalf("an inclusion that appends its own extension was not detected; the check sent %d request(s): %v",
			len(seen), seen)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "<?php") {
		t.Errorf("evidence does not name what was read: %v", findings[0].Evidence.Matches)
	}
}

// TestPathTraversalAsksForTheScriptTheRequestReached: the entry point is `view.php`, not the
// conventional `index.php`, and the include appends the extension. Only a name taken from the
// request can reach it, which is what makes the seeds work on applications in general rather than
// on the ones that happen to name their entry point `index`.
func TestPathTraversalAsksForTheScriptTheRequestReached(t *testing.T) {
	source := "<?php\n// Entry point.\ninclude($_GET['page'] . '.php');\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		const wrapper = "php://filter/convert.base64-encode/resource="
		if strings.TrimPrefix(r.URL.Query().Get("page"), wrapper) == "view" {
			fmt.Fprintf(w, "<html><body><hr/><br/>%s</body></html>",
				base64.StdEncoding.EncodeToString([]byte(source)))
			return
		}
		fmt.Fprint(w, "<html><body><hr/><br/></body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/app/view.php?page=login")

	if len(findings) == 0 {
		t.Fatal("an inclusion reached through the script named by the request was not detected")
	}
	if !strings.Contains(findings[0].Payload, "resource=view") {
		t.Errorf("the payload names %q, want the script the request reached", findings[0].Payload)
	}
}

// TestPathTraversalStaysQuietWhenThePagePublishesEncodedSource: a page that shows base64 of a PHP
// snippet carries the source shape before any payload is sent, and reporting it would be a false
// positive on every page that prints code.
func TestPathTraversalStaysQuietWhenThePagePublishesEncodedSource(t *testing.T) {
	snippet := base64.StdEncoding.EncodeToString([]byte(
		"<?php\n// A snippet a tutorial page would print.\nfunction demo() { return 42; }\n"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><pre>%s</pre></body></html>", snippet)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, pathTraversal{}, server.URL+"/?page=login"); len(findings) != 0 {
		t.Errorf("a page that publishes encoded source was reported as traversal: %+v", findings)
	}
}

// TestTheSourceShapeIsWhatMakesARead pins the evidence rule the wrapper seeds rest on: text that
// opens as a PHP file is source, and the tag appearing somewhere in a page is not.
func TestTheSourceShapeIsWhatMakesARead(t *testing.T) {
	cases := map[string]bool{
		"<?php\necho 1;\n":                           true,
		"\n\t <?php include $page; ?>":               true,
		"\ufeff<?php // byte order mark first":       true,
		"<p>Wrap the code in <?php tags</p>":         false,
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>": false,
		"root:x:0:0:root:/root:/bin/bash":            false,
	}
	for view, want := range cases {
		if got := looksLikePHPSource(view); got != want {
			t.Errorf("looksLikePHPSource(%q) = %v, want %v", view, got, want)
		}
	}
}

func TestOpenRedirectFiresOnExternalLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.HasPrefix(next, "http") || strings.HasPrefix(next, "//") {
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, openRedirect{}, server.URL+"/?next=/home")

	if len(findings) == 0 {
		t.Fatal("open redirect was not detected")
	}
	if findings[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

// TestOpenRedirectIgnoresSameSiteRedirects guards against the obvious false
// positive: a redirect to one of the application's own paths is not a
// vulnerability.
//
// The allowlist is deliberate. A `strings.HasPrefix(next, "/")` guard looks
// safe and is not: "////evil.example" starts with a slash and browsers read it
// as a protocol-relative URL to another host — which crackweb's payload set
// covers, and which is why this test uses a real allowlist.
func TestOpenRedirectIgnoresSameSiteRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		switch next {
		case "/home", "/dashboard", "/search":
			w.Header().Set("Location", next)
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, openRedirect{}, server.URL+"/?next=/dashboard"); len(findings) != 0 {
		t.Errorf("a same-site redirect was reported: %+v", findings)
	}
}

func TestSSTIFiresWhenExpressionIsEvaluated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(name, "{{1999*1999}}") {
			fmt.Fprint(w, "<html><body><h1>Hello 3996001</h1></body></html>")
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello %s</h1></body></html>", name)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, ssti{}, server.URL+"/?name=world")

	if len(findings) == 0 {
		t.Fatal("template evaluation was not detected")
	}
	if !strings.Contains(findings[0].Payload, "1999") {
		t.Errorf("payload = %q, want the arithmetic expression", findings[0].Payload)
	}
}

func TestCRLFStaysQuietOnWellBehavedServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http refuses to write a header containing CRLF, which is exactly
		// the protection the check is looking for.
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, crlfInjection{}, server.URL+"/?redirect=/home"); len(findings) != 0 {
		t.Errorf("CRLF injection reported against a safe server: %+v", findings)
	}
}

func TestChecksAreRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, check := range checks.All() {
		registered[check.ID()] = true
	}
	for _, id := range []string{
		"sqli-error", "sqli-boolean", "sqli-time", "xss-reflected", "path-traversal",
		"ssti", "open-redirect", "crlf-injection", "nosqli", "ssrf", "command-injection",
	} {
		if !registered[id] {
			t.Errorf("check %q is not registered", id)
		}
	}
}

// TestChecksDeclareTheirMetadata keeps the registry honest: every check must
// say what it is, how bad it is, and how to fix it, or the report cannot
// present it usefully.
func TestChecksDeclareTheirMetadata(t *testing.T) {
	for _, check := range checks.All() {
		if check.TitleKey() == "" && !checks.IsRequestLevel(check) {
			t.Errorf("%s has no title key", check.ID())
		}
		if check.DescriptionKey() == "" && !checks.IsRequestLevel(check) {
			t.Errorf("%s has no description key", check.ID())
		}
		if check.Severity() == finding.SeverityUnknown {
			t.Errorf("%s has no severity", check.ID())
		}
		if len(check.Tags()) == 0 {
			t.Errorf("%s has no tags", check.ID())
		}
		if check.ID() != strings.ToLower(check.ID()) {
			t.Errorf("%s should be lower-case", check.ID())
		}
	}
}
