package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

func exposedTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/index.html")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return &checks.Target{Request: request, Response: response}
}

// TestExposedPathFiresOnAnEnvironmentFile: the file nothing links to is being served, and its
// contents say what it is.
func TestExposedPathFiresOnAnEnvironmentFile(t *testing.T) {
	files := map[string]string{
		"/.env": "APP_KEY=base64:crackweb\nDB_PASSWORD=hunter2\n",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if content, ok := files[r.URL.Path]; ok {
			fmt.Fprint(w, content)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a served environment file was not reported")
	}
	if findings[0].CWE != "CWE-538" {
		t.Errorf("CWE = %q, want CWE-538", findings[0].CWE)
	}
	if findings[0].Payload != "/.env" {
		t.Errorf("payload = %q, want the path that answered", findings[0].Payload)
	}
}

// TestExposedPathStaysQuietWhenNothingIsThere: the ordinary site.
func TestExposedPathStaysQuietWhenNothingIsThere(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.html" {
			fmt.Fprint(w, "<html><body>home</body></html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server)); len(findings) != 0 {
		t.Errorf("a site without those files was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestExposedPathStaysQuietOnASiteThatAnswersEverything is the control: a catch-all route
// answers every address with the same page, and that page is not a file it is serving.
// TestExposedPathStaysQuietOnASiteThatEchoesTheName covers the second way a catch-all makes
// this check wrong: the page does not answer with one fixed shell, it answers with the address
// it was asked for. "swagger" and "openapi" are words two of the paths are built from, so the
// echo matches the signature and the control is no help — the two answers differ in the name
// and nothing else. An API description is an object; a page repeating a name back is not.
func TestExposedPathStaysQuietOnASiteThatEchoesTheName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><p>result: %s</p></body></html>", strings.TrimPrefix(r.URL.Path, "/"))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server)); len(findings) != 0 {
		t.Errorf("a site that echoes the name it was asked for was reported: %v", findings[0].Evidence.Matches)
	}
}

func TestExposedPathStaysQuietOnASiteThatAnswersEverything(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>app shell "+strings.Repeat("loading ", 20)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server)); len(findings) != 0 {
		t.Errorf("a catch-all route was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestExposedPathStaysQuietWhenTheSignatureIsElsewhere: the page mentions the word but is not
// the file — the signature is only evidence with the missing-path comparison behind it.
func TestExposedPathStaysQuietWhenThePageMentionsIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.html" {
			fmt.Fprint(w, "<html><body>home "+strings.Repeat("welcome ", 20)+"</body></html>")
			return
		}
		// A page that talks about environment files without being one.
		fmt.Fprint(w, "<html><body>Documentation: set APP_KEY in your .env file "+strings.Repeat("docs ", 20)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server)); len(findings) != 0 {
		t.Errorf("a page mentioning the signature was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestExposedPathFiresOnFrameworkSettings: the list is not only about the obvious files — a
// framework's own settings module carries the key it signs sessions with, and nothing links to
// it either.
func TestExposedPathFiresOnFrameworkSettings(t *testing.T) {
	files := map[string]string{
		"/settings.py": "SECRET_KEY = \"crackweb-secret\"\nDEBUG = True\n",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The framework's own footprint, which is what makes its settings file worth asking for.
		w.Header().Add("Set-Cookie", "csrftoken=abc; Path=/")
		if content, ok := files[r.URL.Path]; ok {
			fmt.Fprint(w, content)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a served framework settings file was not reported")
	}
	if findings[0].Payload != "/settings.py" {
		t.Errorf("payload = %q, want the path that answered", findings[0].Payload)
	}
}

// TestSuggestedTechnologiesReadsWhatTheServerVolunteers: the hints come from the headers and
// the body, and nothing is inferred without them.
func TestSuggestedTechnologiesReadsWhatTheServerVolunteers(t *testing.T) {
	anonymous := &httpmsg.Response{Status: 200, Body: []byte("<html><body>plain page</body></html>")}
	if got := suggestedTechnologies(anonymous); len(got) != 0 {
		t.Errorf("a page that said nothing suggested %v", got)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.4.22")
		fmt.Fprint(w, "<html><body>plain page</body></html>")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	suggested := suggestedTechnologies(response)
	if !suggested["nginx"] || !suggested["php"] {
		t.Errorf("nginx and php were not read from the headers: %v", suggested)
	}
	if suggested["django"] || suggested["spring"] {
		t.Errorf("a technology nobody mentioned was suggested: %v", suggested)
	}
}

// TestExposedPathSkipsStackSpecificNamesWithoutAHint: the entries that need a reason are not
// asked for without one — that is the whole point of the hints.
func TestExposedPathSkipsStackSpecificNamesWithoutAHint(t *testing.T) {
	asked := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked[r.URL.Path] = true
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	_ = runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server))

	for _, path := range []string{"/settings.py", "/nginx_status", "/application.properties", "/wp-config.php.bak"} {
		if asked[path] {
			t.Errorf("%s was asked for without any hint that the target runs it", path)
		}
	}
	// The ones that need no reason are still asked.
	if !asked["/.env"] || !asked["/.git/config"] {
		t.Errorf("an entry that needs no hint was skipped: %v", asked)
	}
}

// TestExposedPathAsksThemWhenTheHintsAreThere: and with a hint, they are asked for.
func TestExposedPathAsksThemWhenTheHintsAreThere(t *testing.T) {
	asked := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked[r.URL.Path] = true
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	_ = runRequestLevel(t, h, exposedPath{}, exposedTarget(t, server))
	if !asked["/nginx_status"] {
		t.Error("nginx_status was not asked for on a server that calls itself nginx")
	}
	if asked["/settings.py"] {
		t.Error("a Django settings file was asked for on an nginx server")
	}
}

// TestExposedPathSignaturesCarryNothingAPageWouldEscape keeps the rule the notes in AGENTS.md
// describe: a signature with a character a page escapes cannot match an escaped body, and the
// one exception here is the script backup, whose response is source rather than markup.
func TestExposedPathSignaturesCarryNothingAPageWouldEscape(t *testing.T) {
	for _, entry := range exposedPathSignatures {
		if entry.signature != "<?php" && strings.ContainsAny(entry.signature, `"'<>&`) {
			t.Errorf("%s: signature %q carries a character a page would escape", entry.path, entry.signature)
		}
	}
}

// TestHostOnceAnswersEachHostQuestionOnce pins the mechanism the host-level checks share.
func TestHostOnceAnswersEachHostQuestionOnce(t *testing.T) {
	ctx := &checks.Context{}
	if !ctx.HostOnce("example.test", "a") {
		t.Fatal("the first caller was told the question had been asked")
	}
	if ctx.HostOnce("example.test", "a") {
		t.Error("the second caller was told it had not")
	}
	if !ctx.HostOnce("example.test", "b") {
		t.Error("a different question on the same host was treated as already asked")
	}
	if !ctx.HostOnce("other.test", "a") {
		t.Error("the same question on another host was treated as already asked")
	}
	// A check with no host to ask about does its work rather than skipping it.
	if !ctx.HostOnce("", "a") {
		t.Error("a nameless host was treated as already asked")
	}
}

// TestExposedPathAsksOncePerHost is why the mechanism exists: the check asks which paths a host
// publishes, and a crawl dispatches it once per discovered URL. Without this the same thirty-odd
// requests go out for every page of the site.
func TestExposedPathAsksOncePerHost(t *testing.T) {
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		if r.URL.Path == "/.env" {
			fmt.Fprint(w, "APP_KEY=base64:crackweb\nDB_PASSWORD=hunter2\n")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	// Two different pages of the same host, as a crawl would hand them over.
	for _, path := range []string{"/index.html", "/about.html"} {
		request, err := httpmsg.NewRequest("GET", server.URL+path)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		response, err := h.client.Do(context.Background(), request)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		runRequestLevel(t, h, exposedPath{}, &checks.Target{Request: request, Response: response})
	}

	envRequests := 0
	for _, path := range requested {
		if path == "/.env" {
			envRequests++
		}
	}
	if envRequests != 1 {
		t.Errorf("/.env was asked for %d time(s) across two pages of one host, want once", envRequests)
	}
}
