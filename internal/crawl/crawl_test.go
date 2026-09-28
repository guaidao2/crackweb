package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/scope"
)

func base(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestParseExtractsLinks(t *testing.T) {
	document := `<html><body>
		<a href="/about">About</a>
		<a href="https://other.example/x">External</a>
		<a href="#section">Anchor only</a>
		<a href="mailto:a@b.c">Mail</a>
		<a href="javascript:void(0)">JS</a>
		<iframe src="/frame"></iframe>
		<meta http-equiv="refresh" content="0; url=/refreshed">
	</body></html>`

	page, err := Parse(document, base(t, "https://example.com/page/"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]bool{
		"https://example.com/about":     true,
		"https://other.example/x":       true,
		"https://example.com/frame":     true,
		"https://example.com/refreshed": true,
	}
	for _, link := range page.Links {
		delete(want, link)
	}
	if len(want) > 0 {
		t.Errorf("missing links: %v (got %v)", want, page.Links)
	}
	for _, link := range page.Links {
		if strings.Contains(link, "#") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "javascript:") {
			t.Errorf("link %q should have been filtered out", link)
		}
	}
}

// TestParseExtractsScriptURLs covers the endpoints a link-only crawl misses:
// single-page applications keep them in string literals.
func TestParseExtractsScriptURLs(t *testing.T) {
	document := `<html><script>
		fetch("/api/v1/users?active=1");
		var base = 'https://example.com/api/orders';
		xhr.open("POST", "/api/login");
	</script></html>`

	page, err := Parse(document, base(t, "https://example.com/"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	joined := strings.Join(page.Links, " ")
	for _, want := range []string{"/api/v1/users?active=1", "https://example.com/api/orders", "/api/login"} {
		if !strings.Contains(joined, want) {
			t.Errorf("script URL %q not extracted; got %v", want, page.Links)
		}
	}
}

func TestParseExtractsForms(t *testing.T) {
	document := `<html><body>
		<form action="/login" method="post">
			<input type="text" name="user" value="admin">
			<input type="password" name="pass">
			<input type="hidden" name="csrf" value="tok123">
			<input type="submit" name="go" value="Sign in">
			<select name="role">
				<option value="user">User</option>
				<option value="admin" selected>Admin</option>
			</select>
			<textarea name="comment">hello</textarea>
		</form>
		<form><input name="q"></form>
	</body></html>`

	page, err := Parse(document, base(t, "https://example.com/"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(page.Forms) != 2 {
		t.Fatalf("got %d forms, want 2", len(page.Forms))
	}

	login := page.Forms[0]
	if got := login.URL(base(t, "https://example.com/")); got != "https://example.com/login" {
		t.Errorf("form URL = %q", got)
	}
	if login.Method != "POST" {
		t.Errorf("form method = %q, want POST", login.Method)
	}

	body := login.EncodeBody()
	for _, want := range []string{"user=admin", "csrf=tok123", "role=admin", "comment=hello"} {
		if !strings.Contains(body, want) {
			t.Errorf("form body %q is missing %q", body, want)
		}
	}
	// A submit button's name/value pair is not part of a scripted submission.
	if strings.Contains(body, "go=") {
		t.Errorf("form body %q includes the submit button", body)
	}

	// A form with no action posts back to the page it is on.
	if got := page.Forms[1].URL(base(t, "https://example.com/search")); got != "https://example.com/search" {
		t.Errorf("actionless form URL = %q", got)
	}
	if page.Forms[1].Method != "GET" {
		t.Errorf("actionless form method = %q, want GET", page.Forms[1].Method)
	}
}

func TestParseHandlesMalformedHTML(t *testing.T) {
	// The parser must not choke on the tag soup that real applications emit.
	page, err := Parse(`<div><a href="/a">unclosed<a href="/b">`, base(t, "https://example.com/"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(page.Links) == 0 {
		t.Error("no links extracted from malformed HTML")
	}
}

func TestAcceptFiltersOutOfScopeAndAssets(t *testing.T) {
	c := New(Options{Scope: []string{"example.com"}})
	c.scope = scope.NewScope([]string{"example.com"})

	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/page", true},
		{"https://example.com/deep/page?x=1", true},
		{"https://other.example/page", false},
		{"https://example.com/style.css", false},
		{"https://example.com/logo.png", false},
		{"mailto:a@b.c", false},
		{"https://example.com/page#frag", true},
	}

	for _, tc := range cases {
		key, ok := c.accept(tc.url, 0)
		if ok != tc.want {
			t.Errorf("accept(%q) = %v, want %v", tc.url, ok, tc.want)
		}
		if ok && strings.Contains(key, "#") {
			t.Errorf("accept(%q) kept the fragment: %q", tc.url, key)
		}
	}
}

// TestCrawlsALinkedSite is the end-to-end check: a small site is crawled, the
// pages are fetched, and the form on the last page produces a request the
// scanner can use.
func TestCrawlsALinkedSite(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		fmt.Fprint(w, `<html><body><h1>Home</h1><a href="/about">About</a><a href="/search">Search</a></body></html>`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		fmt.Fprint(w, `<html><body><a href="/deep/page">Deep</a></body></html>`)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		fmt.Fprint(w, `<html><body>
			<form action="/search" method="get">
				<input name="q" value="test">
			</form></body></html>`)
	})
	mux.HandleFunc("/deep/page", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path]++
		mu.Unlock()
		fmt.Fprint(w, `<html><body>leaf</body></html>`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	var (
		exchanges  []string
		exchangesM sync.Mutex
	)
	crawler := New(Options{
		Client: client,
		Engine: EngineHTTP,
		Depth:  3,
		OnExchange: func(req *httpmsg.Request, resp *httpmsg.Response) {
			exchangesM.Lock()
			exchanges = append(exchanges, req.URLString())
			exchangesM.Unlock()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := crawler.Run(ctx, server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	joined := strings.Join(exchanges, "\n")
	for _, want := range []string{"/about", "/search", "/deep/page"} {
		if !strings.Contains(joined, want) {
			t.Errorf("crawl did not reach %s; visited:\n%s", want, joined)
		}
	}
	// The form must have been submitted with its field.
	if !strings.Contains(joined, "q=test") {
		t.Errorf("crawl did not submit the form; visited:\n%s", joined)
	}

	stats := crawler.Stats()
	if stats.Pages < 4 {
		t.Errorf("Pages = %d, want at least 4", stats.Pages)
	}
	if stats.Elapsed <= 0 {
		t.Error("Elapsed was not recorded")
	}
}

func TestCrawlRespectsDepth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/one">1</a></html>`)
	})
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/two">2</a></html>`)
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/three">3</a></html>`)
	})
	mux.HandleFunc("/three", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><a href="/four">4</a></html>`)
	})
	mux.HandleFunc("/four", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>leaf</html>`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	var visited []string
	var mu sync.Mutex

	crawler := New(Options{
		Client: client,
		Engine: EngineHTTP,
		Depth:  1,
		OnExchange: func(req *httpmsg.Request, _ *httpmsg.Response) {
			mu.Lock()
			visited = append(visited, req.URL.Path)
			mu.Unlock()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := crawler.Run(ctx, server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range visited {
		if path == "/three" || path == "/four" {
			t.Errorf("depth 1 crawl reached %s; visited %v", path, visited)
		}
	}
}

func TestFindChromiumReturnsSomethingOrNothing(t *testing.T) {
	// The result depends on the host, so the contract to check is simply that
	// the lookup does not panic and returns a path or an empty string.
	path := FindChromium()
	if path != "" {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Errorf("FindChromium returned %q, which is not a usable file", path)
		}
	}
}

// TestCrawlSubmitsSelfPostingForm covers the form shape that matters most in
// practice: a form whose action is the page it sits on.
//
// It is the commonest layout on the server-rendered web — search boxes, login
// forms, filter panels all post back to themselves — and it is the one a
// URL-keyed deduplication would quietly break, because the POST target is a URL
// the crawl has already fetched with GET. The two are different requests and
// both have to be sent, so this test pins that down: a self-posting form is
// submitted, with its hidden fields carrying their default values.
func TestCrawlSubmitsSelfPostingForm(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseForm()
			mu.Lock()
			seen = append(seen, "POST id="+r.FormValue("id")+" code="+r.FormValue("code"))
			mu.Unlock()
			fmt.Fprint(w, `<html><body><form method="post" action="/">
				<input type="hidden" name="id" value="42">
				<input type="text" name="code" value="WELCOME10">
				<button type="submit">Go</button></form>
				<p>submitted</p></body></html>`)
			return
		}
		mu.Lock()
		seen = append(seen, "GET /")
		mu.Unlock()
		fmt.Fprint(w, `<html><body><form method="post" action="/">
			<input type="hidden" name="id" value="42">
			<input type="text" name="code" value="WELCOME10">
			<button type="submit">Go</button></form></body></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	crawler := New(Options{Client: client, Engine: EngineHTTP, Depth: 1, MaxPages: 5})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := crawler.Run(ctx, server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(seen, "\n")
	if !strings.Contains(joined, "POST id=42 code=WELCOME10") {
		t.Errorf("self-posting form was not submitted with its hidden fields; saw:\n%s", joined)
	}
	// The submit button must not become a parameter: applications reject bodies
	// that carry it.
	if strings.Contains(joined, "Go") {
		t.Errorf("the submit button was sent as a field; saw:\n%s", joined)
	}
}
