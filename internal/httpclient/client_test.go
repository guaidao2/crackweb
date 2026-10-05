package httpclient

import (
	"compress/gzip"
	"context"
	"fmt"
	"github.com/guaidao2/crackweb/internal/version"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// request builds a message-model request pointed at a test server.
func request(t *testing.T, method, rawURL string, body string, headers ...string) *httpmsg.Request {
	t.Helper()
	req, err := httpmsg.NewRequest(method, rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	if body != "" {
		req.Body = []byte(body)
	}
	return req
}

func TestDoGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s ua=%s", r.Method, r.URL.Path, r.UserAgent())
	}))
	defer server.Close()

	client, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := client.Do(context.Background(), request(t, "GET", server.URL+"/hello", ""))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if resp.Status != 200 {
		t.Errorf("status = %d, want 200", resp.Status)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "path=/hello") {
		t.Errorf("body = %q, want it to carry the path", body)
	}
	if !strings.Contains(body, DefaultUserAgent()) {
		t.Errorf("body = %q, want crackweb's User-Agent", body)
	}
	if resp.Duration <= 0 {
		t.Error("Duration was not recorded")
	}
}

func TestDoPostSendsBodyAndContentType(t *testing.T) {
	var gotBody, gotType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)
		gotType = r.Header.Get("Content-Type")
	}))
	defer server.Close()

	client, _ := New(Options{})
	req := request(t, "POST", server.URL+"/login", "user=admin&pass=1",
		"Content-Type", "application/x-www-form-urlencoded")
	if _, err := client.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if gotBody != "user=admin&pass=1" {
		t.Errorf("server saw body %q", gotBody)
	}
	if gotType != "application/x-www-form-urlencoded" {
		t.Errorf("server saw Content-Type %q", gotType)
	}
}

func TestDoPreservesHostHeader(t *testing.T) {
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
	}))
	defer server.Close()

	client, _ := New(Options{})
	req := request(t, "GET", server.URL+"/", "")
	req.Header.Set("Host", "virtual.example.com")
	if _, err := client.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if gotHost != "virtual.example.com" {
		t.Errorf("server saw Host %q, want the overridden value", gotHost)
	}
}

// TestRedirectsAreNotFollowedByDefault matters for open-redirect detection: the
// Location header has to stay visible.
func TestRedirectsAreNotFollowedByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landing", http.StatusFound)
	}))
	defer server.Close()

	client, _ := New(Options{})
	resp, err := client.Do(context.Background(), request(t, "GET", server.URL+"/", ""))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if resp.Status != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.Status)
	}
	if got := resp.Header.Get("Location"); got != "/landing" {
		t.Errorf("Location = %q, want /landing", got)
	}
}

func TestRedirectsCanBeFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		fmt.Fprint(w, "landed")
	}))
	defer server.Close()

	client, _ := New(Options{FollowRedirects: true})
	resp, err := client.Do(context.Background(), request(t, "GET", server.URL+"/", ""))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if resp.Status != 200 || string(resp.Body) != "landed" {
		t.Errorf("got %d %q, want 200 \"landed\"", resp.Status, resp.Body)
	}
	if !strings.HasSuffix(resp.FinalURL, "/landing") {
		t.Errorf("FinalURL = %q, want it to end in /landing", resp.FinalURL)
	}
}

func TestResponseBodyIsTruncatedAtMaxBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("A", 5000))
	}))
	defer server.Close()

	client, _ := New(Options{MaxBody: 1000})
	resp, err := client.Do(context.Background(), request(t, "GET", server.URL+"/", ""))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if len(resp.Body) != 1000 {
		t.Errorf("body length = %d, want 1000", len(resp.Body))
	}
	if !resp.Truncated {
		t.Error("Truncated = false, want true")
	}
}

func TestGzippedBodyIsDecompressed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		_, _ = gz.Write([]byte("decompressed payload"))
	}))
	defer server.Close()

	// Asking for gzip explicitly stops net/http from handling it, which is the
	// path a replayed capture takes.
	client, _ := New(Options{})
	req := request(t, "GET", server.URL+"/", "", "Accept-Encoding", "gzip")
	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if got := string(resp.Body); got != "decompressed payload" {
		t.Errorf("body = %q, want the decompressed payload", got)
	}
}

func TestRetriesTransientFailures(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail the first two attempts by closing the connection without a
		// response, then succeed.
		if attempts.Add(1) < 3 {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("test server does not support hijacking")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	client, _ := New(Options{Retry: 3})
	resp, err := client.Do(context.Background(), request(t, "GET", server.URL+"/", ""))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "ok" {
		t.Errorf("body = %q, want ok", resp.Body)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestRateLimiterPacesRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	// Five requests per second with a burst of one: the fifth request cannot
	// arrive before roughly 800ms have passed.
	client, _ := New(Options{Rate: 5, Burst: 1})

	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := client.Do(context.Background(), request(t, "GET", server.URL+"/", "")); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 700*time.Millisecond {
		t.Errorf("five requests at 5/s took %v, want the limiter to slow them down", elapsed)
	}
}

func TestRateLimiterHonoursContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	client, _ := New(Options{Rate: 0.5, Burst: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := client.Do(ctx, request(t, "GET", server.URL+"/", "")); err != nil {
		t.Fatalf("first request should pass: %v", err)
	}
	// The second has to wait two seconds for a token; the context gives up first.
	if _, err := client.Do(ctx, request(t, "GET", server.URL+"/", "")); err == nil {
		t.Error("second request succeeded, want the context deadline to win")
	}
}

func TestInvalidProxyIsRejected(t *testing.T) {
	if _, err := New(Options{Proxy: "ftp://proxy:3128"}); err == nil {
		t.Error("unsupported proxy scheme accepted")
	}
	if _, err := New(Options{Proxy: "://bad"}); err == nil {
		t.Error("malformed proxy URL accepted")
	}
}

func TestRequestWithoutURLFails(t *testing.T) {
	client, _ := New(Options{})
	if _, err := client.Do(context.Background(), &httpmsg.Request{Method: "GET"}); err == nil {
		t.Error("request without a URL was sent")
	}
}

// TestCredentialsAreAppliedToEveryRequest: the point of setting an identity on
// the client is that checks which build their own requests carry it too.
func TestCredentialsAreAppliedToEveryRequest(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	client, err := New(Options{Credentials: []Credential{{Name: "Cookie", Value: "session=abc"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.Do(context.Background(), request(t, "GET", server.URL+"/x", "")); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if seen != "session=abc" {
		t.Errorf("Cookie = %q, want %q", seen, "session=abc")
	}
}

// TestCookieIsMergedNotReplaced: a request may carry its own cookies — a CSRF
// token, a consent flag — and dropping them would break the very session the
// credential is meant to preserve.
func TestCookieIsMergedNotReplaced(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	client, err := New(Options{Credentials: []Credential{{Name: "Cookie", Value: "session=abc"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := request(t, "GET", server.URL+"/x", "")
	req.Header.Set("Cookie", "csrf=xyz")
	if _, err := client.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !strings.Contains(seen, "csrf=xyz") || !strings.Contains(seen, "session=abc") {
		t.Errorf("Cookie = %q, want both csrf=xyz and session=abc", seen)
	}
}

// TestExistingAuthorizationIsNotOverridden: a request that already names an
// identity is more specific than a client-wide default.
func TestExistingAuthorizationIsNotOverridden(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	client, err := New(Options{Credentials: []Credential{{Name: "Authorization", Value: "Basic Zm9vOmJhcg=="}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := request(t, "GET", server.URL+"/x", "")
	req.Header.Set("Authorization", "Bearer request-token")
	if _, err := client.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if seen != "Bearer request-token" {
		t.Errorf("Authorization = %q; the request's own value must win", seen)
	}
}

// TestRandomUAComposesRatherThanRepeats: rotation only defeats fingerprinting if
// the values are varied and well-formed. A short fixed list is a fingerprint of
// its own.
func TestRandomUAComposesRatherThanRepeats(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 400; i++ {
		ua := randomUserAgent()
		if !strings.HasPrefix(ua, "Mozilla/5.0 (") {
			t.Fatalf("composed a User-Agent that no browser would send: %q", ua)
		}
		if strings.Contains(strings.ToLower(ua), "crackweb") {
			t.Fatalf("the rotated pool leaks the tool's name: %q", ua)
		}
		seen[ua] = true
	}
	// Not a statistical claim: just enough distinct values that a log cannot
	// group the traffic by this field.
	if len(seen) < 20 {
		t.Errorf("400 calls produced only %d distinct User-Agents", len(seen))
	}
}

// TestRandomUAVariesPerRequest: one identity per client is the same problem at a
// larger scale — it still groups every request together.
func TestRandomUAVariesPerRequest(t *testing.T) {
	var seen = map[string]bool{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.UserAgent()] = true
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	client, err := New(Options{RandomUA: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 40; i++ {
		if _, err := client.Do(context.Background(), request(t, "GET", server.URL+"/x", "")); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if len(seen) < 5 {
		t.Errorf("40 requests carried only %d distinct User-Agents", len(seen))
	}
}

// TestDefaultUserAgentCarriesTheVersion: the banner and the wire should agree.
func TestDefaultUserAgentCarriesTheVersion(t *testing.T) {
	if !strings.Contains(DefaultUserAgent(), version.Version) {
		t.Errorf("DefaultUserAgent() = %q, want it to contain %q", DefaultUserAgent(), version.Version)
	}
}

// TestPerRequestTimeoutOverridesTheClientDeadline is the fix for a silent loss:
// a check that asks the server to wait needs more time than an ordinary request,
// and http.Client.Timeout cannot be widened for one exchange. The deadline has
// to come from the request.
func TestPerRequestTimeoutOverridesTheClientDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
		fmt.Fprint(w, "slow but fine")
	}))
	defer server.Close()

	// The client's default is far too short for this handler.
	client, err := New(Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Do(context.Background(), request(t, "GET", server.URL+"/x", "")); err == nil {
		t.Error("the client default was not applied")
	}

	slow := request(t, "GET", server.URL+"/x", "")
	slow.Timeout = 5 * time.Second
	resp, err := client.Do(context.Background(), slow)
	if err != nil {
		t.Fatalf("a request with its own deadline was cut off: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d, want 200", resp.Status)
	}
}

// TestPerRequestTimeoutStillFires: widening one request must not disable the
// deadline altogether.
func TestPerRequestTimeoutStillFires(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		fmt.Fprint(w, "too slow")
	}))
	defer server.Close()

	client, err := New(Options{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := request(t, "GET", server.URL+"/x", "")
	req.Timeout = 200 * time.Millisecond
	if _, err := client.Do(context.Background(), req); err == nil {
		t.Error("a request's own deadline was not enforced")
	}
}

// TestCredentialsReachTheRequestTheChecksRead pins the half that is easy to lose: the identity
// has to be visible on the message-model request as well as on the wire.
//
// A check is handed the httpmsg.Request, not the wire request, so writing the credential only
// where net/http can see it leaves every check reading an anonymous request while the crawler
// browses as the authenticated user. That is the difference between scanning behind a login and
// scanning the login page and believing it was the other one.
func TestCredentialsReachTheRequestTheChecksRead(t *testing.T) {
	var (
		mu     sync.Mutex
		auth   string
		cookie string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth, cookie = r.Header.Get("Authorization"), r.Header.Get("Cookie")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(Options{Credentials: []Credential{
		{Name: "Authorization", Value: "Bearer crackweb-token"},
		{Name: "Cookie", Value: "sess=crackweb"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req, err := httpmsg.NewRequest("GET", server.URL+"/behind-a-login")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := client.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	mu.Lock()
	wireAuth, wireCookie := auth, cookie
	mu.Unlock()

	if wireAuth != "Bearer crackweb-token" {
		t.Errorf("the wire request carried %q, want the configured token", wireAuth)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer crackweb-token" {
		t.Errorf("the request the checks read carried %q, want the configured token", got)
	}
	if !strings.Contains(wireCookie, "sess=crackweb") {
		t.Errorf("the wire request carried cookie %q", wireCookie)
	}
	if got := req.Header.Get("Cookie"); !strings.Contains(got, "sess=crackweb") {
		t.Errorf("the request the checks read carried cookie %q", got)
	}
}

// TestCredentialsDoNotOverwriteTheRequestsOwnIdentity keeps the rule that made this safe to add:
// a request that already names an identity is never rewritten.
func TestCredentialsDoNotOverwriteTheRequestsOwnIdentity(t *testing.T) {
	client, err := New(Options{Credentials: []Credential{{Name: "Authorization", Value: "Bearer default"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := httpmsg.NewRequest("GET", "http://example.test/x")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer specific")

	httpReq, err := client.buildRequest(context.Background(), req, false)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer specific" {
		t.Errorf("a request's own identity was overwritten with %q", got)
	}
	if got := httpReq.Header.Get("Authorization"); got != "Bearer specific" {
		t.Errorf("the wire request's identity was overwritten with %q", got)
	}
}

// TestAnAnonymousRequestStaysAnonymous is the regression test for a control that cancelled its
// own findings.
//
// A check proves a resource is protected by sending the request again without the identity.
// Deleting the header and calling Do is not enough: a configured credential is a default for
// any request that does not name one, so Do puts it straight back. The control then
// authenticates, succeeds, and quietly discards the finding it exists to support — which is how
// a real alg=none acceptance went unreported in crawl mode while single-URL scans (whose path
// left no credential to restore) reported it.
func TestAnAnonymousRequestStaysAnonymous(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{Credentials: []Credential{{Name: "Authorization", Value: "Bearer configured"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req, err := httpmsg.NewRequest("GET", server.URL+"/api/thing")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer configured")

	// The normal path authenticates.
	if _, err := client.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	// The anonymous path must not, however the request was prepared.
	stripped := req.Clone()
	stripped.Header.Del("Authorization")
	if _, err := client.DoAnonymous(context.Background(), stripped); err != nil {
		t.Fatalf("DoAnonymous: %v", err)
	}

	if len(seen) != 2 {
		t.Fatalf("expected two requests, saw %d", len(seen))
	}
	if seen[0] == "" {
		t.Error("the authenticated request carried no credential")
	}
	if seen[1] != "" {
		t.Errorf("the anonymous request carried %q: the credential was restored", seen[1])
	}
}
