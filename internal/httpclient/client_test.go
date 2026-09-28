package httpclient

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if !strings.Contains(body, DefaultUserAgent) {
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
