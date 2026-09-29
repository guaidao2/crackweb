package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// naiveCacheServer is a cache that keys on the URL alone while the application builds a link
// out of a request header — which is the mistake the check exists to find.
func naiveCacheServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		mu    sync.Mutex
		store = map[string]string{}
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.String()
		mu.Lock()
		body, cached := store[key]
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		if cached {
			w.Header().Set("X-Cache", "HIT")
			fmt.Fprint(w, body)
			return
		}

		body = `<html><body><a href="http://` + r.Header.Get("X-Forwarded-Host") +
			`/account/reset">reset your password</a></body></html>`
		mu.Lock()
		store[key] = body
		mu.Unlock()

		w.Header().Set("X-Cache", "MISS")
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

// requestLevelTarget sends a request once and hands back the exchange.
func requestLevelTarget(t *testing.T, h *harness, rawURL string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return &checks.Target{Request: request, Response: baseline}
}

func TestCachePoisoningFiresWhenAStoredCopyCarriesTheValue(t *testing.T) {
	server := naiveCacheServer(t)
	h := newHarness(t)

	findings := runRequestLevel(t, h, cachePoisoning{}, requestLevelTarget(t, h, server.URL+"/page"))
	if len(findings) == 0 {
		t.Fatal("a cached copy carrying an injected header value was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-349" {
		t.Errorf("CWE = %q, want CWE-349", f.CWE)
	}
	// Certain: a request that never sent the header was handed the value.
	if f.Confidence != "certain" {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
	if !strings.Contains(f.Payload, "X-Forwarded-Host") {
		t.Errorf("the payload does not name the carrier: %q", f.Payload)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "without it") {
		t.Errorf("the evidence has to explain that a header-free request got the value: %v",
			f.Evidence.Matches)
	}
}

// TestCachePoisoningIgnoresACacheThatKeysTheHeader: a cache that keeps the header in its key
// serves each caller their own copy, which is the correct behaviour.
func TestCachePoisoningIgnoresACacheThatKeysTheHeader(t *testing.T) {
	var (
		mu    sync.Mutex
		store = map[string]string{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.String() + "|" + r.Header.Get("X-Forwarded-Host")
		mu.Lock()
		body, cached := store[key]
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		if cached {
			fmt.Fprint(w, body)
			return
		}
		body = `<html><body><a href="http://` + r.Header.Get("X-Forwarded-Host") + `/reset">reset</a></body></html>`
		mu.Lock()
		store[key] = body
		mu.Unlock()
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, cachePoisoning{}, requestLevelTarget(t, h, server.URL+"/page")); len(findings) != 0 {
		t.Errorf("a cache that keys the header was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCachePoisoningIgnoresAnUnreflectedHeader: without a reflection there is nothing for a
// cache to store, whatever else the target does.
func TestCachePoisoningIgnoresAnUnreflectedHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>nothing from a header here</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, cachePoisoning{}, requestLevelTarget(t, h, server.URL+"/page")); len(findings) != 0 {
		t.Errorf("an unreflected header was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCachePoisoningIgnoresNonCacheableMethods: a cache does not keep a POST, so poisoning
// one proves nothing.
func TestCachePoisoningIgnoresNonCacheableMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Header.Get("X-Forwarded-Host"))
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("POST", server.URL+"/page")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := runRequestLevel(t, h, cachePoisoning{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a POST was reported: %v", findings[0].Evidence.Matches)
	}
}

func TestCachePoisoningIsOptIn(t *testing.T) {
	// The poisoned entry stays in the cache for whoever asks for that URL next.
	if !checks.IsUnsafe(cachePoisoning{}) {
		t.Error("cache-poisoning has to be opt-in")
	}
}

func TestAppendQueryKeepsWhatIsThere(t *testing.T) {
	if got, want := appendQuery("", "cb", "abc"), "cb=abc"; got != want {
		t.Errorf("appendQuery on an empty string = %q, want %q", got, want)
	}
	if got, want := appendQuery("id=1", "cb", "abc"), "id=1&cb=abc"; got != want {
		t.Errorf("appendQuery kept the wrong thing: %q, want %q", got, want)
	}
}
