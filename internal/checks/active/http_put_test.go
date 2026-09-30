package active

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

func putTarget(t *testing.T, server *httptest.Server) *checks.Target {
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

// TestHTTPPutFiresOnAServerThatStoresWrites keeps the whole judgement in one place: the file
// is written, read back, and a path nothing was written to is missing.
func TestHTTPPutFiresOnAServerThatStoresWrites(t *testing.T) {
	files := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut, http.MethodPatch:
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			files[r.URL.Path] = string(body)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, "created")
		default:
			if content, ok := files[r.URL.Path]; ok {
				fmt.Fprint(w, content)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Not Found")
		}
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, httpPut{}, putTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a server that stored a PUT was not reported")
	}
	if findings[0].CWE != "CWE-434" {
		t.Errorf("CWE = %q, want CWE-434", findings[0].CWE)
	}
	if !strings.HasPrefix(findings[0].Payload, "PUT ") {
		t.Errorf("payload = %q, want the write described", findings[0].Payload)
	}
}

// TestHTTPPutStaysQuietWhenWritesAreRefused: the ordinary server.
func TestHTTPPutStaysQuietWhenWritesAreRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, "Method Not Allowed")
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Not Found")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, httpPut{}, putTarget(t, server)); len(findings) != 0 {
		t.Errorf("a server that refuses writes was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestHTTPPutStaysQuietWhenEverythingIsServed is the control that matters most: a site that
// answers every path with something cannot show that a write happened.
func TestHTTPPutStaysQuietWhenEverythingIsServed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>app shell "+strings.Repeat("loading ", 20)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, httpPut{}, putTarget(t, server)); len(findings) != 0 {
		t.Errorf("a site that serves every path was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestHTTPPutWritesOncePerHost: the file this check stores is a property of the host, and a crawl
// reaches the same host once per page. Each repeat is another change to a system nobody asked to
// change, so the check asks once and reports on the basis of that one attempt.
func TestHTTPPutWritesOncePerHost(t *testing.T) {
	stored := map[string]string{}
	var puts int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			puts++
			body, _ := io.ReadAll(r.Body)
			stored[r.URL.Path] = string(body)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			if body, ok := stored[r.URL.Path]; ok {
				fmt.Fprint(w, body)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Not Found")
		}
	}))
	defer server.Close()

	h := newHarness(t)
	for _, path := range []string{"/index.html", "/about.html"} {
		request, err := httpmsg.NewRequest("GET", server.URL+path)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		response, err := h.client.Do(context.Background(), request)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		runRequestLevel(t, h, httpPut{}, &checks.Target{Request: request, Response: response})
	}

	mu.Lock()
	defer mu.Unlock()
	if puts != 1 {
		t.Errorf("the host received %d PUT(s) across two pages, want one", puts)
	}
}
