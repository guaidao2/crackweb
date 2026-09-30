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

func overrideTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/home")
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

// TestPathOverrideFiresWhenAHeaderDecidesThePath: the path asked for does not exist, and the
// header turns the answer into the one for a path that does.
func TestPathOverrideFiresWhenAHeaderDecidesThePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if header := r.Header.Get("X-Original-URL"); header != "" {
			path = header
		}
		switch path {
		case "/":
			fmt.Fprint(w, "<html><body>home page "+strings.Repeat("welcome ", 30)+"</body></html>")
		case "/home":
			fmt.Fprint(w, "<html><body>your home</body></html>")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>Not Found</body></html>")
		}
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, pathOverride{}, overrideTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a header that decides the handled path was not reported")
	}
	if findings[0].CWE != "CWE-863" {
		t.Errorf("CWE = %q, want CWE-863", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "X-Original-URL") {
		t.Errorf("payload = %q, want the header named", findings[0].Payload)
	}
}

// TestPathOverrideStaysQuietWhenTheHeaderIsIgnored: the same site without the override.
func TestPathOverrideStaysQuietWhenTheHeaderIsIgnored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, "<html><body>home page "+strings.Repeat("welcome ", 30)+"</body></html>")
		case "/home":
			fmt.Fprint(w, "<html><body>your home</body></html>")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>Not Found</body></html>")
		}
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, pathOverride{}, overrideTarget(t, server)); len(findings) != 0 {
		t.Errorf("a site that ignores the header was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestPathOverrideStaysQuietOnASinglePageApp is the control that matters most: when every
// path answers with the same page, a request for a missing one is not a miss, and nothing
// about the header can be concluded from it.
func TestPathOverrideStaysQuietOnASinglePageApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>app shell "+strings.Repeat("loading ", 30)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, pathOverride{}, overrideTarget(t, server)); len(findings) != 0 {
		t.Errorf("a single-page application was reported: %v", findings[0].Evidence.Matches)
	}
}
