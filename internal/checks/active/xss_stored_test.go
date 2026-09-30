package active

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// guestbookSite stores what is posted and renders it on the next read.
func guestbookSite(t *testing.T, escape bool) *httptest.Server {
	t.Helper()
	var (
		mu    sync.Mutex
		posts []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseForm()
			mu.Lock()
			posts = append(posts, r.FormValue("body"))
			mu.Unlock()
			fmt.Fprint(w, "<html><body>thanks</body></html>")
			return
		}
		mu.Lock()
		stored := strings.Join(posts, " ")
		mu.Unlock()
		if escape {
			stored = strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(stored)
		}
		fmt.Fprintf(w, "<html><body><div>%s</div><p>%s</p></body></html>",
			stored, strings.Repeat("filler ", 30))
	}))
	t.Cleanup(server.Close)
	return server
}

func runStored(t *testing.T, server *httptest.Server) int {
	t.Helper()
	h := newHarness(t)
	request, err := httpmsg.NewRequest("POST", server.URL+"/guestbook")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Body = []byte("body=hello")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Length", "10")

	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	if len(params) == 0 {
		t.Fatal("no parameters")
	}
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}
	return len((xssStored{}).Run(context.Background(), h.ctx, target))
}

func TestXSSStoredFiresWhenTheValueIsKept(t *testing.T) {
	if n := runStored(t, guestbookSite(t, false)); n == 0 {
		t.Error("a value stored and served back as markup was not reported")
	}
}

func TestXSSStoredStaysQuietWhenTheValueIsEscaped(t *testing.T) {
	if n := runStored(t, guestbookSite(t, true)); n != 0 {
		t.Error("a value escaped on output was reported")
	}
}

// TestXSSStoredIgnoresSafeMethods: a read stores nothing.
func TestXSSStoredIgnoresSafeMethods(t *testing.T) {
	server := guestbookSite(t, false)
	h := newHarness(t)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/guestbook?body=hello")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}
	if n := len((xssStored{}).Run(context.Background(), h.ctx, target)); n != 0 {
		t.Error("a GET was treated as a write")
	}
}

// TestXSSPathReflectionFiresOnUnescapedSegment: the route prints the name it was addressed by
// into the page, which is a reflection the parameter walk cannot reach.
func TestXSSPathReflectionFiresOnUnescapedSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", segments[len(segments)-1])
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/greet/world?ref=top")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	findings := runRequestLevel(t, h, xssReflected{}, target)
	if len(findings) == 0 {
		t.Fatal("a segment printed unescaped into the page was not reported")
	}
	if findings[0].CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "path segment") {
		t.Errorf("payload = %q, want the payload to say where it was put", findings[0].Payload)
	}
}

// TestXSSPathReflectionStaysQuietWhenTheSegmentIsEscaped is the line the judgement draws: the
// value still comes back, and it is not executable.
func TestXSSPathReflectionStaysQuietWhenTheSegmentIsEscaped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>",
			template.HTMLEscapeString(segments[len(segments)-1]))
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/greet/world?ref=top")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	if findings := runRequestLevel(t, h, xssReflected{}, target); len(findings) != 0 {
		t.Errorf("an escaped segment was reported: %v", findings[0].Evidence.Matches)
	}
}
