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
