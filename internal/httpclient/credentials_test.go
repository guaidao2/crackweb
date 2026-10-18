package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// TestApplyCredentialsIsIdempotent: the entry point may be called more than once for
// the same request, and a Cookie credential must not accumulate a copy per call.
func TestApplyCredentialsIsIdempotent(t *testing.T) {
	client, err := New(Options{Credentials: []Credential{
		{Name: "Cookie", Value: "sess=abc"},
		{Name: "Authorization", Value: "Bearer x"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := httpmsg.NewRequest("GET", "http://example.test/x")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Cookie", "csrf=xyz")

	client.ApplyCredentials(req)
	client.ApplyCredentials(req)

	if got := req.Header.Get("Cookie"); got != "csrf=xyz; sess=abc" {
		t.Errorf("Cookie = %q, want one copy of each pair", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer x" {
		t.Errorf("Authorization = %q", got)
	}
}

// TestBareCookieTokenDoesNotAccumulate: a --cookie value without "=" is not a valid
// pair, but repeating it on every call would still grow the header.
func TestBareCookieTokenDoesNotAccumulate(t *testing.T) {
	client, err := New(Options{Credentials: []Credential{{Name: "Cookie", Value: "flag"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := httpmsg.NewRequest("GET", "http://example.test/x")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Cookie", "flag")
	client.ApplyCredentials(req)
	client.ApplyCredentials(req)

	if got := req.Header.Get("Cookie"); got != "flag" {
		t.Errorf("Cookie = %q, want the bare token once", got)
	}
}

// TestSendingDoesNotMutateTheSharedRequest is the regression test for the race and the
// growing header: Do used to write the identity into the message-model request on every
// send, while the checks sharing that request were reading it.
func TestSendingDoesNotMutateTheSharedRequest(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Cookie"))
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	client, err := New(Options{Credentials: []Credential{{Name: "Cookie", Value: "sess=abc"}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req, err := httpmsg.NewRequest("GET", server.URL+"/x")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Cookie", "csrf=xyz")
	client.ApplyCredentials(req)
	before := req.Header.Get("Cookie")

	for i := 0; i < 3; i++ {
		if _, err := client.Do(context.Background(), req); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}

	if got := req.Header.Get("Cookie"); got != before {
		t.Errorf("sending changed the shared request: %q -> %q", before, got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, cookie := range seen {
		if strings.Count(cookie, "sess=abc") != 1 {
			t.Errorf("a request carried a duplicated credential: %q", cookie)
		}
	}
}
