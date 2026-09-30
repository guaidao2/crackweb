package active

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// guardedSite reproduces the shape: the token is checked in the form branch, and the branches
// added later assume somebody else checks it.
func guardedSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		fields := map[string]string{}
		for _, pair := range strings.Split(string(body), "&") {
			if k, v, ok := strings.Cut(pair, "="); ok {
				fields[k] = v
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		// The guard compares the type exactly, which is the mistake: the same type under another
		// spelling skips it.
		if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			if fields["token"] != "SECRET-TOKEN" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "forbidden: bad or missing token\n")
				return
			}
		}
		fmt.Fprint(w, "accepted: action performed\n")
	}))
	t.Cleanup(server.Close)
	return server
}

func contentTypeTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("POST", server.URL+"/ct_bypass.php")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Body = []byte("action=delete&token=SECRET-TOKEN")
	request.Header.Set("Content-Length", fmt.Sprint(len(request.Body)))

	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if response.Status != 200 {
		t.Fatalf("baseline status = %d, want the guarded request to be accepted", response.Status)
	}
	// No Param: this is a request-level check.
	return &checks.Target{Request: request, Response: response}
}

// TestContentTypeBypassFiresWhenTheGuardIsOnOneType: refused with the request's own type and a
// forged token, accepted with the body unchanged and another type.
func TestContentTypeBypassFiresWhenTheGuardIsOnOneType(t *testing.T) {
	h := newHarness(t)
	findings := runRequestLevel(t, h, contentTypeBypass{}, contentTypeTarget(t, guardedSite(t)))
	if len(findings) == 0 {
		t.Fatal("a guard attached to one Content-Type was not reported")
	}
	if findings[0].CWE != "CWE-352" {
		t.Errorf("CWE = %q, want CWE-352", findings[0].CWE)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "refused") {
		t.Errorf("evidence does not show the refusal it is measured against: %v", findings[0].Evidence.Matches)
	}
}

// TestContentTypeBypassStaysQuietWhenTheTokenIsCheckedEverywhere: the guard holds whatever the
// body is called.
func TestContentTypeBypassStaysQuietWhenTheTokenIsCheckedEverywhere(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		if !strings.Contains(string(body), "token=SECRET-TOKEN") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "forbidden\n")
			return
		}
		fmt.Fprint(w, "accepted\n")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, contentTypeBypass{}, contentTypeTarget(t, server)); len(findings) != 0 {
		t.Errorf("an endpoint that always checks the token was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestContentTypeBypassStaysQuietWithoutAGuard: a request with no token to remove is somebody
// else's finding — there is nothing here to get around.
func TestContentTypeBypassStaysQuietWithoutAGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "accepted\n")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, contentTypeBypass{}, contentTypeTarget(t, server)); len(findings) != 0 {
		t.Errorf("an endpoint with no guard at all was reported: %v", findings[0].Evidence.Matches)
	}
}
