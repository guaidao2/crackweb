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

// refererGuardedSite reproduces the shape: the token is checked only when the request looks like
// it came from the application, which is a promise the browser never made.
func refererGuardedSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fields := map[string]string{}
		for _, pair := range strings.Split(string(body), "&") {
			if k, v, ok := strings.Cut(pair, "="); ok {
				fields[k] = v
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		if referer := r.Header.Get("Referer"); referer != "" && strings.Contains(referer, "127.0.0.1") {
			if fields["token"] != "SECRET-TOKEN" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "forbidden: bad token\n")
				return
			}
		}
		fmt.Fprint(w, "accepted: action performed\n")
	}))
	t.Cleanup(server.Close)
	return server
}

func refererTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("POST", server.URL+"/referer_guard.php")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", server.URL+"/form")
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
	return &checks.Target{Request: request, Response: response}
}

// TestRefererBypassFiresWhenTheGuardNeedsTheHeader: refused with the token forged, accepted with
// the same forged token and no Referer at all.
func TestRefererBypassFiresWhenTheGuardNeedsTheHeader(t *testing.T) {
	h := newHarness(t)
	findings := runRequestLevel(t, h, refererBypass{}, refererTarget(t, refererGuardedSite(t)))
	if len(findings) == 0 {
		t.Fatal("a guard resting on the Referer header was not reported")
	}
	if findings[0].CWE != "CWE-352" {
		t.Errorf("CWE = %q, want CWE-352", findings[0].CWE)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "was refused") {
		t.Errorf("evidence does not show the refusal it is measured against: %v", findings[0].Evidence.Matches)
	}
}

// TestRefererBypassStaysQuietWhenTheTokenIsCheckedAnyway: the guard holds whatever the header says.
func TestRefererBypassStaysQuietWhenTheTokenIsCheckedAnyway(t *testing.T) {
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
	if findings := runRequestLevel(t, h, refererBypass{}, refererTarget(t, server)); len(findings) != 0 {
		t.Errorf("an endpoint that always checks the token was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestRefererBypassStaysQuietWithoutAGuard: there is no token to forge, so there is nothing here
// to get around.
func TestRefererBypassStaysQuietWithoutAGuard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "accepted\n")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("POST", server.URL+"/plain")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Body = []byte("action=delete")
	request.Header.Set("Content-Length", fmt.Sprint(len(request.Body)))
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	target := &checks.Target{Request: request, Response: response}
	if findings := runRequestLevel(t, h, refererBypass{}, target); len(findings) != 0 {
		t.Errorf("an endpoint with no guard at all was reported: %v", findings[0].Evidence.Matches)
	}
}
