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

func spoofTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/admin")
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

// TestIPSpoofFiresWhenTheRefusalWasAboutTheClaimedAddress: the endpoint said 403 and answered
// 200 once the header named a loopback address.
func TestIPSpoofFiresWhenTheRefusalWasAboutTheClaimedAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			fmt.Fprint(w, "<html><body>admin console "+strings.Repeat("privileged ", 20)+"</body></html>")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><body>Forbidden</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, ipSpoof{}, spoofTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("an endpoint opened by a spoofed address was not reported")
	}
	if findings[0].CWE != "CWE-290" {
		t.Errorf("CWE = %q, want CWE-290", findings[0].CWE)
	}
	if findings[0].Confidence != "certain" {
		t.Errorf("confidence = %q, want certain: the refusal became an answer", findings[0].Confidence)
	}
}

// TestIPSpoofStaysQuietWhenTheEndpointIgnoresTheHeader: the refusal stands.
func TestIPSpoofStaysQuietWhenTheEndpointIgnoresTheHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><body>Forbidden</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, ipSpoof{}, spoofTarget(t, server)); len(findings) != 0 {
		t.Errorf("an endpoint that ignores the header was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestIPSpoofStaysQuietWhenNothingWasRefused: a page that answered says nothing about what it
// would do for a refused request, so the check does not ask.
func TestIPSpoofStaysQuietWhenNothingWasRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>public page</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, ipSpoof{}, spoofTarget(t, server)); len(findings) != 0 {
		t.Errorf("a page that was not refused was reported: %v", findings[0].Evidence.Matches)
	}
}
