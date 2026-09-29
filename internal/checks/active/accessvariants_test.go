package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// protectedTarget sends the request once and hands back the exchange, which is what a
// request-level check is given.
func protectedTarget(t *testing.T, h *harness, rawURL string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline request: %v", err)
	}
	return &checks.Target{Request: request, Response: baseline}
}

// TestAccessVariantsFiresWhenAnotherSpellingIsServed is the case the check exists for: the
// rule covers the path as written, and the layer serving the resource recognises another
// spelling of it.
func TestAccessVariantsFiresWhenAnotherSpellingIsServed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body>Forbidden: administrators only</body></html>")
		case "/admin/":
			// The router behind the rule treats the trailing slash as the same resource.
			fmt.Fprint(w, "<html><body><h1>Administration</h1><p>12 users, 3 pending</p></body></html>")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, accessControlVariants{}, protectedTarget(t, h, server.URL+"/admin"))

	if len(findings) == 0 {
		t.Fatal("a refusal that did not survive a trailing slash was not reported")
	}
	f := findings[0]
	if f.Payload != "trailing slash" {
		t.Errorf("variant = %q, want %q", f.Payload, "trailing slash")
	}
	if f.CWE != "CWE-863" {
		t.Errorf("CWE = %q, want CWE-863", f.CWE)
	}
	if string(f.Severity) != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if len(f.Evidence.Request) == 0 || len(f.Evidence.Baseline) == 0 {
		t.Error("the evidence must carry both the variant that worked and the refusal")
	}
}

// TestAccessVariantsFiresWhenAnotherMethodIsServed: the rule was written for one method
// while the framework answers another.
func TestAccessVariantsFiresWhenAnotherMethodIsServed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<html><body>Authentication required</body></html>")
			return
		}
		if r.Method == http.MethodPost {
			fmt.Fprint(w, "<html><body><h1>Administration</h1><p>12 users, 3 pending</p></body></html>")
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, accessControlVariants{}, protectedTarget(t, h, server.URL+"/admin"))

	if len(findings) == 0 {
		t.Fatal("a refusal that did not survive a change of method was not reported")
	}
	if findings[0].Payload != "method POST" {
		t.Errorf("variant = %q, want %q", findings[0].Payload, "method POST")
	}
	if findings[0].Method != "POST" {
		t.Errorf("finding method = %q, want POST", findings[0].Method)
	}
}

// TestAccessVariantsIgnoresAConsistentRefusal: every spelling refused is a rule doing its
// job, and reporting it would be noise.
func TestAccessVariantsIgnoresAConsistentRefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><body>Forbidden: administrators only</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, accessControlVariants{}, protectedTarget(t, h, server.URL+"/admin")); len(findings) != 0 {
		t.Errorf("a consistent refusal was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestAccessVariantsIgnoresAMissingResource: a 404 says nothing about a rule, so it is not
// a baseline to work from.
func TestAccessVariantsIgnoresAMissingResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gone" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>Not found</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body><h1>Administration</h1></body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, accessControlVariants{}, protectedTarget(t, h, server.URL+"/gone")); len(findings) != 0 {
		t.Errorf("a 404 was treated as a refusal to bypass: %v", findings[0].Evidence.Matches)
	}
}

// TestAccessVariantsIgnoresAnUnsupportedMethod: an OPTIONS that answers 200 is a
// capability announcement, not the resource, and the check does not ask with it.
func TestAccessVariantsIgnoresAnUnsupportedMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><body>Forbidden: administrators only</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, accessControlVariants{}, protectedTarget(t, h, server.URL+"/admin")); len(findings) != 0 {
		t.Errorf("an OPTIONS capability response was reported as a bypass: %v", findings[0].Evidence.Matches)
	}
}

// TestPathVariantsCoverTheSpellingsThatDiffer pins the variant list down: each entry is a
// way of writing the same resource that one layer may normalise and another may not.
func TestPathVariantsCoverTheSpellingsThatDiffer(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.com/admin/panel?x=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	seen := map[string]string{}
	for _, variant := range pathVariants(request.URL) {
		seen[variant.name] = variant.url.EscapedPath()
	}
	for name, want := range map[string]string{
		"trailing slash":            "/admin/panel/",
		"repeated separator":        "//admin/panel",
		"upper case":                "/ADMIN/PANEL",
		"dot segment":               "/admin/./panel",
		"percent-encoded character": "/admin/%70anel",
	} {
		if got, ok := seen[name]; !ok {
			t.Errorf("variant %q is missing", name)
		} else if got != want {
			t.Errorf("variant %q = %q, want %q", name, got, want)
		}
	}
}

// TestAccessVariantsIgnoresARedirect: a redirect is as likely to be the "go and log in"
// detour as it is to be the resource, and the check does not guess between the two.
func TestAccessVariantsIgnoresARedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body>Forbidden: administrators only</body></html>")
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, accessControlVariants{}, protectedTarget(t, h, server.URL+"/admin")); len(findings) != 0 {
		t.Errorf("a redirect was reported as the resource being served: %v", findings[0].Evidence.Matches)
	}
}
