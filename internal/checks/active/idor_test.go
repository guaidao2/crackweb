package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// sessionsFor returns two identities that the test servers below recognise.
func sessionsFor() []checks.Session {
	return []checks.Session{
		{Label: "session-1", Headers: []httpmsg.KV{{Name: "Cookie", Value: "sess=alice"}}},
		{Label: "session-2", Headers: []httpmsg.KV{{Name: "Cookie", Value: "sess=bob"}}},
	}
}

// orderBody renders a plausible protected resource.
func orderBody(owner string) string {
	return fmt.Sprintf(`<html><body><h1>Order 42</h1>
<p>Owner: %s</p><p>Total: 199.00</p><p>Items: widget, gadget, sprocket</p>
<p>Shipping address: 1 Example Street</p></body></html>`, owner)
}

// TestIDORFiresWhenTwoSessionsSeeTheSameObject is the core case: the object is
// behind a login, yet both identities are handed the same content, so it is not
// scoped to its owner.
func TestIDORFiresWhenTwoSessionsSeeTheSameObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<html><body>Please log in to view this order.</body></html>")
			return
		}
		// The bug: the handler never checks that the order belongs to the
		// caller, so every signed-in user sees the same record.
		fmt.Fprint(w, orderBody("alice"))
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.Sessions = sessionsFor()

	findings := withParameter(t, h, accessControl{}, server.URL+"/order?id=42")
	if len(findings) == 0 {
		t.Fatal("a shared protected object was not reported as an access-control failure")
	}

	f := findings[0]
	if f.CWE != "CWE-639" {
		t.Errorf("CWE = %q, want CWE-639", f.CWE)
	}
	if string(f.Severity) != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	// The evidence must explain the reasoning, not just assert a conclusion.
	if len(f.Evidence.Matches) == 0 || !strings.Contains(f.Evidence.Matches[0], "anonymous") {
		t.Errorf("evidence does not explain the comparison: %v", f.Evidence.Matches)
	}
	if len(f.Evidence.Baseline) == 0 {
		t.Error("the anonymous response is not attached as evidence")
	}
}

// TestIDORStaysQuietWhenObjectsAreScoped is the test that makes the check
// usable: a correctly built application serves each user their own record.
func TestIDORStaysQuietWhenObjectsAreScoped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Cookie") {
		case "":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<html><body>Please log in to view this order.</body></html>")
		case "sess=alice":
			fmt.Fprint(w, orderBody("alice"))
		default:
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body>This order does not belong to your account.</body></html>")
		}
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.Sessions = sessionsFor()

	if findings := withParameter(t, h, accessControl{}, server.URL+"/order?id=42"); len(findings) != 0 {
		t.Errorf("a correctly scoped object was reported as an access-control failure")
	}
}

// TestIDORStaysQuietForPublicObjects covers the other obvious false positive: a
// page that anyone can read is not an access-control bug.
func TestIDORStaysQuietForPublicObjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, orderBody("public catalogue"))
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.Sessions = sessionsFor()

	if findings := withParameter(t, h, accessControl{}, server.URL+"/product?id=42"); len(findings) != 0 {
		t.Errorf("a public object was reported as an access-control failure")
	}
}

// TestIDORNeedsTwoSessions documents the contract: with one identity there is
// no way to tell "you can read your own record" from "you can read anyone's".
func TestIDORNeedsTwoSessions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "<html><body>log in first, please</body></html>")
			return
		}
		fmt.Fprint(w, orderBody("alice"))
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.Sessions = sessionsFor()[:1]

	if findings := withParameter(t, h, accessControl{}, server.URL+"/order?id=42"); len(findings) != 0 {
		t.Error("the check ran with a single session")
	}
}

// TestIDORIgnoresNonIdentifierParameters keeps the check from firing on every
// search box in the application.
func TestIDORIgnoresNonIdentifierParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, orderBody("alice"))
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.Sessions = sessionsFor()

	for _, target := range []string{
		server.URL + "/search?q=hello&lang=en",
		server.URL + "/page?title=about&sort=asc",
	} {
		findings := withParameter(t, h, accessControl{}, target)
		if len(findings) != 0 {
			t.Errorf("%s was treated as an object reference", target)
		}
	}
}

func TestLooksLikeIdentifier(t *testing.T) {
	cases := []struct {
		param httpmsg.Param
		want  bool
	}{
		{httpmsg.Param{Name: "id", Value: "42"}, true},
		{httpmsg.Param{Name: "userId", Value: "7"}, true},
		{httpmsg.Param{Name: "order_id", Value: "1001"}, true},
		{httpmsg.Param{Name: "account", Value: "abc"}, true},
		{httpmsg.Param{Name: "ref", Value: "550e8400-e29b-41d4-a716-446655440000"}, true},
		// A numeric value is an identifier whatever the parameter is called.
		{httpmsg.Param{Name: "page", Value: "3"}, true},
		// Free text is not.
		{httpmsg.Param{Name: "q", Value: "hello world"}, false},
		{httpmsg.Param{Name: "lang", Value: "en"}, false},
		{httpmsg.Param{Name: "sort", Value: "created_at"}, false},
	}

	for _, tc := range cases {
		if got := looksLikeIdentifier(tc.param); got != tc.want {
			t.Errorf("looksLikeIdentifier(%s=%s) = %v, want %v", tc.param.Name, tc.param.Value, got, tc.want)
		}
	}
}

func TestIsUUID(t *testing.T) {
	if !isUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("a well-formed UUID was rejected")
	}
	for _, bad := range []string{"", "not-a-uuid", "550e8400-e29b-41d4-a716", "550e8400xe29bx41d4xa716x446655440000"} {
		if isUUID(bad) {
			t.Errorf("isUUID(%q) = true", bad)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	for _, good := range []string{"0", "42", "1234567890"} {
		if !isNumeric(good) {
			t.Errorf("isNumeric(%q) = false", good)
		}
	}
	for _, bad := range []string{"", "-1", "1.5", "12a", "99999999999999999999999"} {
		if isNumeric(bad) {
			t.Errorf("isNumeric(%q) = true", bad)
		}
	}
}

// TestIDORIsRegistered keeps the check reachable from the CLI.
func TestIDORIsRegistered(t *testing.T) {
	if checks.ByID("idor") == nil {
		t.Fatal("the idor check is not registered")
	}
}
