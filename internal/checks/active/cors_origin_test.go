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

// corsSite answers with whatever `reply` makes of the Origin it was sent.
func corsSite(t *testing.T, reply func(origin string) (string, bool)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, withCredentials := reply(r.Header.Get("Origin"))
		if allowed != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowed)
		}
		if withCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, "<html><body>page</body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

func corsTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/api/me")
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

// TestCORSOriginFiresWhenTheOriginIsEchoed: the policy names the caller's own origin, and
// credentials come with it.
func TestCORSOriginFiresWhenTheOriginIsEchoed(t *testing.T) {
	server := corsSite(t, func(origin string) (string, bool) { return origin, true })
	h := newHarness(t)
	findings := runRequestLevel(t, h, corsOrigin{}, corsTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a policy that echoed the request's origin was not reported")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical once credentials are allowed", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Payload, "crackweb-cors.example") {
		t.Errorf("payload = %q, want the origin that was asked with", findings[0].Payload)
	}
}

// TestCORSOriginFiresOnANullOrigin: `null` comes from sandboxed frames and local files, and a
// policy that names it is open to a document the attacker put there.
func TestCORSOriginFiresOnANullOrigin(t *testing.T) {
	server := corsSite(t, func(origin string) (string, bool) {
		if origin == "null" {
			return "null", true
		}
		return "", false
	})
	h := newHarness(t)
	findings := runRequestLevel(t, h, corsOrigin{}, corsTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a policy that allowed null was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "sandboxed") {
		t.Errorf("evidence does not explain what null is: %v", findings[0].Evidence.Matches)
	}
}

// TestCORSOriginFiresOnASuffixMatch: the host name is matched as a suffix rather than
// compared, so a name that merely ends with it is trusted.
func TestCORSOriginFiresOnASuffixMatch(t *testing.T) {
	server := corsSite(t, func(origin string) (string, bool) {
		if strings.HasSuffix(origin, "127.0.0.1") {
			return origin, true
		}
		return "", false
	})
	h := newHarness(t)
	if findings := runRequestLevel(t, h, corsOrigin{}, corsTarget(t, server)); len(findings) == 0 {
		t.Error("a suffix match on the host name was not reported")
	}
}

// TestCORSOriginStaysQuietWhenOnlyTheListedOriginIsAllowed: a policy that names one origin
// and refuses everything else.
func TestCORSOriginStaysQuietWhenOnlyTheListedOriginIsAllowed(t *testing.T) {
	server := corsSite(t, func(origin string) (string, bool) {
		if origin == "https://trusted.example" {
			return origin, true
		}
		return "", false
	})
	h := newHarness(t)
	if findings := runRequestLevel(t, h, corsOrigin{}, corsTarget(t, server)); len(findings) != 0 {
		t.Errorf("a policy with a fixed origin was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCORSOriginStaysQuietOnAWildcard: `*` is not this site trusting the caller, and it is the
// passive check's business.
func TestCORSOriginStaysQuietOnAWildcard(t *testing.T) {
	server := corsSite(t, func(string) (string, bool) { return "*", false })
	h := newHarness(t)
	if findings := runRequestLevel(t, h, corsOrigin{}, corsTarget(t, server)); len(findings) != 0 {
		t.Errorf("a wildcard was read as an echo: %v", findings[0].Evidence.Matches)
	}
}
