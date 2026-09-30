package active

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// socketTarget builds the target for a page that already has a session, which is what makes the
// socket worth hijacking.
func socketTarget(t *testing.T, server *httptest.Server, withSession bool) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/ws")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if withSession {
		request.Header.Set("Cookie", "session=abc123")
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return &checks.Target{Request: request, Response: response}
}

// TestWebSocketOriginFiresOnAnUpgradeItShouldNotAccept: the handshake completes, with the
// acceptance header a WebSocket server has to compute, for an origin the application does not
// serve.
func TestWebSocketOriginFiresOnAnUpgradeItShouldNotAccept(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Key") == "" {
			fmt.Fprint(w, "<html><body>not a websocket endpoint</body></html>")
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, webSocketOrigin{}, socketTarget(t, server, true))
	if len(findings) == 0 {
		t.Fatal("a handshake accepted for any origin was not reported")
	}
	if findings[0].CWE != "CWE-1385" {
		t.Errorf("CWE = %q, want CWE-1385", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "crackweb-ws.example") {
		t.Errorf("payload = %q, want the origin that was asked with", findings[0].Payload)
	}
}

// TestWebSocketOriginStaysQuietWhenTheOriginIsChecked: the endpoint refuses an origin it does not
// serve.
func TestWebSocketOriginStaysQuietWhenTheOriginIsChecked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An exact comparison, which is what the check is not looking for.
		if origin := r.Header.Get("Origin"); origin != "" && origin != "https://"+r.Host {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, webSocketOrigin{}, socketTarget(t, server, true)); len(findings) != 0 {
		t.Errorf("an endpoint that checks the origin was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestWebSocketOriginStaysQuietWithoutASession: a socket that authenticates nobody has nothing to
// ride on, which is the first of the two things that keep this from reporting every socket.
func TestWebSocketOriginStaysQuietWithoutASession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, webSocketOrigin{}, socketTarget(t, server, false)); len(findings) != 0 {
		t.Errorf("a socket with no session was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestWebSocketOriginNeedsTheAcceptanceHeader is the second of the two: 101 alone is a status any
// endpoint may return, and a WebSocket server computes the acceptance value from the key.
func TestWebSocketOriginNeedsTheAcceptanceHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.WriteHeader(http.StatusSwitchingProtocols) // no acceptance header
			return
		}
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, webSocketOrigin{}, socketTarget(t, server, true)); len(findings) != 0 {
		t.Errorf("a bare 101 was read as a WebSocket handshake: %v", findings[0].Evidence.Matches)
	}
}

// TestWebSocketOriginFiresOnAWeakComparison is the second reason the variants are tried: a check
// written with a substring match — the site's own name as a suffix or a prefix — accepts an
// origin that is plainly not the site, and an exact comparison would have refused it.
func TestWebSocketOriginFiresOnAWeakComparison(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The host without its port, which is the spelling the variants carry: an origin that
		// names the site as a suffix is exactly the weak comparison being looked for.
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		origin := r.Header.Get("Origin")
		if origin != "" && !strings.HasSuffix(origin, host) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, webSocketOrigin{}, socketTarget(t, server, true))
	if len(findings) == 0 {
		t.Fatal("a socket whose origin check matches a suffix was not reported")
	}
	joined := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(joined, "substring") {
		t.Errorf("the evidence does not say what the mistake was: %v", findings[0].Evidence.Matches)
	}
	if !strings.Contains(findings[0].Payload, "crackweb-ws.example") {
		t.Errorf("payload = %q, want the origin that was accepted", findings[0].Payload)
	}
}
