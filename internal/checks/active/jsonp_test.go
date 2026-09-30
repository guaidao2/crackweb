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

func jsonpTarget(t *testing.T, server *httptest.Server) *checks.Target {
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

// TestJSONPFiresWhenTheCallbackIsHonoured: the endpoint builds the call around the name it was
// given, and the same address without it answers with the data alone.
func TestJSONPFiresWhenTheCallbackIsHonoured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := `{"user":"admin","token":"secret"}`
		if callback := r.URL.Query().Get("callback"); callback != "" {
			fmt.Fprintf(w, "%s(%s);", callback, data)
			return
		}
		fmt.Fprint(w, data)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, jsonp{}, jsonpTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("an honoured callback was not reported")
	}
	if findings[0].CWE != "CWE-346" {
		t.Errorf("CWE = %q, want CWE-346", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "callback="+jsonpMarker) {
		t.Errorf("payload = %q, want the callback the probe asked for", findings[0].Payload)
	}
}

// TestJSONPStaysQuietOnAPageThatEchoesTheName: the echo contains the marker, which is why the
// judgement requires the parenthesis that follows it in a call.
func TestJSONPStaysQuietOnAPageThatEchoesTheName(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>You asked for %s but this endpoint is not a JSONP one</body></html>",
			r.URL.Query().Get("callback"))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, jsonp{}, jsonpTarget(t, server)); len(findings) != 0 {
		t.Errorf("an endpoint that echoed the name was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestJSONPStaysQuietOnOrdinaryJSON: a JSON response that ignores the parameter is the endpoint
// behaving.
func TestJSONPStaysQuietOnOrdinaryJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"user":"admin"}`)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, jsonp{}, jsonpTarget(t, server)); len(findings) != 0 {
		t.Errorf("an ordinary JSON endpoint was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestJSONPWrappedInRequiresTheCall pins the predicate itself: the name alone is an echo, the
// name followed by a parenthesis is a call.
func TestJSONPWrappedInRequiresTheCall(t *testing.T) {
	if jsonpWrappedIn([]byte("<p>callback: crackwebJsonpCallback</p>"), jsonpMarker) {
		t.Error("a bare mention was read as a call")
	}
	if !jsonpWrappedIn([]byte("crackwebJsonpCallback({});"), jsonpMarker) {
		t.Error("a call was not recognised")
	}
	if !jsonpWrappedIn([]byte("CRACKWEBJSONPCALLBACK({});"), jsonpMarker) {
		t.Error("a call spelled in another case was not recognised")
	}
}
