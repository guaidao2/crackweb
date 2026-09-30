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

// stubOOB hands out callback addresses of a chosen shape and reports whether one was used.
type stubOOB struct {
	// shape is the callback URL, with {token} where the unique part goes.
	shape    string
	responds bool
	issued   int
}

func (s *stubOOB) NewURL(string) (string, string) {
	s.issued++
	token := fmt.Sprintf("tok%d", s.issued)
	return strings.ReplaceAll(s.shape, "{token}", token), token
}

func (s *stubOOB) Poll(string) []checks.Interaction {
	if !s.responds {
		return nil
	}
	return []checks.Interaction{{
		Protocol:   "dns",
		RemoteAddr: "192.0.2.9:53000",
		Detail:     "tok1.crackweb-oob.example",
	}}
}

// resolverServer answers like a JSON endpoint that builds an address from the value it is given.
func resolverServer(t *testing.T, requests *[]string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.URL.Query().Get("data"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func deserializationTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/api?data=x")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	return &checks.Target{Request: request, Response: response, Param: &params[0]}
}

// TestDeserializationCallbackFiresOnAResolvedName: the payload asks the parser to build an
// address from a name, the name is resolved, and the resolution comes back to the scan.
func TestDeserializationCallbackFiresOnAResolvedName(t *testing.T) {
	var requests []string
	server := resolverServer(t, &requests)
	target := deserializationTarget(t, server)

	h := newHarness(t)
	h.ctx.OOB = &stubOOB{shape: "http://{token}.crackweb-oob.example/", responds: true}
	findings := runRequestLevel(t, h, deserialization{}, target)
	if len(findings) == 0 {
		t.Fatal("a target that resolved the name in the payload was not reported")
	}
	if findings[0].CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "Inet4Address") {
		t.Errorf("payload = %q, want the payload that made the parser resolve a name", findings[0].Payload)
	}
}

// TestDeserializationCallbackStaysQuietWithoutADomain is the bound that keeps this from spending
// requests on a technique that cannot answer: with no delegated domain the callback is an
// address, an address is not resolved, and the payloads are never sent.
func TestDeserializationCallbackStaysQuietWithoutADomain(t *testing.T) {
	var requests []string
	server := resolverServer(t, &requests)
	target := deserializationTarget(t, server)

	h := newHarness(t)
	h.ctx.OOB = &stubOOB{shape: "http://10.0.0.5:8080/", responds: true}
	if findings := runRequestLevel(t, h, deserialization{}, target); len(findings) != 0 {
		t.Errorf("a numeric callback was reported: %v", findings[0].Evidence.Matches)
	}
	for _, sent := range requests {
		if strings.Contains(sent, "Inet4Address") {
			t.Errorf("a payload asking for a name to be resolved was sent with an address: %s", sent)
		}
	}
}
