package active

import (
	"context"
	"fmt"
	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/finding"
)

// fetchSite is a target that fetches whatever URL it is given — the shape of the
// application-side request forgery this check is for — and prints what came back.
// The metadata service is simulated because the address itself is link-local.
func fetchSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			target = r.FormValue("url")
		}
		switch {
		case strings.Contains(target, "169.254.169.254"),
			strings.Contains(target, "100.100.100.200"),
			strings.Contains(target, "metadata.google.internal"):
			fmt.Fprint(w, "<pre>ami-id\nami-launch-index\ninstance-id\ninstance-type\n"+
				"local-hostname\nsecurity-credentials/\n</pre>")
		default:
			fmt.Fprintf(w, "<pre>fetched: %s</pre>", html.EscapeString(target))
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestSSRFFiresOnCloudMetadata: the target reached a service that answers only
// from inside an instance, and handed back its fields. No listener of ours was
// involved, which is what makes this the strongest form the check can report.
func TestSSRFFiresOnCloudMetadata(t *testing.T) {
	server := fetchSite(t)
	h := newHarness(t)
	findings := withParameter(t, h, ssrf{}, server.URL+"/fetch?url=http://example.com")
	if len(findings) == 0 {
		t.Fatal("a target that fetched the instance metadata service was not reported")
	}
	f := findings[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
	if !strings.Contains(f.Payload, "169.254.169.254") && !strings.Contains(f.Payload, "100.100.100.200") &&
		!strings.Contains(f.Payload, "metadata.google.internal") {
		t.Errorf("payload = %q, want a metadata address", f.Payload)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "ami-id") {
		t.Errorf("the evidence does not quote the metadata: %v", f.Evidence.Matches)
	}
}

// TestSSRFStaysQuietWhenThePageOnlyEchoesItsInput: a page that prints the URL it
// was given renders the metadata *address*, and every seed contains one. Only the
// metadata *contents* are evidence, and they are absent here.
func TestSSRFStaysQuietWhenThePageOnlyEchoesItsInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><p>You asked for %s</p></body></html>",
			html.EscapeString(r.URL.Query().Get("url")))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, ssrf{}, server.URL+"/fetch?url=http://example.com"); len(findings) != 0 {
		t.Errorf("a page that only echoed its input was reported: %v", findings[0].Evidence.Matches)
	}
}

// internalServiceSite answers the way a fetch proxy does, and only a protocol request
// gets the service's own reply back: the payload has to speak Redis to see `+PONG`.
func internalServiceSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if strings.Contains(target, "gopher://") && strings.Contains(target, "6379") {
			fmt.Fprint(w, "<pre>+PONG\r\n</pre>")
			return
		}
		if strings.Contains(target, "gopher://") && strings.Contains(target, "11211") {
			fmt.Fprint(w, "<pre>STAT pid 1\r\nSTAT uptime 42\r\nEND\r\n</pre>")
			return
		}
		fmt.Fprintf(w, "<pre>fetched: %s</pre>", html.EscapeString(target))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestSSRFFiresOnAnInternalService: the reply is the service's, not the target's, so the
// evidence is the protocol answer itself.
func TestSSRFFiresOnAnInternalService(t *testing.T) {
	server := internalServiceSite(t)
	h := newHarness(t)
	findings := withParameter(t, h, ssrf{}, server.URL+"/fetch?url=http://example.com")
	if len(findings) == 0 {
		t.Fatal("a target that carried a protocol request to an internal service was not reported")
	}
	f := findings[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(f.Payload, "gopher://") {
		t.Errorf("payload = %q, want a protocol request", f.Payload)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "Redis") {
		t.Errorf("evidence does not name the service: %v", f.Evidence.Matches)
	}
}

// TestSSRFStaysQuietWhenTheAnswerIsTheTargetsOwn: a page that prints the string for its
// own reasons is not a service answering.
func TestSSRFStaysQuietWhenTheAnswerIsTheTargetsOwn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body><p>our status page mentions +PONG sometimes</p></body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, ssrf{}, server.URL+"/fetch?url=http://example.com"); len(findings) != 0 {
		t.Errorf("a page that already mentioned the signature was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestSSRFFileReadFiresOnAFetcherThatTakesTheFileScheme: the URL the caller supplies reaches a
// function that opens paths as readily as it opens pages, and the file comes back in the
// response.
func TestSSRFFileReadFiresOnAFetcherThatTakesTheFileScheme(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/plain")
		if strings.HasPrefix(target, "file://") && strings.Contains(target, "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/usr/bin/zsh\ndaemon:x:1:1:daemon:/usr/sbin\n")
			return
		}
		fmt.Fprint(w, "fetch failed\n")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/?url=http://example.test")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()

	findings := runRequestLevel(t, h, ssrf{}, &checks.Target{Request: request, Response: response, Param: &params[0]})
	if len(findings) == 0 {
		t.Fatal("a fetcher that returned a file was not reported")
	}
	if findings[0].CWE != "CWE-918" {
		t.Errorf("CWE = %q, want CWE-918", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "file://") {
		t.Errorf("payload = %q, want the file the server was asked for", findings[0].Payload)
	}
}

// TestSSRFFileReadStaysQuietWhenTheSchemeIsRefused: a fetcher that only ever returns what it
// could not fetch is not evidence of anything.
func TestSSRFFileReadStaysQuietWhenTheSchemeIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "not a permitted scheme\n")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/?url=http://example.test")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()

	if findings := runRequestLevel(t, h, ssrf{}, &checks.Target{Request: request, Response: response, Param: &params[0]}); len(findings) != 0 {
		t.Errorf("a refused scheme was reported: %v", findings[0].Evidence.Matches)
	}
}
