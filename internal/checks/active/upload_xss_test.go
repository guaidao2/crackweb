package active

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
)

// nameEchoSite renders the uploaded name back to the page, encoded or not. It
// still judges names — one no filesystem could hold is refused — so the control
// group in the check sees an endpoint with answers to tell apart.
func nameEchoSite(t *testing.T, escaping bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		// Every entry is judged, not just the first: an endpoint that checks one of two would
		// be the duplicate-field finding, and this fixture is not that.
		for _, candidate := range allFilenames(string(raw)) {
			if len(candidate) > 200 || isDangerousUploadName(candidate) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
				return
			}
		}
		name := filenameFromBody(string(raw))
		if escaping {
			name = html.EscapeString(name)
		}
		fmt.Fprintf(w, "<html><body><p>uploaded: %s</p>%s</body></html>",
			name, strings.Repeat("thank you ", 30))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadFiresOnAFilenameThatIsRendered: the file is never executed, but its
// name is stored as markup in the page that lists it.
func TestUploadFiresOnAFilenameThatIsRendered(t *testing.T) {
	server := nameEchoSite(t, false)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an upload form that rendered the name as markup was not reported")
	}
	if findings[0].CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "onerror") && !strings.Contains(findings[0].Payload, "onload") {
		t.Errorf("payload = %q, want a markup-carrying name", findings[0].Payload)
	}
}

// TestUploadStaysQuietWhenTheNameIsEncoded: the same page, encoding what it
// prints. Nothing is stored, so nothing is reported.
func TestUploadStaysQuietWhenTheNameIsEncoded(t *testing.T) {
	server := nameEchoSite(t, true)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a page that encoded the name was reported: %v", findings[0].Evidence.Matches)
	}
}

// strippingUploadSite normalises a name the way PHP does — the path is dropped
// before the file is stored — and refuses the dangerous extensions. It is the
// hardened shape, and the traversal names must not be reported against it.
func strippingUploadSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		name := filenameFromBody(string(raw))
		if index := strings.LastIndexAny(name, `/\`); index >= 0 {
			name = name[index+1:]
		}
		for _, candidate := range allFilenames(string(raw)) {
			if index := strings.LastIndexAny(candidate, `/\`); index >= 0 {
				candidate = candidate[index+1:]
			}
			if len(candidate) > 200 || isDangerousUploadName(candidate) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
				return
			}
		}
		fmt.Fprintf(w, "<html><body>Upload complete: %s %s</body></html>",
			html.EscapeString(name), strings.Repeat("thank you ", 30))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadStaysQuietWhenTheServerStripsThePath: the file was accepted, but the
// path in the name was not used, and the response looks exactly like a genuine
// upload — because it is one. Reporting this would be a false positive against
// every PHP endpoint that uploads correctly.
func TestUploadStaysQuietWhenTheServerStripsThePath(t *testing.T) {
	server := strippingUploadSite(t)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a server that stripped the path was reported: %v", findings[0].Evidence.Matches)
	}
}
