package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// outputSite is a target whose parameter reaches a shell and whose page prints
// what the shell produced — the reflected form of command injection, which needs
// no listener of the scanner's own. It accepts the hidden spellings too, because
// a filter is what those exist to get past: `cat${IFS}/etc/pass?d` is the same
// command as `cat /etc/passwd`.
func outputSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			ip = r.FormValue("ip")
		}
		w.Header().Set("Content-Type", "text/html")
		echoed := strings.ReplaceAll(ip, "<", "&lt;")

		reads := strings.Contains(ip, "passwd") || strings.Contains(ip, "pass?d") ||
			strings.Contains(ip, "pass*")
		if reads && strings.Contains(ip, "cat") {
			fmt.Fprintf(w, "<html><body><p>PING %s</p><pre>"+
				"root:x:0:0:root:/root:/bin/bash\n"+
				"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
				"www-data:x:82:82::/home/www-data:/sbin/nologin</pre></body></html>", echoed)
			return
		}
		fmt.Fprintf(w, "<html><body><p>PING %s</p><p>no output</p></body></html>", echoed)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestCommandInjectionFiresOnPrintedFile: the target answered with the contents
// of a file it was told to read, which is execution that has already been used as
// a read primitive.
func TestCommandInjectionFiresOnPrintedFile(t *testing.T) {
	server := outputSite(t)
	h := newHarness(t)
	findings := withParameter(t, h, commandInjection{}, server.URL+"/ping?ip=127.0.0.1")
	if len(findings) == 0 {
		t.Fatal("a target that printed a file it was asked to read was not reported")
	}
	f := findings[0]
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "root:x:0:0") {
		t.Errorf("the evidence does not quote the file: %v", f.Evidence.Matches)
	}
	if len(f.Evidence.Request) == 0 || len(f.Evidence.Response) == 0 {
		t.Error("evidence is incomplete")
	}
}

// TestCommandInjectionStaysQuietWhenNothingPrints: a page that echoes the request
// is not a page that ran a command. Every seed is echoed here, including the ones
// that would print a file on a target that executes.
func TestCommandInjectionStaysQuietWhenNothingPrints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>PING %s</p></body></html>",
			strings.ReplaceAll(r.URL.Query().Get("ip"), "<", "&lt;"))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, commandInjection{}, server.URL+"/ping?ip=127.0.0.1"); len(findings) != 0 {
		t.Errorf("a page that only echoed its input was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCommandInjectionPathFiresOnARouteThatRunsTheSegment: the name in the path is handed to a
// shell, and the file the command was asked to read comes back.
func TestCommandInjectionPathFiresOnARouteThatRunsTheSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The whole path: the payload carries slashes of its own, so taking the last segment
		// would see only the tail of the command.
		segment := strings.Trim(r.URL.Path, "/")
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(segment, "cat /etc/passwd") {
			fmt.Fprint(w, "localhost\nroot:x:0:0:root:/root:/usr/bin/zsh\ndaemon:x:1:1:daemon:/usr/sbin\n")
			return
		}
		fmt.Fprint(w, "localhost\n")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/tool/localhost?host=localhost")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	findings := runRequestLevel(t, h, commandInjection{}, target)
	if len(findings) == 0 {
		t.Fatal("a command run with a value from the path was not reported")
	}
	if findings[0].CWE != "CWE-78" {
		t.Errorf("CWE = %q, want CWE-78", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "path") {
		t.Errorf("payload = %q, want the payload to say where it was put", findings[0].Payload)
	}
}

// TestCommandInjectionPathStaysQuietOnARouteThatOnlyEchoesTheSegment: the segment comes back,
// and no command ran.
func TestCommandInjectionPathStaysQuietOnARouteThatOnlyEchoesTheSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "no host named %s is reachable\n", strings.Trim(r.URL.Path, "/"))
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/tool/localhost?host=localhost")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	if findings := runRequestLevel(t, h, commandInjection{}, target); len(findings) != 0 {
		t.Errorf("a route that echoed the segment was reported: %v", findings[0].Evidence.Matches)
	}
}
