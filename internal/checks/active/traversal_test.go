package active

import (
	"context"
	"fmt"
	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// procSelfOnlySite reads files only when the path goes through `/proc/self/root`
// — the shape left behind by a filter that strips `../` and refuses paths that
// begin with `/etc`. The plain seeds cannot reach the file here; the kernel's
// per-process link names neither of those things.
func procSelfOnlySite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file == "" {
			file = r.FormValue("file")
		}
		if !strings.HasPrefix(file, "/proc/self/root") {
			fmt.Fprint(w, "<html><body><p>read failed</p></body></html>")
			return
		}
		fmt.Fprint(w, "<html><body><pre>root:x:0:0:root:/root:/bin/bash\n"+
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n</pre></body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

// TestPathTraversalFiresThroughProcSelfRoot: the file is reachable, and only
// through the link a `../` filter does not cover.
func TestPathTraversalFiresThroughProcSelfRoot(t *testing.T) {
	server := procSelfOnlySite(t)
	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/view?file=index.html")
	if len(findings) == 0 {
		t.Fatal("a target reachable only through /proc/self/root was not reported")
	}
	if !strings.Contains(findings[0].Payload, "/proc/self/") {
		t.Errorf("payload = %q, want a /proc/self path", findings[0].Payload)
	}
}

// noArithmeticSite evaluates the template but refuses operators — the shape of a
// sandbox that leaves attribute access and string repetition in place. Only the
// engine-specific fingerprints reach it; `1999*1999` is refused.
func noArithmeticSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("tpl")
		if value == "" {
			value = r.FormValue("tpl")
		}
		switch {
		case strings.Contains(value, "7*'7'"):
			fmt.Fprint(w, "<html><body><p>7777777</p></body></html>")
		case strings.Contains(value, "__class__"):
			fmt.Fprint(w, "<html><body><p><class 'str'></p></body></html>")
		default:
			fmt.Fprintf(w, "<html><body><p>literal: %s</p></body></html>", value)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestSSTIFiresOnEngineSpecificFingerprints: the target evaluates the language
// but not arithmetic, so the finding comes from a fingerprint that identifies the
// engine rather than from the product.
func TestSSTIFiresOnEngineSpecificFingerprints(t *testing.T) {
	server := noArithmeticSite(t)
	h := newHarness(t)
	findings := withParameter(t, h, ssti{}, server.URL+"/render?tpl=hello")
	if len(findings) == 0 {
		t.Fatal("a target that evaluates without arithmetic was not reported")
	}
	matched := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(matched, "7777777") && !strings.Contains(matched, "<class 'str'>") {
		t.Errorf("evidence does not quote the fingerprint: %v", findings[0].Evidence.Matches)
	}
}

// TestSSTIEvidenceReadsAnEscapedPage: a framework that escapes what it renders is doing the
// safer thing, and it still evaluated the value. The signature has to be found in the
// escaped text too, or every page that escapes its output would be missed.
func TestSSTIEvidenceReadsAnEscapedPage(t *testing.T) {
	escaped := "<p>result: &lt;class &#39;str&#39;&gt;</p>"
	if got := sstiEvidence(escaped, "<p>result: hello</p>"); got != "<class 'str'>" {
		t.Errorf("sstiEvidence on an escaped page = %q, want the attribute fingerprint", got)
	}
	// The raw form still matches.
	if got := sstiEvidence("<p>result: <class 'str'></p>", "<p>result: hello</p>"); got != "<class 'str'>" {
		t.Errorf("sstiEvidence on a raw page = %q", got)
	}
	// A baseline that already carries it — in either form — is still a baseline.
	if got := sstiEvidence(escaped, escaped); got != "" {
		t.Errorf("an escaped baseline was used as evidence: %q", got)
	}
	if got := sstiEvidence(escaped, "<p>result: &lt;class &#39;str&#39;&gt;</p>"); got != "" {
		t.Errorf("an escaped baseline was used as evidence: %q", got)
	}
}

// TestSSTIPathInjectionFiresOnARouteThatRendersTheSegment: the name in the path is what the
// template is built from, and the evidence is the evaluated result rather than anything the page
// echoes.
func TestSSTIPathInjectionFiresOnARouteThatRendersTheSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A route that renders the segment, with the arithmetic the seeds ask for.
		segment := strings.Trim(r.URL.Path, "/")
		body := "<html><body><p>Hello, " + segment + "</p></body></html>"
		body = strings.ReplaceAll(body, "{{1999*1999}}", "3996001")
		body = strings.ReplaceAll(body, "{{7*'7'}}", "7777777")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/greet/world?ref=top")
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

	findings := runRequestLevel(t, h, ssti{}, target)
	if len(findings) == 0 {
		t.Fatal("a segment rendered as a template was not reported")
	}
	if findings[0].CWE != "CWE-94" {
		t.Errorf("CWE = %q, want CWE-94", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "path segment") {
		t.Errorf("payload = %q, want the payload to say where it was put", findings[0].Payload)
	}
}

// TestSSTIPathStaysQuietWhenTheSegmentIsPrintedVerbatim: the expression comes back as text, so
// nothing evaluated it. This is the line between a reflection and template injection, and it is
// why the finding quotes the result rather than the payload.
func TestSSTIPathStaysQuietWhenTheSegmentIsPrintedVerbatim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>No page named %s</p></body></html>", strings.Trim(r.URL.Path, "/"))
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/greet/world?ref=top")
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

	if findings := runRequestLevel(t, h, ssti{}, target); len(findings) != 0 {
		t.Errorf("a page that printed the expression verbatim was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestTraversalSurvivesAMiddlewareThatDecodesOnce covers the double-decoding shape: a filter
// decodes the value and looks for `../`, and the application decodes it again before reading.
// Only a traversal that is encoded twice reaches the file — the first decode leaves `%2e%2e%2f`,
// which the filter does not recognise as a path, and the second turns it back into `../`.
//
// The encoding arrives without being asked for: the transformation produces `%2e%2e%2f` as the
// payload's text, and the transport encodes that again on the wire. Asserting it here keeps a
// future change to either half from quietly removing the only shape that gets through.
func TestTraversalSurvivesAMiddlewareThatDecodesOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("file")
		// The filter: what the framework handed the application, checked for a path.
		if strings.Contains(value, "../") || strings.Contains(value, "..\\") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<p>blocked by middleware</p>")
			return
		}
		// The application decodes again, and only then reads.
		decoded, err := url.QueryUnescape(value)
		if err != nil || !strings.HasPrefix(decoded, "../") {
			fmt.Fprint(w, "<p>cannot read</p>")
			return
		}
		if !strings.Contains(decoded, "etc/passwd") {
			fmt.Fprint(w, "<p>cannot read</p>")
			return
		}
		fmt.Fprint(w, "<pre>root:x:0:0:root:/root:/usr/bin/zsh</pre>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/?file=readme.txt")
	if len(findings) == 0 {
		t.Fatal("a traversal that only a second decode reveals was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "root:x:0:0") {
		t.Errorf("the evidence does not quote the file: %v", findings[0].Evidence.Matches)
	}
}

// TestSSTIExecutionFiresWhenTheTemplateRunsACommand: the arithmetic proves the engine evaluated
// something; this proves what it can reach. The target called back, which is code execution.
func TestSSTIExecutionFiresWhenTheTemplateRunsACommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>result: hello</body></html>")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/?tpl=hello")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()

	h.ctx.OOB = &stubOOB{shape: "http://192.0.2.9:8099/{token}", responds: true}
	findings := runRequestLevel(t, h, ssti{}, &checks.Target{Request: request, Response: response, Param: &params[0]})
	if len(findings) == 0 {
		t.Fatal("a template that ran a command was not reported")
	}
	if findings[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical once the command reached back", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Payload, "popen") && !strings.Contains(findings[0].Payload, "curl") {
		t.Errorf("payload = %q, want the chain that runs a command", findings[0].Payload)
	}
}

// TestSSTIExecutionStaysQuietWithoutAnInteractionServer: nothing is sent when there is no service
// to call back to, and the arithmetic still answers.
func TestSSTIExecutionStaysQuietWithoutAnInteractionServer(t *testing.T) {
	var sent []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>result: hello</body></html>")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/?tpl=hello")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	if h.ctx.OOB != nil {
		t.Fatal("this test is about the case with no interaction server")
	}

	runRequestLevel(t, h, ssti{}, &checks.Target{Request: request, Response: response, Param: &params[0]})
	// The seeds that print a command's output are still sent — they need no server — but nothing
	// carrying a callback address may be, because there is no address to carry.
	for _, query := range sent {
		if strings.Contains(query, "192.0.2.9") || strings.Contains(query, "8099") {
			t.Errorf("a chain carrying a callback was sent with no server to answer it: %s", query)
		}
	}
}
