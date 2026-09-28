package template

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

const sampleTemplate = `
id: lab-error-sqli

info:
  name: Lab error-based SQL injection
  author:
    - crackweb
    - tester
  severity: critical
  description: The parameter reaches a SQL statement unparameterised.
  reference: https://owasp.org/www-community/attacks/SQL_Injection
  tags: sqli,lab,injection
  classification:
    cwe-id: CWE-89
    cve-id: CVE-2024-0001

http:
  - method: GET
    path:
      - "{{RootURL}}/?id=1'"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "You have an error in your SQL syntax"
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - "len(body) > 10"
`

func TestParseTemplate(t *testing.T) {
	tmpl, err := Parse([]byte(sampleTemplate))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if tmpl.ID != "lab-error-sqli" {
		t.Errorf("ID = %q", tmpl.ID)
	}
	if tmpl.Info.Name != "Lab error-based SQL injection" {
		t.Errorf("Name = %q", tmpl.Info.Name)
	}
	// A comma-separated scalar and a real sequence must both decode.
	if len(tmpl.Info.Tags) != 3 || tmpl.Info.Tags[0] != "sqli" {
		t.Errorf("Tags = %v, want three entries from a scalar", tmpl.Info.Tags)
	}
	if len(tmpl.Info.Author) != 2 {
		t.Errorf("Author = %v, want two entries from a sequence", tmpl.Info.Author)
	}
	if len(tmpl.Info.Reference) != 1 {
		t.Errorf("Reference = %v, want one entry from a scalar", tmpl.Info.Reference)
	}
	if tmpl.Severity() != "critical" {
		t.Errorf("Severity() = %q", tmpl.Severity())
	}
	if tmpl.Info.Classification.CWEID[0] != "CWE-89" {
		t.Errorf("CWE = %v", tmpl.Info.Classification.CWEID)
	}

	requests := tmpl.Requests_()
	if len(requests) != 1 || len(requests[0].Matchers) != 3 {
		t.Fatalf("requests = %d, matchers = %d", len(requests), len(requests[0].Matchers))
	}
	if reasons := tmpl.Unsupported(); len(reasons) != 0 {
		t.Errorf("Unsupported() = %v, want none", reasons)
	}
}

func TestParseRejectsIncompleteTemplates(t *testing.T) {
	if _, err := Parse([]byte("info:\n  name: no id\n")); err == nil {
		t.Error("template without an id was accepted")
	}
	if _, err := Parse([]byte("id: no-requests\ninfo:\n  name: x\n")); err == nil {
		t.Error("template without requests was accepted")
	}
}

func TestUnsupportedFeaturesAreReported(t *testing.T) {
	source := `
id: uses-flow
info:
  name: x
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: xpath
        xpath: ["//div"]
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reasons := tmpl.Unsupported()
	if len(reasons) == 0 {
		t.Fatal("xpath matcher was not reported as unsupported")
	}
	if !strings.Contains(strings.Join(reasons, " "), "xpath") {
		t.Errorf("reasons = %v, want xpath mentioned", reasons)
	}
}

func TestBuiltinVariables(t *testing.T) {
	req, err := httpmsg.NewRequest("GET", "https://example.com:8443/app/page.php?a=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	vars := BuiltinVariables(req.URL)

	cases := map[string]string{
		"BaseURL":  "https://example.com:8443/app/page.php?a=1",
		"RootURL":  "https://example.com:8443",
		"Hostname": "example.com:8443",
		"Host":     "example.com",
		"Port":     "8443",
		"Scheme":   "https",
		"Path":     "/app",
		"File":     "page.php",
	}
	for name, want := range cases {
		if got := vars[name].String(); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestBuiltinVariablesDefaultPorts(t *testing.T) {
	req, _ := httpmsg.NewRequest("GET", "https://example.com/")
	vars := BuiltinVariables(req.URL)
	if got := vars["Hostname"].String(); got != "example.com:443" {
		t.Errorf("Hostname = %q, want example.com:443", got)
	}
	if got := vars["Port"].String(); got != "443" {
		t.Errorf("Port = %q, want 443", got)
	}
}

func TestExpand(t *testing.T) {
	vars := map[string]Value{
		"Host":  StringValue("example.com"),
		"Port":  NumberValue(8443),
		"Empty": StringValue(""),
	}

	cases := map[string]string{
		"{{Host}}":           "example.com",
		"https://{{Host}}/x": "https://example.com/x",
		"{{ Host }}":         "example.com",
		"a{{Port}}b":         "a8443b",
		"{{Unknown}}":        "{{Unknown}}",
		"no placeholders":    "no placeholders",
		"{{Empty}}":          "",
	}
	for in, want := range cases {
		if got := Expand(in, vars); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDSLExpressions(t *testing.T) {
	vars := map[string]Value{
		"body":           StringValue("hello world, you have an error"),
		"status_code":    NumberValue(200),
		"content_length": NumberValue(32),
		"duration":       NumberValue(1.5),
	}

	cases := []struct {
		expression string
		want       bool
	}{
		{`status_code == 200`, true},
		{`status_code == 404`, false},
		{`status_code != 404`, true},
		{`status_code >= 200 && status_code < 300`, true},
		{`len(body) > 10`, true},
		{`len(body) < 10`, false},
		{`contains(body, 'error')`, true},
		{`contains(body, 'missing')`, false},
		{`contains(tolower(body), 'HELLO')`, false},
		{`contains(toupper(body), 'HELLO')`, true},
		{`starts_with(body, 'hello')`, true},
		{`ends_with(body, 'error')`, true},
		{`regex('err(or)?', body)`, true},
		{`status_code == 200 && contains(body, 'error')`, true},
		{`status_code == 500 || contains(body, 'error')`, true},
		{`!(status_code == 500)`, true},
		{`duration > 1.0`, true},
		{`content_length == 32`, true},
		{`concat('a', 'b') == 'ab'`, true},
		{`len(base64('abc')) > 0`, true},
		{`md5('abc') == '900150983cd24fb0d6963f7d28e17f72'`, true},
	}

	for _, tc := range cases {
		got, err := EvalBool(tc.expression, vars)
		if err != nil {
			t.Errorf("EvalBool(%q) errored: %v", tc.expression, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EvalBool(%q) = %v, want %v", tc.expression, got, tc.want)
		}
	}
}

func TestDSLErrorsAreReported(t *testing.T) {
	if _, err := Eval("status_code ==", nil); err == nil {
		t.Error("a truncated expression was accepted")
	}
	if _, err := Eval("unknown_func(1)", nil); err == nil {
		t.Error("an unknown function was accepted")
	}
}

func TestUnknownVariableIsEmptyNotFatal(t *testing.T) {
	// A template may reference a variable crackweb does not supply; that must
	// not abort the check.
	value, err := Eval("len(missing_variable) == 0", map[string]Value{})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !value.Truthy() {
		t.Error("unknown variable did not evaluate to empty")
	}
}

// TestRunsTemplateAgainstATarget is the end-to-end check for the engine.
func TestRunsTemplateAgainstATarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			fmt.Fprint(w, "<html><body>You have an error in your SQL syntax near '"+id+"'</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>Article "+id+"</body></html>")
	}))
	defer server.Close()

	tmpl, err := Parse([]byte(sampleTemplate))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	client, err := httpclient.New(httpclient.Options{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	runner := NewRunner(client)

	target, err := httpmsg.NewRequest("GET", server.URL+"/?id=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	findings := runner.Execute(context.Background(), tmpl, target, nil)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.TemplateID != "lab-error-sqli" {
		t.Errorf("TemplateID = %q", f.TemplateID)
	}
	if f.Title == "" || !strings.Contains(f.Title, "SQL injection") {
		t.Errorf("Title = %q", f.Title)
	}
	if string(f.Severity) != "critical" {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q", f.CWE)
	}
	if len(f.Evidence.Matches) == 0 {
		t.Error("no evidence was recorded")
	}
}

func TestTemplateThatShouldNotMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>perfectly normal page</body></html>")
	}))
	defer server.Close()

	tmpl, _ := Parse([]byte(sampleTemplate))
	client, _ := httpclient.New(httpclient.Options{})
	runner := NewRunner(client)
	target, _ := httpmsg.NewRequest("GET", server.URL+"/")

	if findings := runner.Execute(context.Background(), tmpl, target, nil); len(findings) != 0 {
		t.Errorf("matched a page that should not match: %d finding(s)", len(findings))
	}
}

func TestPayloadsMultiplyRequests(t *testing.T) {
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Query().Get("page"))
		fmt.Fprint(w, "<html>nothing here</html>")
	}))
	defer server.Close()

	source := `
id: payload-test
info:
  name: payload test
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/?page={{paths}}"
    payloads:
      paths:
        - admin
        - login
    matchers:
      - type: word
        words: ["this will not match anything"]
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	client, _ := httpclient.New(httpclient.Options{})
	runner := NewRunner(client)
	target, _ := httpmsg.NewRequest("GET", server.URL+"/")

	runner.Execute(context.Background(), tmpl, target, nil)

	joined := strings.Join(requested, ",")
	if !strings.Contains(joined, "admin") || !strings.Contains(joined, "login") {
		t.Errorf("payload values were not both used; requested %v", requested)
	}
}

func TestSeverityParsing(t *testing.T) {
	cases := map[string]string{
		"critical": "critical",
		"HIGH":     "high",
		"Medium":   "medium",
		"low":      "low",
		"info":     "info",
		"":         "unknown",
		"weird":    "unknown",
	}
	for in, want := range cases {
		tmpl := &Template{Info: Info{Severity: in}}
		if got := tmpl.Severity(); got != want {
			t.Errorf("Severity(%q) = %q, want %q", in, got, want)
		}
	}
}
