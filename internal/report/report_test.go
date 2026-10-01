package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"unicode/utf8"
)

// sampleData builds a report with one finding, in the given language.
func sampleData(t *testing.T, lang i18n.Lang) *Data {
	t.Helper()

	request, err := httpmsg.NewRequest("GET", "https://example.com/item?id=1'")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Accept", "*/*")

	f := &finding.Finding{
		ID:             "abc123",
		CheckID:        "sqli-error",
		TitleKey:       i18n.KeyCheckSQLiErrorTitle,
		DescriptionKey: i18n.KeyCheckSQLiErrorDesc,
		RemediationKey: i18n.KeyCheckSQLiErrorFix,
		Severity:       finding.SeverityCritical,
		Confidence:     finding.ConfidenceCertain,
		Method:         "GET",
		URL:            "https://example.com/item?id=1'",
		Param:          "query:id",
		Payload:        "'",
		CWE:            "CWE-89",
		Tags:           []string{"active", "sqli"},
		References:     []string{"https://cwe.mitre.org/data/definitions/89.html"},
		FoundAt:        time.Now(),
		Evidence: finding.Evidence{
			Request:  request.Raw(),
			Response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nYou have an error in your SQL syntax"),
			Baseline: []byte("HTTP/1.1 200 OK\r\n\r\nArticle 1"),
			Matches:  []string{"you have an error in your sql syntax"},
			Diff:     "content changed",
		},
	}

	started := time.Now().Add(-2 * time.Minute)
	return &Data{
		Target:    "https://example.com/item?id=1'",
		Bundle:    i18n.New(lang),
		Started:   started,
		Finished:  started.Add(90 * time.Second),
		Hosts:     []string{"example.com"},
		Endpoints: 3,
		Requests:  42,
		Findings:  []*finding.Finding{f},
	}
}

func TestHTMLReport(t *testing.T) {
	data := sampleData(t, i18n.EN)

	var buf bytes.Buffer
	if err := HTML(&buf, data); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	html := buf.String()

	for _, want := range []string{
		"<!doctype html>",
		"SQL injection",
		"example.com",
		"CWE-89",
		"query:id",
		"curl",
		"<style>",
		"data-search=",
		"sev-critical",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report is missing %q", want)
		}
	}
	// The report must be self-contained: no external references to fetch.
	if strings.Contains(html, "<script src=") || strings.Contains(html, "<link rel=\"stylesheet\"") {
		t.Error("HTML report pulls in external assets; it should be a single file")
	}
}

func TestHTMLReportLocalises(t *testing.T) {
	data := sampleData(t, i18n.ZH)

	var buf bytes.Buffer
	if err := HTML(&buf, data); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	html := buf.String()

	for _, want := range []string{"crackweb 漏洞报告", "SQL 注入", "修复建议", "严重"} {
		if !strings.Contains(html, want) {
			t.Errorf("Chinese HTML report is missing %q", want)
		}
	}
	if strings.Contains(html, "Remediation") {
		t.Error("Chinese report still shows English section headings")
	}
}

func TestHTMLReportWithNoFindings(t *testing.T) {
	data := sampleData(t, i18n.EN)
	data.Findings = nil

	var buf bytes.Buffer
	if err := HTML(&buf, data); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(buf.String(), "No vulnerabilities were identified") {
		t.Error("empty report does not say so")
	}
}

func TestJSONReport(t *testing.T) {
	data := sampleData(t, i18n.EN)

	var buf bytes.Buffer
	if err := JSON(&buf, data); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var decoded struct {
		Tool      string `json:"tool"`
		Version   string `json:"version"`
		Target    string `json:"target"`
		Endpoints int    `json:"endpoints"`
		Requests  int    `json:"requests"`
		Summary   struct {
			Total    int `json:"total"`
			Critical int `json:"critical"`
		} `json:"summary"`
		Findings []struct {
			ID         string `json:"id"`
			Check      string `json:"check"`
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			CWE        string `json:"cwe"`
			Curl       string `json:"curl"`
			Evidence   struct {
				Request string   `json:"request"`
				Matches []string `json:"matches"`
			} `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if decoded.Tool != "crackweb" {
		t.Errorf("tool = %q", decoded.Tool)
	}
	if decoded.Endpoints != 3 || decoded.Requests != 42 {
		t.Errorf("counters = %d/%d, want 3/42", decoded.Endpoints, decoded.Requests)
	}
	if decoded.Summary.Total != 1 || decoded.Summary.Critical != 1 {
		t.Errorf("summary = %+v", decoded.Summary)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(decoded.Findings))
	}

	f := decoded.Findings[0]
	if f.Check != "sqli-error" || f.Severity != "critical" || f.Confidence != "certain" {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Curl, "curl") {
		t.Errorf("curl command missing: %q", f.Curl)
	}
	if !strings.Contains(f.Evidence.Request, "GET ") {
		t.Errorf("evidence request missing: %q", f.Evidence.Request)
	}
}

func TestSARIFReport(t *testing.T) {
	data := sampleData(t, i18n.EN)

	var buf bytes.Buffer
	if err := SARIF(&buf, data); err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	var decoded struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid SARIF: %v", err)
	}

	if decoded.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", decoded.Version)
	}
	if !strings.Contains(decoded.Schema, "sarif") {
		t.Errorf("schema = %q", decoded.Schema)
	}
	if len(decoded.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(decoded.Runs))
	}

	run := decoded.Runs[0]
	if run.Tool.Driver.Name != "crackweb" {
		t.Errorf("driver = %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "sqli-error" {
		t.Errorf("rules = %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(run.Results))
	}
	// A critical finding must be an error, so a pipeline can gate on it.
	if run.Results[0].Level != "error" {
		t.Errorf("level = %q, want error", run.Results[0].Level)
	}
	if len(run.Results[0].Locations) != 1 {
		t.Error("no location: a code-scanning UI needs one")
	}
}

func TestMarkdownReport(t *testing.T) {
	data := sampleData(t, i18n.EN)

	var buf bytes.Buffer
	if err := Markdown(&buf, data); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	text := buf.String()

	for _, want := range []string{"# crackweb", "## 1.", "sqli-error", "1m 30s", "```"} {
		if !strings.Contains(text, want) {
			t.Errorf("Markdown report is missing %q", want)
		}
	}
}

func TestFormatFromPath(t *testing.T) {
	cases := map[string]string{
		"report.html":    "html",
		"report.HTM":     "html",
		"out.json":       "json",
		"out.sarif":      "sarif",
		"notes.md":       "markdown",
		"notes.markdown": "markdown",
		"report":         "",
		"report.txt":     "",
	}
	for path, want := range cases {
		if got := FormatFromPath(path); got != want {
			t.Errorf("FormatFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestWriteRejectsUnknownExtension(t *testing.T) {
	data := sampleData(t, i18n.EN)
	err := Write(t.TempDir()+"/report.txt", data)
	if err == nil {
		t.Fatal("an unguessable extension was accepted")
	}
	if !strings.Contains(err.Error(), ".html") {
		t.Errorf("error does not say what is supported: %v", err)
	}
}

func TestWriteProducesEveryFormat(t *testing.T) {
	data := sampleData(t, i18n.EN)
	dir := t.TempDir()

	for _, name := range []string{"r.html", "r.json", "r.sarif", "r.md"} {
		path := dir + "/" + name
		if err := Write(path, data); err != nil {
			t.Errorf("Write(%s): %v", name, err)
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if len(content) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

// TestCurlCommandIsRunnable checks the reproduction command is plausible shell,
// not just a string that mentions curl.
func TestCurlCommandIsRunnable(t *testing.T) {
	raw := []byte("POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=1'")
	command := curlCommand(raw)

	for _, want := range []string{"curl", "-X POST", "http://example.com/login", "--data-binary", "user=admin"} {
		if !strings.Contains(command, want) {
			t.Errorf("curl command is missing %q:\n%s", want, command)
		}
	}
	// Host and Content-Length are set by curl itself.
	if strings.Contains(command, "-H 'Host:") || strings.Contains(command, "Content-Length") {
		t.Errorf("curl command duplicates headers curl manages:\n%s", command)
	}
}

// TestRenderProducesValidUTF8: evidence is taken verbatim from responses, so it
// can carry any byte sequence. A report that is not valid UTF-8 cannot be read
// at all by a strict parser, which loses every finding in it — so the bytes are
// cleaned at the boundary rather than trusted.
func TestRenderProducesValidUTF8(t *testing.T) {
	// 0xff 0xfe are never valid UTF-8; the rest is a normal page.
	binary := append([]byte("<html><body>\xff\xfe\x00data</body></html>"), 0xff, 0xfe, 0x80)

	data := &Data{
		Bundle: i18n.New(i18n.EN),
		Findings: []*finding.Finding{{
			Title:    "binary evidence",
			Severity: finding.SeverityHigh,
			URL:      "http://example.com/x?id=1",
			Evidence: finding.Evidence{Response: binary, Baseline: binary, Request: binary},
		}},
	}

	for _, format := range Formats() {
		var buf bytes.Buffer
		if err := Render(&buf, format, data); err != nil {
			t.Fatalf("Render(%s): %v", format, err)
		}
		if !utf8.Valid(buf.Bytes()) {
			t.Errorf("Render(%s) produced invalid UTF-8", format)
		}
	}
}

// TestReportPutsTheBoundaryBeforeTheNumbers pins where the coverage boundary belongs.
//
// A scan that was cut short — requests never answered, something answering in the application's
// place — says how much the counts below it can be trusted, so it has to be read first. It used
// to sit among the metadata (start time, duration, request count) in the HTML report, which is
// where a reader looks last.
func TestReportPutsTheBoundaryBeforeTheNumbers(t *testing.T) {
	data := sampleData(t, i18n.EN)
	data.Boundary = Boundary{Unanswered: 7}

	var buf bytes.Buffer
	if err := HTML(&buf, data); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	html := buf.String()

	alert := strings.Index(html, "boundary-alert")
	cards := strings.Index(html, `class="cards"`)
	if alert < 0 {
		t.Fatal("the boundary was not rendered at all")
	}
	if cards < 0 || alert > cards {
		t.Errorf("the boundary is not ahead of the summary numbers (boundary@%d cards@%d)", alert, cards)
	}
	if !strings.Contains(html, "7") {
		t.Error("the boundary lost the count it was given")
	}

	// The text report puts it before the findings, and before the "nothing found" line, for the
	// same reason.
	var mdBuf bytes.Buffer
	if err := Markdown(&mdBuf, data); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	text := mdBuf.String()
	boundaryAt := strings.Index(text, "Coverage boundary")
	firstFinding := strings.Index(text, "## 1.")
	if boundaryAt < 0 {
		t.Fatal("the markdown report dropped the boundary")
	}
	if firstFinding >= 0 && boundaryAt > firstFinding {
		t.Errorf("the markdown boundary is after the findings (boundary@%d findings@%d)", boundaryAt, firstFinding)
	}
}
