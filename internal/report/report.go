// Package report turns findings into something a human can act on.
//
// Four formats share one model: a self-contained HTML report for reading and
// sharing, JSON for tooling, SARIF for code-scanning pipelines, and Markdown
// for pasting into an issue. All of them render their text through the message
// catalogue, so a report generated in Chinese reads as Chinese throughout.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/version"
)

// Data is everything a report needs.
type Data struct {
	// Target is what the scan was pointed at, as the user named it.
	Target string
	// Bundle renders every label and sentence in the report.
	Bundle *i18n.Bundle
	// Started and Finished bracket the run.
	Started  time.Time
	Finished time.Time
	// Hosts, Endpoints and Requests describe the scope that was covered.
	Hosts     []string
	Endpoints int
	Requests  int
	// Findings are the deduplicated results, already sorted.
	Findings []*finding.Finding
}

// Duration is the scan's wall-clock time.
func (d *Data) Duration() time.Duration {
	if d.Started.IsZero() || d.Finished.IsZero() {
		return 0
	}
	return d.Finished.Sub(d.Started)
}

// Counts tallies findings per severity.
func (d *Data) Counts() map[finding.Severity]int {
	return finding.CountBySeverity(d.Findings)
}

// Write renders a report to path. The format follows the file extension:
// .html, .json, .sarif, .md/.markdown. Anything else is an error rather than a
// guess, so a typo cannot silently produce the wrong artefact.
func Write(path string, data *Data) error {
	format := FormatFromPath(path)
	if format == "" {
		return fmt.Errorf("report: cannot tell the format of %q; use .html, .json, .sarif or .md", path)
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("report: create %s: %w", dir, err)
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("report: create %s: %w", path, err)
	}
	defer file.Close()

	if err := Render(file, format, data); err != nil {
		return err
	}
	return file.Sync()
}

// FormatFromPath infers a report format from a file extension.
func FormatFromPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
		return "html"
	case ".json":
		return "json"
	case ".sarif":
		return "sarif"
	case ".md", ".markdown":
		return "markdown"
	default:
		return ""
	}
}

// Formats lists the supported report formats.
func Formats() []string { return []string{"html", "json", "sarif", "markdown"} }

// Render writes a report in the named format.
//
// The output is forced to valid UTF-8. Evidence carries bytes taken verbatim
// from responses, and a response may contain anything — a truncated multi-byte
// sequence, a Latin-1 page, a binary body. Emitting those unchanged produces a
// file that a strict reader rejects outright, which turns a report about
// several findings into no report at all. Invalid sequences become U+FFFD, which
// costs nothing: the evidence is still readable, and the whole file stays
// parseable.
func Render(w io.Writer, format string, data *Data) error {
	var buf bytes.Buffer
	if err := renderTo(&buf, format, data); err != nil {
		return err
	}
	if utf8.Valid(buf.Bytes()) {
		_, err := buf.WriteTo(w)
		return err
	}
	_, err := io.WriteString(w, strings.ToValidUTF8(buf.String(), "�"))
	return err
}

// renderTo writes a report in the named format without the UTF-8 guarantee.
func renderTo(w io.Writer, format string, data *Data) error {
	switch format {
	case "html", "":
		return HTML(w, data)
	case "json":
		return JSON(w, data)
	case "sarif":
		return SARIF(w, data)
	case "markdown", "md":
		return Markdown(w, data)
	default:
		return fmt.Errorf("report: unknown format %q", format)
	}
}

// titleText renders a finding's title, preferring literal text over a
// catalogue key so that template-supplied findings read as their author wrote
// them.
func titleText(bundle *i18n.Bundle, f *finding.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return bundle.T(f.TitleKey)
}

// descriptionText renders a finding's description.
func descriptionText(bundle *i18n.Bundle, f *finding.Finding) string {
	if f.Description != "" {
		return f.Description
	}
	return bundle.T(f.DescriptionKey)
}

// remediationText renders a finding's remediation advice.
func remediationText(bundle *i18n.Bundle, f *finding.Finding) string {
	if f.Remediation != "" {
		return f.Remediation
	}
	return bundle.T(f.RemediationKey)
}

// severityLabel renders a severity in the user's language.
func severityLabel(bundle *i18n.Bundle, s finding.Severity) string {
	return bundle.T(severityKey(s))
}

// severityKey maps a severity to its catalogue key.
func severityKey(s finding.Severity) i18n.Key {
	switch s {
	case finding.SeverityCritical:
		return i18n.KeySeverityCritical
	case finding.SeverityHigh:
		return i18n.KeySeverityHigh
	case finding.SeverityMedium:
		return i18n.KeySeverityMedium
	case finding.SeverityLow:
		return i18n.KeySeverityLow
	case finding.SeverityInfo:
		return i18n.KeySeverityInfo
	default:
		return i18n.KeySeverityUnknown
	}
}

// confidenceLabel renders a confidence in the user's language.
func confidenceLabel(bundle *i18n.Bundle, c finding.Confidence) string {
	return bundle.T(confidenceKey(c))
}

// confidenceKey maps a confidence to its catalogue key.
func confidenceKey(c finding.Confidence) i18n.Key {
	switch c {
	case finding.ConfidenceCertain:
		return i18n.KeyConfidenceCertain
	case finding.ConfidenceFirm:
		return i18n.KeyConfidenceFirm
	default:
		return i18n.KeyConfidenceTentative
	}
}

// severityOrder is the display order of severity buckets, worst first.
var severityOrder = []finding.Severity{
	finding.SeverityCritical,
	finding.SeverityHigh,
	finding.SeverityMedium,
	finding.SeverityLow,
	finding.SeverityInfo,
}

// curlCommand renders a raw request as a curl command, so a reader can replay a
// finding without reconstructing it by hand.
func curlCommand(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	req, err := httpmsg.ParseRequest(raw, httpmsg.ParseOptions{})
	if err != nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("curl -i -sS -X ")
	b.WriteString(shellQuoteIfNeeded(req.Method))
	b.WriteByte(' ')
	b.WriteString(shellQuoteIfNeeded(req.URLString()))
	for _, field := range req.Header.All() {
		switch strings.ToLower(field.Name) {
		case "host", "content-length":
			continue
		}
		fmt.Fprintf(&b, " \\\n  -H %s", shellQuoteIfNeeded(field.Name+": "+field.Value))
	}
	if len(req.Body) > 0 {
		b.WriteString(" \\\n  --data-binary ")
		b.WriteString(shellQuoteIfNeeded(string(req.Body)))
	}
	return b.String()
}

// shellQuoteIfNeeded quotes a value for a POSIX shell when it contains anything
// that would otherwise be interpreted.
func shellQuoteIfNeeded(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\"'\\$`&|;<>()*?[]{}!#~=") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// --- JSON ---------------------------------------------------------------

// jsonReport is the JSON report shape. It is written out with stable field
// names and no nesting that a consumer would have to guess at.
type jsonReport struct {
	Tool      string        `json:"tool"`
	Version   string        `json:"version"`
	Authors   string        `json:"authors"`
	Target    string        `json:"target"`
	Started   string        `json:"started"`
	Finished  string        `json:"finished"`
	Duration  string        `json:"duration"`
	Hosts     []string      `json:"hosts,omitempty"`
	Endpoints int           `json:"endpoints"`
	Requests  int           `json:"requests"`
	Summary   jsonSummary   `json:"summary"`
	Findings  []jsonFinding `json:"findings"`
}

// jsonSummary is the per-severity tally.
type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// jsonFinding is one finding in JSON form.
type jsonFinding struct {
	ID          string   `json:"id"`
	Check       string   `json:"check"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter,omitempty"`
	Payload     string   `json:"payload,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	TemplateID  string   `json:"template_id,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
	Evidence    struct {
		Matches  []string `json:"matches,omitempty"`
		Diff     string   `json:"diff,omitempty"`
		Duration string   `json:"duration,omitempty"`
		Request  string   `json:"request,omitempty"`
		Response string   `json:"response,omitempty"`
		Baseline string   `json:"baseline,omitempty"`
	} `json:"evidence"`
	Curl string `json:"curl,omitempty"`
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, data *Data) error {
	counts := data.Counts()
	out := jsonReport{
		Tool:      version.Name,
		Version:   version.Version,
		Authors:   version.Authors,
		Target:    data.Target,
		Started:   formatTime(data.Started),
		Finished:  formatTime(data.Finished),
		Duration:  data.Duration().Round(time.Millisecond).String(),
		Hosts:     data.Hosts,
		Endpoints: data.Endpoints,
		Requests:  data.Requests,
		Summary: jsonSummary{
			Total:    len(data.Findings),
			Critical: counts[finding.SeverityCritical],
			High:     counts[finding.SeverityHigh],
			Medium:   counts[finding.SeverityMedium],
			Low:      counts[finding.SeverityLow],
			Info:     counts[finding.SeverityInfo],
		},
		Findings: make([]jsonFinding, 0, len(data.Findings)),
	}

	for _, f := range data.Findings {
		out.Findings = append(out.Findings, jsonFindingFor(data.Bundle, f))
	}

	return newJSONEncoder(w).Encode(out)
}

// jsonFindingFor converts a finding into its wire form.
func jsonFindingFor(bundle *i18n.Bundle, f *finding.Finding) jsonFinding {
	method, url := f.Method, f.URL
	if method == "" {
		if req, err := httpmsg.ParseRequest(f.Evidence.Request, httpmsg.ParseOptions{}); err == nil {
			method, url = req.Method, req.URLString()
		}
	}

	out := jsonFinding{
		ID:          f.ID,
		Check:       f.CheckID,
		Title:       titleText(bundle, f),
		Severity:    string(f.Severity),
		Confidence:  string(f.Confidence),
		Method:      method,
		URL:         url,
		Parameter:   f.Param,
		Payload:     f.Payload,
		CWE:         f.CWE,
		TemplateID:  f.TemplateID,
		Tags:        f.Tags,
		Description: descriptionText(bundle, f),
		Remediation: remediationText(bundle, f),
		References:  f.References,
		Curl:        curlCommand(f.Evidence.Request),
	}
	out.Evidence.Matches = f.Evidence.Matches
	out.Evidence.Diff = f.Evidence.Diff
	if f.Evidence.Duration > 0 {
		out.Evidence.Duration = f.Evidence.Duration.Round(time.Millisecond).String()
	}
	out.Evidence.Request = string(f.Evidence.Request)
	out.Evidence.Response = string(f.Evidence.Response)
	out.Evidence.Baseline = string(f.Evidence.Baseline)
	return out
}

// formatTime renders a timestamp in a stable, UTC, machine-readable form.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// newJSONEncoder returns an encoder configured for readable, unescaped JSON.
// HTML escaping is off so that a payload containing < or & stays legible.
func newJSONEncoder(w io.Writer) *json.Encoder {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder
}
