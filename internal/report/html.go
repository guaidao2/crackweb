package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/version"
)

//go:embed template.html
var htmlTemplateSource string

// htmlTemplate is parsed once at start-up. A parse failure is a build-time
// mistake, so panicking here is the honest outcome.
var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateSource))

// htmlView is the fully rendered view model. Nothing in the template needs to
// know about findings, bundles or time formatting.
type htmlView struct {
	Lang      string
	Title     string
	Subtitle  string
	ToolLine  string
	Target    string
	Started   string
	Finished  string
	Duration  string
	Hosts     string
	Endpoints int
	Requests  int
	Total     int
	MaxCount  int
	// Boundary holds the sentences about what stood between the scan and the target.
	Boundary []string
	Cards    []severityCard
	Findings []findingCard
	Labels   htmlLabels
}

// severityCard is one bucket in the summary strip.
type severityCard struct {
	Key   string
	Label string
	Count int
	Class string
	// Percent is the bar width, so the strip reads as a chart.
	Percent int
}

// findingCard is one finding, pre-rendered for the template.
type findingCard struct {
	Index      int
	Title      string
	Check      string
	CheckID    string
	Severity   string
	SevClass   string
	Confidence string
	Method     string
	URL        string
	Param      string
	Payload    string
	CWE        string
	Tags       string
	Template   string
	Descr      string
	Fix        string
	Refs       []string
	Matches    []string
	Diff       string
	Request    string
	Response   string
	Baseline   string
	HasBase    bool
	Curl       string
	// Search is the lower-cased blob the client-side filter matches against.
	Search string
}

// htmlLabels holds every UI string, so the template stays free of catalogue
// lookups.
type htmlLabels struct {
	Summary     string
	Target      string
	Started     string
	Finished    string
	Duration    string
	Hosts       string
	Endpoints   string
	Requests    string
	Boundary    string
	Findings    string
	NoFindings  string
	Filter      string
	ExpandAll   string
	CollapseAll string
	Disclaimer  string
	Check       string
	Severity    string
	Confidence  string
	URL         string
	Parameter   string
	Payload     string
	Description string
	Remediation string
	References  string
	Request     string
	Response    string
	Baseline    string
	Evidence    string
	Difference  string
	CWE         string
	Curl        string
}

// HTML renders the self-contained HTML report.
func HTML(w io.Writer, data *Data) error {
	return htmlTemplate.Execute(w, buildHTMLView(data))
}

// buildHTMLView turns findings and metadata into the template's model.
func buildHTMLView(data *Data) *htmlView {
	bundle := data.Bundle
	if bundle == nil {
		bundle = i18n.New(i18n.Default)
	}
	counts := data.Counts()

	view := &htmlView{
		Lang:      string(bundle.Lang()),
		Title:     bundle.T(i18n.KeyReportTitle),
		Subtitle:  bundle.T(i18n.KeyReportSubtitle),
		ToolLine:  version.Full(),
		Target:    data.Target,
		Started:   humanTime(data.Started),
		Finished:  humanTime(data.Finished),
		Duration:  humanDuration(data.Duration()),
		Hosts:     strings.Join(data.Hosts, ", "),
		Endpoints: data.Endpoints,
		Requests:  data.Requests,
		Total:     len(data.Findings),
		Boundary:  boundaryLines(bundle, data.Boundary),
		Labels: htmlLabels{
			Summary:     bundle.T(i18n.KeyReportSummary),
			Boundary:    bundle.T(i18n.KeyReportBoundaryTitle),
			Target:      bundle.T(i18n.KeyReportTarget),
			Started:     bundle.T(i18n.KeyReportStarted),
			Finished:    bundle.T(i18n.KeyReportFinished),
			Duration:    bundle.T(i18n.KeyReportDuration),
			Hosts:       bundle.T(i18n.KeyReportHosts),
			Endpoints:   bundle.T(i18n.KeyReportEndpoints),
			Requests:    bundle.T(i18n.KeyReportRequests),
			Findings:    bundle.T(i18n.KeyReportFindings),
			NoFindings:  bundle.T(i18n.KeyReportNoFindings),
			Filter:      bundle.T(i18n.KeyReportFilter),
			ExpandAll:   bundle.T(i18n.KeyReportExpandAll),
			CollapseAll: bundle.T(i18n.KeyReportCollapseAll),
			Disclaimer:  bundle.T(i18n.KeyAppDisclaimer),
			Check:       bundle.T(i18n.KeyReportFieldCheck),
			Severity:    bundle.T(i18n.KeyReportFieldSeverity),
			Confidence:  bundle.T(i18n.KeyReportFieldConfidence),
			URL:         bundle.T(i18n.KeyReportFieldURL),
			Parameter:   bundle.T(i18n.KeyReportFieldParam),
			Payload:     bundle.T(i18n.KeyReportFieldPayload),
			Description: bundle.T(i18n.KeyReportFieldDescription),
			Remediation: bundle.T(i18n.KeyReportFieldRemediation),
			References:  bundle.T(i18n.KeyReportFieldReferences),
			Request:     bundle.T(i18n.KeyReportFieldRequest),
			Response:    bundle.T(i18n.KeyReportFieldResponse),
			Baseline:    bundle.T(i18n.KeyReportFieldBaseline),
			Evidence:    bundle.T(i18n.KeyReportFieldEvidence),
			Difference:  bundle.T(i18n.KeyReportFieldDiff),
			CWE:         bundle.T(i18n.KeyReportCWE),
			Curl:        bundle.T(i18n.KeyReportCurl),
		},
	}

	// Severity cards, with bars scaled against the largest bucket so the strip
	// reads as a chart rather than a list.
	worst := 0
	for _, severity := range severityOrder {
		if counts[severity] > worst {
			worst = counts[severity]
		}
	}
	view.MaxCount = worst
	for _, severity := range severityOrder {
		count := counts[severity]
		percent := 0
		if worst > 0 {
			percent = count * 100 / worst
		}
		view.Cards = append(view.Cards, severityCard{
			Key:     string(severity),
			Label:   severityLabel(bundle, severity),
			Count:   count,
			Class:   severityClass(severity),
			Percent: percent,
		})
	}

	for i, f := range data.Findings {
		view.Findings = append(view.Findings, buildFindingCard(bundle, f, i+1))
	}
	return view
}

// buildFindingCard pre-renders one finding.
func buildFindingCard(bundle *i18n.Bundle, f *finding.Finding, index int) findingCard {
	method, url := f.Method, f.URL
	if method == "" {
		method = "GET"
	}
	if url == "" {
		url = "(unknown)"
	}

	card := findingCard{
		Index:      index,
		Title:      titleText(bundle, f),
		Check:      f.CheckID,
		CheckID:    f.CheckID,
		Severity:   severityLabel(bundle, f.Severity),
		SevClass:   severityClass(f.Severity),
		Confidence: confidenceLabel(bundle, f.Confidence),
		Method:     method,
		URL:        url,
		Param:      f.Param,
		Payload:    f.Payload,
		CWE:        f.CWE,
		Tags:       strings.Join(f.Tags, ", "),
		Template:   f.TemplateID,
		Descr:      descriptionText(bundle, f),
		Fix:        remediationText(bundle, f),
		Refs:       f.References,
		Matches:    f.Evidence.Matches,
		Diff:       f.Evidence.Diff,
		Request:    string(f.Evidence.Request),
		Response:   string(f.Evidence.Response),
		Baseline:   string(f.Evidence.Baseline),
		HasBase:    len(f.Evidence.Baseline) > 0,
		Curl:       curlCommand(f.Evidence.Request),
	}
	if f.Evidence.ResponseTruncated {
		card.Response += "\n\n[truncated]"
	}

	// The search blob lets the filter box match on anything a reader might
	// remember, without shipping the findings twice.
	card.Search = strings.ToLower(strings.Join([]string{
		card.Title, card.CheckID, card.Severity, card.Method, card.URL,
		card.Param, card.Payload, card.CWE, card.Tags, card.Descr,
	}, " "))
	return card
}

// severityClass maps a severity to its CSS class name.
func severityClass(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "sev-critical"
	case finding.SeverityHigh:
		return "sev-high"
	case finding.SeverityMedium:
		return "sev-medium"
	case finding.SeverityLow:
		return "sev-low"
	case finding.SeverityInfo:
		return "sev-info"
	default:
		return "sev-unknown"
	}
}

// humanTime renders a timestamp for reading.
func humanTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// humanDuration renders a duration compactly.
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	d = d.Round(time.Second)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	switch {
	case hours > 0:
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
