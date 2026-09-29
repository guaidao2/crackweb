package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/version"
)

// --- SARIF --------------------------------------------------------------

// sarifLog is the SARIF 2.1.0 document. The shape is fixed by the spec; the
// fields crackweb does not populate are omitted rather than sent empty.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  sarifText         `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	Partial   map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// SARIF writes the report in SARIF 2.1.0, which is what GitHub code scanning
// and most CI dashboards consume.
func SARIF(w io.Writer, data *Data) error {
	bundle := data.Bundle
	if bundle == nil {
		bundle = i18n.New(i18n.Default)
	}

	// One rule per check that actually fired, so the dashboard shows a tidy
	// ruleset rather than every check crackweb knows about.
	rules := map[string]sarifRule{}
	var ruleOrder []string
	for _, f := range data.Findings {
		if _, seen := rules[f.CheckID]; seen {
			continue
		}
		rule := sarifRule{
			ID:               f.CheckID,
			Name:             checkerName(f.CheckID),
			ShortDescription: sarifText{Text: titleText(bundle, f)},
			FullDescription:  sarifText{Text: descriptionText(bundle, f)},
			Properties: map[string]string{
				"security-severity": securityScore(f.Severity),
				"severity":          string(f.Severity),
			},
		}
		if len(f.References) > 0 {
			rule.HelpURI = f.References[0]
		}
		rules[f.CheckID] = rule
		ruleOrder = append(ruleOrder, f.CheckID)
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           version.Name,
			Version:        version.Version,
			InformationURI: version.Repo,
		}},
		Results: make([]sarifResult, 0, len(data.Findings)),
	}
	for _, id := range ruleOrder {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rules[id])
	}

	for _, f := range data.Findings {
		text := titleText(bundle, f)
		if f.Param != "" {
			text += " (" + f.Param + ")"
		}

		result := sarifResult{
			RuleID:  f.CheckID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: text},
			Partial: map[string]any{
				"confidence": string(f.Confidence),
				"check":      f.CheckID,
			},
		}
		if f.URL != "" {
			result.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.URL},
				},
			}}
		}
		if f.Payload != "" {
			result.Partial["payload"] = f.Payload
		}
		if f.CWE != "" {
			result.Partial["cwe"] = f.CWE
		}
		run.Results = append(run.Results, result)
	}

	encoder := newJSONEncoder(w)
	return encoder.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

// checkerName turns a check ID into a display name.
func checkerName(id string) string {
	parts := strings.Split(id, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// sarifLevel maps a severity to a SARIF level.
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium, finding.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}

// securityScore maps a severity to the numeric score GitHub displays.
func securityScore(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.5"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

// --- Markdown -----------------------------------------------------------

// Markdown writes a report that reads well in a terminal, an issue or a pull
// request comment.
func Markdown(w io.Writer, data *Data) error {
	bundle := data.Bundle
	if bundle == nil {
		bundle = i18n.New(i18n.Default)
	}
	out := bufio.NewWriter(w)

	fmt.Fprintf(out, "# %s\n\n", bundle.T(i18n.KeyReportTitle))
	fmt.Fprintf(out, "%s\n\n", bundle.T(i18n.KeyReportSubtitle))
	fmt.Fprintf(out, "- **%s**: `%s`\n", bundle.T(i18n.KeyReportTarget), data.Target)
	fmt.Fprintf(out, "- **%s**: %s\n", bundle.T(i18n.KeyReportStarted), humanTime(data.Started))
	fmt.Fprintf(out, "- **%s**: %s\n", bundle.T(i18n.KeyReportDuration), humanDuration(data.Duration()))
	fmt.Fprintf(out, "- **%s**: %d\n", bundle.T(i18n.KeyReportEndpoints), data.Endpoints)
	fmt.Fprintf(out, "- **%s**: %d\n", bundle.T(i18n.KeyReportRequests), data.Requests)
	if len(data.Hosts) > 0 {
		fmt.Fprintf(out, "- **%s**: %s\n", bundle.T(i18n.KeyReportHosts), strings.Join(data.Hosts, ", "))
	}
	fmt.Fprintf(out, "- **%s**\n\n", bundle.T(i18n.KeyReportGeneratedBy, version.Full()))

	counts := data.Counts()
	fmt.Fprintf(out, "| %s | %d |\n|---|---|\n", bundle.T(i18n.KeyReportSummary), len(data.Findings))
	for _, severity := range severityOrder {
		fmt.Fprintf(out, "| %s | %d |\n", severityLabel(bundle, severity), counts[severity])
	}
	fmt.Fprintf(out, "\n")

	// The boundary comes before the findings, and before the "nothing found" early return:
	// whether a result is complete decides how the list under it should be read, and that
	// matters most in exactly the case where the list is empty.
	if boundary := boundaryLines(bundle, data.Boundary); len(boundary) > 0 {
		fmt.Fprintf(out, "## %s\n\n", bundle.T(i18n.KeyReportBoundaryTitle))
		for _, line := range boundary {
			fmt.Fprintf(out, "- %s\n", line)
		}
		fmt.Fprintf(out, "\n")
	}

	if len(data.Findings) == 0 {
		fmt.Fprintf(out, "%s\n\n", bundle.T(i18n.KeyReportNoFindings))
		fmt.Fprintf(out, "---\n\n> %s\n", bundle.T(i18n.KeyAppDisclaimer))
		return out.Flush()
	}

	for i, f := range data.Findings {
		fmt.Fprintf(out, "## %d. %s\n\n", i+1, titleText(bundle, f))
		fmt.Fprintf(out, "- **%s**: %s\n", bundle.T(i18n.KeyReportFieldSeverity), severityLabel(bundle, f.Severity))
		fmt.Fprintf(out, "- **%s**: %s\n", bundle.T(i18n.KeyReportFieldConfidence), confidenceLabel(bundle, f.Confidence))
		fmt.Fprintf(out, "- **%s**: `%s`\n", bundle.T(i18n.KeyReportFieldCheck), f.CheckID)
		fmt.Fprintf(out, "- **%s**: `%s %s`\n", bundle.T(i18n.KeyReportFieldURL), f.Method, f.URL)
		if f.Param != "" {
			fmt.Fprintf(out, "- **%s**: `%s`\n", bundle.T(i18n.KeyReportFieldParam), f.Param)
		}
		if f.Payload != "" {
			fmt.Fprintf(out, "- **%s**: `%s`\n", bundle.T(i18n.KeyReportFieldPayload), escapeInline(f.Payload))
		}
		if f.CWE != "" {
			fmt.Fprintf(out, "- **%s**: %s\n", bundle.T(i18n.KeyReportCWE), f.CWE)
		}
		fmt.Fprintf(out, "\n**%s**\n\n%s\n\n", bundle.T(i18n.KeyReportFieldDescription), descriptionText(bundle, f))
		fmt.Fprintf(out, "**%s**\n\n%s\n\n", bundle.T(i18n.KeyReportFieldRemediation), remediationText(bundle, f))

		if len(f.Evidence.Matches) > 0 {
			fmt.Fprintf(out, "**%s**\n\n", bundle.T(i18n.KeyReportFieldEvidence))
			for _, m := range f.Evidence.Matches {
				fmt.Fprintf(out, "- `%s`\n", escapeInline(m))
			}
			fmt.Fprintf(out, "\n")
		}
		if f.Evidence.Diff != "" {
			fmt.Fprintf(out, "**%s**: %s\n\n", bundle.T(i18n.KeyReportFieldDiff), f.Evidence.Diff)
		}
		if len(f.Evidence.Request) > 0 {
			fmt.Fprintf(out, "**%s**\n\n```http\n%s\n```\n\n",
				bundle.T(i18n.KeyReportFieldRequest), truncateText(string(f.Evidence.Request), 4000))
		}
		if curl := curlCommand(f.Evidence.Request); curl != "" {
			fmt.Fprintf(out, "**%s**\n\n```sh\n%s\n```\n\n", bundle.T(i18n.KeyReportCurl), curl)
		}
		if len(f.References) > 0 {
			fmt.Fprintf(out, "**%s**\n\n", bundle.T(i18n.KeyReportFieldReferences))
			for _, r := range f.References {
				fmt.Fprintf(out, "- <%s>\n", r)
			}
			fmt.Fprintf(out, "\n")
		}
		fmt.Fprintf(out, "---\n\n")
	}

	fmt.Fprintf(out, "> %s\n", bundle.T(i18n.KeyAppDisclaimer))
	return out.Flush()
}

// escapeInline makes a value safe inside a Markdown code span.
func escapeInline(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "`", "'"), "\n", " ")
}

// truncateText caps a long block for a Markdown report.
func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... [truncated]"
}
