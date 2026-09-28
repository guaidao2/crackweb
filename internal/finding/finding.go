// Package finding is crackweb's result model: one vulnerability, with the
// evidence needed to believe it and reproduce it.
//
// A Finding is deliberately self-contained. It carries the exact request that
// triggered it, the response that proved it, and the payload that was injected,
// so a report reader never has to take the scanner's word for anything — and a
// developer can replay the finding with one copy-paste.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/i18n"
)

// Severity rates how much damage the finding could do.
type Severity string

// Severity levels, ordered from least to most severe and matching the names
// nuclei uses so that template-supplied severities drop straight in.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// severityRank orders severities for sorting and for filtering by minimum
// severity. Unknown sorts below everything: it means "not determined".
var severityRank = map[Severity]int{
	SeverityUnknown:  0,
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
}

// Rank returns the severity's ordering position; higher is more severe.
func (s Severity) Rank() int { return severityRank[ParseSeverity(string(s))] }

// ParseSeverity normalises a severity string, accepting the spellings templates
// and humans actually use. Anything unrecognised becomes SeverityUnknown rather
// than an error: a typo in a template should not stop a scan.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate", "med":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "information":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// Confidence expresses how sure the check is that this is a real vulnerability,
// not a false positive. It is the main lever against alert fatigue: a scanner
// that reports everything as certain trains its users to ignore it.
type Confidence string

// Confidence levels, modelled on the levels Burp uses.
const (
	// ConfidenceCertain means the evidence is conclusive — an error message,
	// file contents, or an out-of-band callback.
	ConfidenceCertain Confidence = "certain"
	// ConfidenceFirm means strong evidence that could, in rare configurations,
	// have another explanation.
	ConfidenceFirm Confidence = "firm"
	// ConfidenceTentative means a hint worth a human's attention.
	ConfidenceTentative Confidence = "tentative"
)

// confidenceRank orders confidences for sorting.
var confidenceRank = map[Confidence]int{
	ConfidenceTentative: 1,
	ConfidenceFirm:      2,
	ConfidenceCertain:   3,
}

// Rank returns the confidence's ordering position; higher is more certain.
func (c Confidence) Rank() int { return confidenceRank[ParseConfidence(string(c))] }

// ParseConfidence normalises a confidence string, defaulting to tentative.
func ParseConfidence(s string) Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "certain", "high":
		return ConfidenceCertain
	case "firm", "medium":
		return ConfidenceFirm
	default:
		return ConfidenceTentative
	}
}

// Evidence is the proof attached to a finding: what was sent, what came back,
// and which part of the response triggered the check.
type Evidence struct {
	// Request is the raw request that triggered the finding, injection included.
	Request []byte
	// Response is the raw response that proved it, possibly truncated.
	Response []byte
	// ResponseTruncated records that Response was cut short for storage.
	ResponseTruncated bool
	// Matches are the literal strings, regular expressions or expressions that
	// fired, in the order the check evaluated them.
	Matches []string
	// Diff summarises how the response differed from the baseline, in the
	// scanner's words. It is what a human reads when the payload is subtle.
	Diff string
	// Baseline is the raw response to the unmodified request, when the finding
	// rests on a comparison.
	Baseline []byte
	// Duration is how long the triggering request took, which is the evidence
	// for time-based findings.
	Duration time.Duration
}

// Finding is one reported vulnerability.
type Finding struct {
	// ID is a stable identifier derived from the check and injection point, so
	// that two runs against the same target produce comparable reports.
	ID string

	// CheckID is the machine name of the check that fired, e.g. "sqli-error".
	CheckID string
	// TitleKey and DescriptionKey are catalogue keys: the report renders the
	// finding in whichever language the user asked for, without the check
	// needing to know anything about languages.
	TitleKey       i18n.Key
	DescriptionKey i18n.Key
	// Title, Description and Remediation carry literal text for findings whose
	// prose comes from outside the catalogue — a nuclei template brings its own
	// wording, in whatever language its author wrote it. When set, they take
	// precedence over the keys above.
	Title       string
	Description string
	Remediation string

	// Severity and Confidence rate the finding.
	Severity   Severity
	Confidence Confidence

	// Method, URL and Param locate the vulnerability. Param is empty for
	// findings that are not tied to one parameter, such as a missing header.
	Method string
	URL    string
	Param  string
	// Payload is the exact value injected, when the finding came from a mutation.
	Payload string

	// Evidence is the proof.
	Evidence Evidence

	// RemediationKey is a catalogue key for the fix advice.
	RemediationKey i18n.Key
	// References are external links: advisories, CWEs, documentation.
	References []string
	// Tags are free-form labels used for filtering.
	Tags []string
	// CWE and CVSS carry the classification when it is known.
	CWE  string
	CVSS string

	// TemplateID is set when the finding came from a nuclei-compatible template.
	TemplateID string

	// DedupHostOnly collapses findings that share a host, a check and a
	// parameter, ignoring the path. Response-header configuration is normally
	// site-wide, so reporting it once per URL would bury everything else.
	DedupHostOnly bool
	// DedupExtra adds a check-specific dimension to the dedup key, such as the
	// cookie name that is missing its flags.
	DedupExtra string

	// FoundAt is when the check fired.
	FoundAt time.Time
}

// DedupKey identifies the same vulnerability across repeats. Two findings with
// the same key are the same problem seen twice, so only the first is reported.
//
// The key deliberately excludes the payload: a parameter vulnerable to three
// SQL injection payloads is one finding with three proofs, not three findings.
func (f *Finding) DedupKey() string {
	location := normaliseURLForDedup(f.URL)
	if f.DedupHostOnly {
		location = hostOf(f.URL)
	}
	parts := []string{f.CheckID, f.Method, location, f.Param, f.DedupExtra}
	return strings.Join(parts, "|")
}

// ComputeID fills in ID from the dedup key when it is empty.
func (f *Finding) ComputeID() {
	if f.ID != "" {
		return
	}
	sum := sha256.Sum256([]byte(f.DedupKey()))
	f.ID = hex.EncodeToString(sum[:8])
}

// normaliseURLForDedup strips the query string and fragment from a URL so that
// the same endpoint found with different parameters collapses to one key.
func normaliseURLForDedup(rawURL string) string {
	if i := strings.IndexAny(rawURL, "?#"); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}

// hostOf extracts the host from a URL, falling back to the raw string.
func hostOf(rawURL string) string {
	rest := rawURL
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// Sort orders findings most-severe first, then most-confident, then by URL, so
// that reports lead with what matters.
func Sort(findings []*Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Confidence.Rank() != b.Confidence.Rank() {
			return a.Confidence.Rank() > b.Confidence.Rank()
		}
		if a.URL != b.URL {
			return a.URL < b.URL
		}
		if a.Param != b.Param {
			return a.Param < b.Param
		}
		return a.CheckID < b.CheckID
	})
}

// Dedup collapses findings that share a dedup key, keeping the first occurrence
// of each alongside the extra payloads that also proved it.
func Dedup(findings []*Finding) []*Finding {
	seen := make(map[string]*Finding, len(findings))
	out := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		key := f.DedupKey()
		if kept, ok := seen[key]; ok {
			kept.Evidence.Matches = appendUnique(kept.Evidence.Matches, f.Evidence.Matches...)
			continue
		}
		seen[key] = f
		out = append(out, f)
	}
	return out
}

// appendUnique appends values not already present, preserving order.
func appendUnique(dst []string, values ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}

// CountBySeverity tallies findings per severity, for report summaries.
func CountBySeverity(findings []*Finding) map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}
