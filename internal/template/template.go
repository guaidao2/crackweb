// Package template implements a nuclei-compatible YAML template engine.
//
// The point of compatibility is ecosystem: there are thousands of published
// nuclei templates, and a scanner that can read them inherits that coverage
// without anyone rewriting them. crackweb therefore parses the same document
// shape — id/info, http requests, matchers, extractors, the same helper
// variables — and reports hits as ordinary findings.
//
// Compatibility is deliberately a subset, and an honest one. Fields crackweb
// cannot honour (flow, multi-protocol chaining, raw unsafe requests) are
// reported when a template is loaded rather than silently ignored, because a
// template that half-runs is worse than one that refuses to.
package template

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/crackweb/internal/finding"
)

// Template is one nuclei template document.
type Template struct {
	ID        string            `yaml:"id"`
	Info      Info              `yaml:"info"`
	Variables map[string]string `yaml:"variables"`
	// HTTP holds the HTTP request blocks. nuclei accepts both "http" and the
	// older "requests" spelling.
	HTTP     []HTTPRequest `yaml:"http"`
	Requests []HTTPRequest `yaml:"requests"`
	// Flow marks a template whose control flow crackweb cannot execute.
	Flow string `yaml:"flow"`
	// SelfContained and StopAtFirstMatch are accepted for compatibility.
	SelfContained    bool `yaml:"self-contained"`
	StopAtFirstMatch bool `yaml:"stop-at-first-match"`
}

// Info is the template's metadata block.
type Info struct {
	Name           string         `yaml:"name"`
	Author         StringList     `yaml:"author"`
	Severity       string         `yaml:"severity"`
	Description    string         `yaml:"description"`
	Reference      StringList     `yaml:"reference"`
	Tags           StringList     `yaml:"tags"`
	Classification Classification `yaml:"classification"`
	Metadata       map[string]any `yaml:"metadata"`
}

// Classification carries the CVE/CWE/CVSS block.
type Classification struct {
	CVEID      StringList `yaml:"cve-id"`
	CWEID      StringList `yaml:"cwe-id"`
	CVSSScore  any        `yaml:"cvss-score"`
	CVSSMetric string     `yaml:"cvss-metrics"`
}

// HTTPRequest is one request block.
type HTTPRequest struct {
	Method       string                `yaml:"method"`
	Path         StringList            `yaml:"path"`
	Raw          StringList            `yaml:"raw"`
	Headers      map[string]string     `yaml:"headers"`
	Body         string                `yaml:"body"`
	Redirects    bool                  `yaml:"redirects"`
	MaxRedirects int                   `yaml:"max-redirects"`
	CookieReuse  bool                  `yaml:"cookie-reuse"`
	Unsafe       bool                  `yaml:"unsafe"`
	Payloads     map[string]StringList `yaml:"payloads"`
	Attack       string                `yaml:"attack"`

	MatchersCondition string      `yaml:"matchers-condition"`
	Matchers          []Matcher   `yaml:"matchers"`
	Extractors        []Extractor `yaml:"extractors"`

	// StopAtFirstMatch is accepted per-request for compatibility.
	StopAtFirstMatch bool   `yaml:"stop-at-first-match"`
	ReqCondition     bool   `yaml:"req-condition"`
	HostRedirects    bool   `yaml:"host-redirects"`
	Threads          int    `yaml:"threads"`
	Pipeline         bool   `yaml:"pipeline"`
	SkipVariables    bool   `yaml:"skip-variables-check"`
	ID               string `yaml:"id"`
}

// Matcher is one detection rule.
type Matcher struct {
	Type            string     `yaml:"type"`
	Part            string     `yaml:"part"`
	Words           StringList `yaml:"words"`
	Regex           StringList `yaml:"regex"`
	Status          []int      `yaml:"status"`
	Size            []int      `yaml:"size"`
	DSL             StringList `yaml:"dsl"`
	Binary          StringList `yaml:"binary"`
	XPath           StringList `yaml:"xpath"`
	Condition       string     `yaml:"condition"`
	Negative        bool       `yaml:"negative"`
	CaseInsensitive bool       `yaml:"case-insensitive"`
	Internal        bool       `yaml:"internal"`
	Name            string     `yaml:"name"`
	Encoding        string     `yaml:"encoding"`
}

// Extractor pulls a value out of a response.
type Extractor struct {
	Type     string     `yaml:"type"`
	Part     string     `yaml:"part"`
	Regex    StringList `yaml:"regex"`
	Group    int        `yaml:"group"`
	Name     string     `yaml:"name"`
	KVal     StringList `yaml:"kval"`
	JSON     StringList `yaml:"json"`
	DSL      StringList `yaml:"dsl"`
	Internal bool       `yaml:"internal"`
}

// StringList unmarshals a YAML field that may be written as a single scalar or
// as a sequence. nuclei templates use both spellings freely — "tags: cve,rce"
// and a proper list mean the same thing — so the decoder has to accept either.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		text := strings.TrimSpace(value.Value)
		if text == "" {
			return nil
		}
		// A comma-separated scalar is a list in disguise.
		if strings.Contains(text, ",") {
			for _, part := range strings.Split(text, ",") {
				if part = strings.TrimSpace(part); part != "" {
					*s = append(*s, part)
				}
			}
			return nil
		}
		*s = append(*s, text)
		return nil
	case yaml.SequenceNode:
		for _, item := range value.Content {
			var text string
			if err := item.Decode(&text); err != nil {
				return err
			}
			if text = strings.TrimSpace(text); text != "" {
				*s = append(*s, text)
			}
		}
		return nil
	default:
		return nil
	}
}

// Severity returns the template's severity, normalised onto crackweb's scale.
// An unrecognised value becomes "unknown" rather than being passed through, so
// a typo in a template cannot produce a report element nobody can filter.
func (t *Template) Severity() string {
	return string(finding.ParseSeverity(t.Info.Severity))
}

// Requests returns the effective request list, whichever spelling was used.
func (t *Template) Requests_() []HTTPRequest {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// Parse decodes one template document.
func Parse(data []byte) (*Template, error) {
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if tmpl.ID == "" {
		return nil, fmt.Errorf("template has no id")
	}
	if len(tmpl.Requests_()) == 0 && tmpl.Flow == "" {
		return nil, fmt.Errorf("template %s has no http requests", tmpl.ID)
	}
	return &tmpl, nil
}

// Unsupported returns the features a template uses that crackweb cannot honour.
// A caller can then warn rather than load a template that will quietly do the
// wrong thing.
func (t *Template) Unsupported() []string {
	var reasons []string

	if strings.TrimSpace(t.Flow) != "" {
		reasons = append(reasons, "flow-based request orchestration")
	}
	for i, req := range t.Requests_() {
		label := fmt.Sprintf("request %d", i+1)
		if req.Unsafe {
			reasons = append(reasons, label+": raw unsafe requests")
		}
		if len(req.Payloads) > 1 && !strings.EqualFold(req.Attack, "") &&
			!strings.EqualFold(req.Attack, "batteringram") {
			// Crackweb executes every payload combination one at a time, which
			// matches batteringram; the other attacks need cross-product
			// variable handling it does not have.
			reasons = append(reasons, label+": attack type "+req.Attack)
		}
		if req.Pipeline {
			reasons = append(reasons, label+": HTTP pipelining")
		}
		for _, m := range req.Matchers {
			switch strings.ToLower(m.Type) {
			case "word", "regex", "status", "size", "dsl", "binary", "":
			case "xpath":
				reasons = append(reasons, label+": xpath matchers")
			default:
				reasons = append(reasons, label+": matcher type "+m.Type)
			}
		}
		for _, e := range req.Extractors {
			switch strings.ToLower(e.Type) {
			case "regex", "kval", "dsl", "json", "":
			case "xpath":
				reasons = append(reasons, label+": xpath extractors")
			default:
				reasons = append(reasons, label+": extractor type "+e.Type)
			}
		}
	}
	return dedupeStrings(reasons)
}

// LoadDir reads every .yaml/.yml template under a directory, recursively.
func LoadDir(dir string) ([]*Template, []error) {
	var (
		templates []*Template
		errs      []error
	)

	walkErr := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, readErr))
			return nil
		}
		tmpl, parseErr := Parse(data)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, parseErr))
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}

	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	return templates, errs
}

// dedupeStrings removes duplicates while preserving order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
