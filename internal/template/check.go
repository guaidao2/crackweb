package template

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// Check adapts a template to the check interface, so templates and built-in
// checks run through exactly the same scanner, queue and reporting path.
//
// A template brings its own prose, in the language its author wrote it, so the
// adapter returns no catalogue keys and the finding carries literal text
// instead. That is the honest outcome: crackweb cannot translate a template it
// did not write.
type Check struct {
	tmpl   *Template
	runner *Runner
}

// NewCheck wraps a template as a runnable check.
func NewCheck(tmpl *Template, runner *Runner) *Check {
	return &Check{tmpl: tmpl, runner: runner}
}

// Template returns the wrapped template.
func (c *Check) Template() *Template { return c.tmpl }

// ID is namespaced so a template can never shadow a built-in check.
func (c *Check) ID() string { return "template:" + c.tmpl.ID }

// TitleKey returns an empty key: the title comes from the template itself.
func (c *Check) TitleKey() i18n.Key { return "" }

// DescriptionKey returns an empty key, for the same reason.
func (c *Check) DescriptionKey() i18n.Key { return "" }

// RemediationKey returns an empty key: templates carry no remediation advice.
func (c *Check) RemediationKey() i18n.Key { return "" }

// Severity maps the template's severity onto crackweb's scale.
func (c *Check) Severity() finding.Severity {
	return finding.ParseSeverity(c.tmpl.Info.Severity)
}

// Tags exposes the template's tags for filtering, plus a marker that says where
// the check came from.
func (c *Check) Tags() []string {
	tags := append([]string{"template"}, c.tmpl.Info.Tags...)
	return tags
}

// Passive is false: a template always sends its own request.
func (c *Check) Passive() bool { return false }

// IsRequestLevel is true: a template describes one request to send, so running
// it once per parameter would send that request several times over.
func (c *Check) IsRequestLevel() bool { return true }

// Run executes the template against the target and returns what matched.
func (c *Check) Run(ctx context.Context, cc *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil {
		return nil
	}

	// The scan is told about every request the template sends, so its totals and
	// its --verbose stream cover template traffic too.
	var observe func(*httpmsg.Request)
	if cc != nil {
		observe = cc.Observe
	}

	findings := c.runner.Execute(ctx, c.tmpl, t.Request, t.Response, observe)
	for _, f := range findings {
		// Fill in the prose the check interface has no room for.
		if f.Title == "" {
			f.Title = c.tmpl.Info.Name
		}
		if f.Description == "" {
			f.Description = c.tmpl.Info.Description
		}
		if f.Severity == finding.SeverityUnknown {
			f.Severity = c.Severity()
		}
		if strings.TrimSpace(f.Title) == "" {
			f.Title = c.tmpl.ID
		}
	}
	return findings
}

// Truncation reports a template whose payloads describe more requests than the
// per-template budget allows.
//
// The template still runs; it just runs over fewer combinations than it wrote,
// and a caller can say so. The alternative — a silent cap — is a scan that
// reports "nothing found" for payloads it never sent.
type Truncation struct {
	TemplateID string
	// Request is the 1-based block the count belongs to.
	Request int
	// Described is how many requests the template's payloads describe.
	Described int
	// Sent is how many of them crackweb will send.
	Sent int
}

// LoadChecks loads every template under the given directories and wraps them as
// checks. Templates using features crackweb cannot honour are returned
// separately, so the caller can warn instead of running them half-way, and
// templates that exceed the request budget are reported so the caller can say
// how much of them will run.
func LoadChecks(runner *Runner, dirs []string) (loaded []*Check, unsupported map[string][]string, truncated []Truncation, errs []error) {
	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		templates, loadErrs := LoadDir(dir)
		errs = append(errs, loadErrs...)

		for _, tmpl := range templates {
			if reasons := tmpl.Unsupported(); len(reasons) > 0 {
				if unsupported == nil {
					unsupported = map[string][]string{}
				}
				unsupported[tmpl.ID] = reasons
				continue
			}
			truncated = append(truncated, budgetNotes(tmpl)...)
			loaded = append(loaded, NewCheck(tmpl, runner))
		}
	}
	return loaded, unsupported, truncated, errs
}

// budgetNotes reports the blocks whose payloads describe more requests than the
// budget allows.
func budgetNotes(tmpl *Template) []Truncation {
	var notes []Truncation
	for index, block := range tmpl.Requests_() {
		described := payloadCombinationCount(block)
		if described <= MaxPayloadCombinations {
			continue
		}
		notes = append(notes, Truncation{
			TemplateID: tmpl.ID,
			Request:    index + 1,
			Described:  described,
			Sent:       MaxPayloadCombinations,
		})
	}
	return notes
}
