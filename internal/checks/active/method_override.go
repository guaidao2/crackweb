package active

import (
	"context"
	"strconv"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// methodOverrideHeaders are the fields frameworks and front ends use to let a
// client name a method the transport would not carry.
//
// They exist for a legitimate reason — a browser form can only send GET and
// POST, so a REST application accepts the real verb in a header. The problem is
// the same feature seen from the other side: an access rule that reads the
// request line sees "GET" while the application performs a DELETE.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
	"X-Original-Method",
	"X-Override-Method",
	"_method",
}

// methodOverrideVerbs are the methods worth claiming. They are the ones a rule
// is most likely to refuse and most damaging to reach.
var methodOverrideVerbs = []string{"DELETE", "PUT", "PATCH"}

// methodOverrideSimilarity is how different a response must be before the
// override is judged to have been acted on.
const methodOverrideSimilarity = 0.90

// methodOverrideStability is how alike two back-to-back requests must be before
// their answers are worth comparing at all.
const methodOverrideStability = 0.98

// methodOverrideControlHeader is a header no application reads. It is sent
// before the real probe so that a target which reacts to *any* new header — a
// Vary-driven cache, a header-echoing debug page — is not mistaken for one that
// reads this particular header.
const methodOverrideControlHeader = "X-Crackweb-Control"

// methodOverride detects an application that lets a header decide what the
// request does.
//
// The judgement is a difference, not a status code: if adding the header changes
// what comes back, something downstream read it. That is the precondition for a
// bypass — whether the bypass is real depends on where the access rule lives,
// which a scanner cannot see, so the finding says so rather than asserting it.
type methodOverride struct{}

func (methodOverride) ID() string                 { return "method-override" }
func (methodOverride) TitleKey() i18n.Key         { return i18n.KeyCheckMethodOverrideTitle }
func (methodOverride) DescriptionKey() i18n.Key   { return i18n.KeyCheckMethodOverrideDesc }
func (methodOverride) RemediationKey() i18n.Key   { return i18n.KeyCheckMethodOverrideFix }
func (methodOverride) Severity() finding.Severity { return finding.SeverityMedium }
func (methodOverride) Tags() []string {
	return []string{"active", "authorization", "misconfiguration"}
}
func (methodOverride) Passive() bool { return false }

// IsRequestLevel marks this as a check that rewrites the request's headers.
func (methodOverride) IsRequestLevel() bool { return true }

func (methodOverride) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// A response that already failed gives no baseline to measure a change
	// against, and a 405 is exactly the state a bypass would move away from —
	// but then the change would be an improvement the check cannot interpret,
	// so it stays quiet and leaves that to a targeted test.
	if t.Response.Status >= 400 {
		return nil
	}

	// The comparison has to be against the target as it is now, not as it was
	// when it was discovered: several checks run against a page that has since
	// had a form submitted to it, and judging those against the stored response
	// reports the form submission as the probe's doing.
	baseline := c.StableBaseline(ctx, t.Request, methodOverrideStability)
	if baseline == nil {
		return nil
	}

	// The control: a header with no meaning, sent through the same path. If it
	// moves the response too, this target cannot distinguish "read the override"
	// from "read anything".
	control := t.Request.Clone()
	control.Header.Set(methodOverrideControlHeader, "1")
	controlResponse, err := c.Do(ctx, control)
	if err != nil || controlResponse == nil {
		return nil
	}
	controlScore := diff.CompareFingerprints(
		c.Fingerprint(baseline), c.Fingerprint(controlResponse)).Score
	if controlScore < methodOverrideSimilarity {
		return nil
	}

	for _, header := range methodOverrideHeaders {
		for _, verb := range methodOverrideVerbs {
			mutated := t.Request.Clone()
			mutated.Header.Set(header, verb)

			response, err := c.Do(ctx, mutated)
			if err != nil || response == nil {
				continue
			}
			// A refusal is the correct outcome: the application ignored the
			// header, or refused the method it named.
			if response.Status >= 400 && response.Status == baseline.Status {
				continue
			}
			// A server error is a crash, not a decision about the header. One arriving
			// while the baseline was a 200 compares an error page against a working one
			// and concludes that the application acted on the override — which is how a
			// single transient 5xx becomes that finding. The WAF state machine already
			// reads a 5xx this way ("a 5xx from the origin is a crash, not a refusal");
			// this check did not.
			if response.Status >= 500 {
				continue
			}

			// Measured against the control, not just the baseline: the question
			// is whether this header did something the meaningless one did not.
			similarity := diff.CompareFingerprints(
				c.Fingerprint(controlResponse), c.Fingerprint(response)).Score
			if similarity >= methodOverrideSimilarity {
				// Nothing changed beyond what the meaningless control header
				// already changed, so this header was not read.
				continue
			}

			f := checks.NewFinding(methodOverride{}, t,
				i18n.KeyCheckMethodOverrideTitle, i18n.KeyCheckMethodOverrideDesc, i18n.KeyCheckMethodOverrideFix)
			f.Severity = finding.SeverityMedium
			// Tentative: the header is demonstrably honoured, but whether that
			// crosses an authorisation boundary is not something this response
			// can show.
			f.Confidence = finding.ConfidenceTentative
			f.Method = mutated.Method
			f.URL = mutated.URLString()
			f.Payload = header + ": " + verb
			f.CWE = "CWE-650"
			f.References = []string{
				"https://owasp.org/www-community/attacks/HTTP_Verb_Tampering",
				"https://cwe.mitre.org/data/definitions/650.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(controlResponse.Body, 4096)
			f.Evidence.Matches = []string{
				header + ": " + verb + " changed the response where the control header " +
					methodOverrideControlHeader + " did not (status " +
					strconv.Itoa(controlResponse.Status) + " → " + strconv.Itoa(response.Status) +
					", similarity " + round3(similarity) + ")",
			}
			return []*finding.Finding{f}
		}
	}
	return nil
}
