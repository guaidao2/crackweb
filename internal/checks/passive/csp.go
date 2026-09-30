package passive

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// cspWeaknesses reports a Content-Security-Policy that is present but does not do the job it
// is credited with.
//
// The policy is the second line of defence once markup has slipped through, and a policy
// that permits inline script is not that line: `'unsafe-inline'` is precisely the permission
// an injected `<script>` needs. The difference between "no policy" and "a policy that allows
// what it should stop" matters to whoever fixes it — one is a missing header, the other is a
// review of the policy — so this is a check of its own rather than a line in the header one.
type cspWeaknesses struct{}

func (cspWeaknesses) ID() string { return "passive-csp" }
func (cspWeaknesses) TitleKey() i18n.Key {
	return i18n.KeyCheckCSPTitle
}
func (cspWeaknesses) DescriptionKey() i18n.Key {
	return i18n.KeyCheckCSPDesc
}
func (cspWeaknesses) RemediationKey() i18n.Key {
	return i18n.KeyCheckCSPFix
}
func (cspWeaknesses) Severity() finding.Severity { return finding.SeverityLow }
func (cspWeaknesses) Tags() []string {
	return []string{"passive", "headers", "hardening", "xss"}
}
func (cspWeaknesses) Passive() bool { return true }

// cspSourcesThatDoNotHelp are the source expressions that leave the policy without its
// effect. They are compared against the sources of the script directive, lower-cased.
var cspSourcesThatDoNotHelp = []string{"*", "'unsafe-inline'", "'unsafe-eval'", "data:"}

// cspNonceOrHash reports whether a source list carries a nonce or a hash.
//
// It matters because the specification says a nonce or hash makes the browser *ignore*
// `'unsafe-inline'` in the same list. A policy written that way is doing the right thing
// while looking, to a string comparison, like one that is not — and reporting it would be a
// false positive against a target whose policy is stricter than it appears.
func cspNonceOrHash(sources []string) bool {
	for _, source := range sources {
		lower := strings.ToLower(source)
		for _, prefix := range []string{"'nonce-", "'sha256-", "'sha384-", "'sha512-"} {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	}
	return false
}

// cspScriptDirective returns the sources governing script for a policy, and the name of the
// directive they came from.
//
// The script directive wins; `default-src` is the fallback the specification defines. Both
// missing means nothing constrains script at all.
func cspScriptDirective(policy string) (sources []string, directive string, found bool) {
	for _, clause := range strings.Split(policy, ";") {
		fields := strings.Fields(clause)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if name != "script-src" && name != "default-src" {
			continue
		}
		// A later script-src overrides an earlier default-src.
		if directive == "script-src" {
			continue
		}
		sources, directive, found = fields[1:], name, true
		if name == "script-src" {
			return sources, directive, true
		}
	}
	return sources, directive, found
}

// cspProblems describes what is wrong with a policy, as sentences for the evidence.
func cspProblems(policy string) []string {
	sources, directive, found := cspScriptDirective(policy)
	if !found {
		return []string{"the policy sets neither script-src nor default-src, so nothing constrains script"}
	}
	var out []string
	lowered := make([]string, 0, len(sources))
	for _, source := range sources {
		lowered = append(lowered, strings.ToLower(source))
	}
	hasNonceOrHash := cspNonceOrHash(sources)
	for _, bad := range cspSourcesThatDoNotHelp {
		present := false
		for _, source := range lowered {
			if source == bad {
				present = true
				break
			}
		}
		if !present {
			continue
		}
		if bad == "'unsafe-inline'" && hasNonceOrHash {
			// The browser ignores it in this list, so neither does the finding apply.
			continue
		}
		out = append(out, directive+" allows "+bad)
	}
	return out
}

func (cspWeaknesses) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Response == nil || !isHTML(t.Response) {
		return nil
	}
	enforced := t.Response.Header.Get("Content-Security-Policy")
	reportOnly := t.Response.Header.Get("Content-Security-Policy-Report-Only")
	// A missing policy is the other check's business.
	if enforced == "" && reportOnly == "" {
		return nil
	}

	var matches []string
	policy := enforced
	if policy == "" {
		matches = append(matches, "only Content-Security-Policy-Report-Only is present, so the "+
			"policy is reported on and never enforced")
		policy = reportOnly
	}
	matches = append(matches, cspProblems(policy)...)
	if len(matches) == 0 {
		return nil
	}

	f := checks.NewFinding(cspWeaknesses{}, t,
		i18n.KeyCheckCSPTitle, i18n.KeyCheckCSPDesc, i18n.KeyCheckCSPFix)
	f.Severity = finding.SeverityLow
	f.Confidence = finding.ConfidenceCertain
	f.DedupHostOnly = true
	f.Evidence.Matches = matches
	return []*finding.Finding{f}
}
