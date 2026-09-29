package active

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// parameterTypeBypass looks for a validation that only applies to a scalar.
//
// Frameworks disagree about what `id[]=abc` is: one hands the handler an array, another
// takes the first element, a third rejects the request outright. Where a check on the
// value was written for a string and the framework delivers something else, the check
// never sees what it was meant to reject — and the same value, offered again under a name
// the framework parses differently, goes straight through.
//
// The test is therefore the same value twice. The first half is what keeps it honest: a
// parameter that accepts anything has no validation to step around, so the check stops
// there rather than reporting the parameter as unprotected.
type parameterTypeBypass struct{}

func (parameterTypeBypass) ID() string { return "parameter-type-bypass" }
func (parameterTypeBypass) TitleKey() i18n.Key {
	return i18n.KeyCheckTypeBypassTitle
}
func (parameterTypeBypass) DescriptionKey() i18n.Key {
	return i18n.KeyCheckTypeBypassDesc
}
func (parameterTypeBypass) RemediationKey() i18n.Key {
	return i18n.KeyCheckTypeBypassFix
}
func (parameterTypeBypass) Severity() finding.Severity { return finding.SeverityMedium }
func (parameterTypeBypass) Tags() []string {
	return []string{"active", "injection", "validation", "owasp-top10"}
}
func (parameterTypeBypass) Passive() bool { return false }

// typeBypassProbe is a value no validator that was written for a real parameter would
// accept: it is not a number, not an identifier, and carries a character every encoding
// has to escape.
const typeBypassProbe = "crackweb!invalid"

// typeBypassForms are the spellings the parameter is renamed to. Both are array forms,
// which is the shape that makes a framework hand a scalar validator something that is not
// one.
var typeBypassForms = []string{"%s[]", "%s[0]"}

// typeBypassSimilarity is how alike the wrapped response has to be to the original before
// it counts as the application having served the request as usual. A refusal page, a
// validation error or a stack trace is not an acceptance.
const typeBypassSimilarity = 0.8

func (parameterTypeBypass) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// A value inside an encoded document is addressed by a different mechanism, and the
	// envelope would have to be rebuilt for this question to mean anything.
	if t.Param.Wrapper != httpmsg.WrapNone {
		return nil
	}
	if t.Param.In != httpmsg.LocQuery && t.Param.In != httpmsg.LocBody {
		return nil
	}
	if t.Response.Status >= 400 || len(t.Response.Body) == 0 {
		return nil
	}

	encoded := url.QueryEscape(typeBypassProbe)

	// Is the value validated at all? Without a validation there is nothing to step around,
	// and a parameter that accepts anything is not this check's subject.
	probeRequest, ok := rewriteParameterName(t.Request, *t.Param, t.Param.RawName, encoded)
	if !ok {
		return nil
	}
	refused, err := c.Do(ctx, probeRequest)
	if err != nil || refused == nil || refused.Status < 400 {
		return nil
	}

	base := c.BaselineFingerprint(t)
	for _, form := range typeBypassForms {
		name := fmt.Sprintf(form, t.Param.RawName)
		mutated, ok := rewriteParameterName(t.Request, *t.Param, name, encoded)
		if !ok {
			continue
		}
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil {
			continue
		}
		if response.Status < 200 || response.Status >= 300 || len(response.Body) == 0 {
			continue
		}
		// The same value was refused a moment ago, so a response that looks like the
		// ordinary page is the validation having been stepped around.
		if diff.CompareFingerprints(base, c.Fingerprint(response)).Score < typeBypassSimilarity {
			continue
		}

		f := checks.NewFinding(parameterTypeBypass{}, t,
			i18n.KeyCheckTypeBypassTitle, i18n.KeyCheckTypeBypassDesc, i18n.KeyCheckTypeBypassFix)
		f.Severity = finding.SeverityMedium
		f.Confidence = finding.ConfidenceFirm
		f.Payload = name + "=" + typeBypassProbe
		f.DedupExtra = name
		f.CWE = "CWE-1287"
		f.References = []string{
			"https://cwe.mitre.org/data/definitions/1287.html",
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Raw(), 8192)
		f.Evidence.Baseline = truncate(t.Response.Raw(), 4096)
		f.Evidence.Matches = []string{c.Bundle.T(i18n.KeyEvidenceTypeBypass,
			typeBypassProbe, refused.Status, name, response.Status)}
		return []*finding.Finding{f}
	}
	return nil
}

// rewriteParameterName rebuilds a request with one parameter pair rewritten: a different
// name, and the value it should carry. The pairs around it keep their order and their
// encoding.
func rewriteParameterName(req *httpmsg.Request, param httpmsg.Param, name, encodedValue string) (*httpmsg.Request, bool) {
	out := req.Clone()
	switch param.In {
	case httpmsg.LocQuery:
		if out.URL == nil {
			return nil, false
		}
		out.URL.RawQuery = replacePairText(out.URL.RawQuery, param, name, encodedValue)
	case httpmsg.LocBody:
		body := replacePairText(string(out.Body), param, name, encodedValue)
		out.Body = []byte(body)
		out.Header.Set("Content-Length", strconv.Itoa(len(body)))
	default:
		return nil, false
	}
	return out, true
}

// replacePairText rewrites one "name=value" pair, matching on the raw name and skipping
// earlier namesakes.
func replacePairText(raw string, param httpmsg.Param, name, value string) string {
	parts := strings.Split(raw, "&")
	seen := 0
	for index, part := range parts {
		existing, _, _ := strings.Cut(part, "=")
		if existing != param.RawName {
			continue
		}
		if seen == param.Occurrence {
			parts[index] = name + "=" + value
			return strings.Join(parts, "&")
		}
		seen++
	}
	return raw + "&" + name + "=" + value
}
