package active

import (
	"context"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// ipSpoof reports a restricted endpoint that lets the caller say where it is connecting from.
//
// The check only has anything to say about an address the site already refused: a 401 or a
// 403 is a site stating that this request is not allowed, and if adding a header that names
// a loopback or private address turns that into an answer, the refusal was about the address
// the caller claimed rather than the one it came from. Anything else is not evidence — a
// page that answers 200 has not told us what it would do for a refused request.
//
// It is deliberately narrow for that reason. A scanner cannot know which paths are
// restricted; what it can know is which ones it was just refused, and that is enough.
type ipSpoof struct{}

func (ipSpoof) ID() string                 { return "ip-spoof" }
func (ipSpoof) TitleKey() i18n.Key         { return i18n.KeyCheckIPSpoofTitle }
func (ipSpoof) DescriptionKey() i18n.Key   { return i18n.KeyCheckIPSpoofDesc }
func (ipSpoof) RemediationKey() i18n.Key   { return i18n.KeyCheckIPSpoofFix }
func (ipSpoof) Severity() finding.Severity { return finding.SeverityHigh }
func (ipSpoof) Tags() []string {
	return []string{"active", "access-control", "proxy", "owasp-top10"}
}
func (ipSpoof) Passive() bool { return false }

// IsRequestLevel marks this as a check about the address rather than about one parameter.
func (ipSpoof) IsRequestLevel() bool { return true }

// ipSpoofHeaders are the headers a front end sets and an application may trust by mistake.
var ipSpoofHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP",
	"CF-Connecting-IP", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
}

// ipSpoofValues are the addresses an allow-list is written for.
var ipSpoofValues = []string{"127.0.0.1", "10.0.0.1", "192.168.0.1"}

func (ipSpoof) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// The only starting point that means anything is a refusal.
	if t.Response.Status != 401 && t.Response.Status != 403 {
		return nil
	}

	for _, header := range ipSpoofHeaders {
		for _, value := range ipSpoofValues {
			mutated := t.Request.Clone()
			mutated.Header.Set(header, value)
			response, err := c.Do(ctx, mutated)
			if err != nil || response == nil {
				continue
			}
			if response.Status >= 300 {
				continue
			}

			f := checks.NewFinding(ipSpoof{}, t,
				i18n.KeyCheckIPSpoofTitle, i18n.KeyCheckIPSpoofDesc, i18n.KeyCheckIPSpoofFix)
			f.Severity = finding.SeverityHigh
			// Certain: the endpoint refused the request and then answered it, and the header
			// is the only thing that changed.
			f.Confidence = finding.ConfidenceCertain
			f.Method = mutated.Method
			f.URL = mutated.URLString()
			f.Payload = header + ": " + value
			f.CWE = "CWE-290"
			f.References = []string{
				"https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
				"https://cwe.mitre.org/data/definitions/290.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				"the endpoint refused this request with " + statusWord(t.Response.Status) +
					" and answered it once " + header + " named " + value,
				"the restriction is applied to the address the caller claims, so an address the " +
					"caller can write is as good as one it has",
			}
			f.Evidence.Diff = string(t.Response.Body)[:min(len(t.Response.Body), 120)] + "\n-->\n" +
				string(response.Body)[:min(len(response.Body), 200)]
			return []*finding.Finding{f}
		}
	}
	return nil
}

// statusWord names a refusal for the evidence sentence.
func statusWord(status int) string {
	switch status {
	case 401:
		return "401 Unauthorized"
	case 403:
		return "403 Forbidden"
	}
	return "a refusal"
}
