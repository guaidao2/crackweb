package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// storedSeeds are chosen to be inert where they are written and active where
// they are read, which is what makes a stored flaw different from a reflected
// one: the request that carries the payload renders nothing dangerous.
var storedSeeds = []string{
	"<script>alert(document.domain)</script>",
	"<img src=x onerror=alert(document.domain)>",
	"<svg/onload=alert(document.domain)>",
	`"><script>alert(document.domain)</script>`,
	`'><img src=x onerror=alert(document.domain)>`,
}

// xssStored detects a payload that is saved by one request and executed by the
// next.
//
// The check writes the payload with the request a user would submit, then fetches
// the same location again as a reader would. If the value survived storage and
// came back parsed as markup, the page now runs what was stored — which is the
// whole of the flaw. Nothing about this needs the write and the read to be
// different endpoints: a guestbook, a comment field and a profile form all show
// the value back on the page they were posted from, and those are the cases this
// covers.
//
// Only writes are tested, because only a write stores anything, and the payload
// has to be one the page did not already contain — a page that ships
// `<script>alert(...)</script>` as an example is not a page that was injected.
type xssStored struct{}

func (xssStored) ID() string                 { return "xss-stored" }
func (xssStored) TitleKey() i18n.Key         { return i18n.KeyCheckXSSStoredTitle }
func (xssStored) DescriptionKey() i18n.Key   { return i18n.KeyCheckXSSStoredDesc }
func (xssStored) RemediationKey() i18n.Key   { return i18n.KeyCheckXSSStoredFix }
func (xssStored) Severity() finding.Severity { return finding.SeverityHigh }
func (xssStored) Tags() []string {
	return []string{"active", "injection", "xss", "stored", "owasp-top10"}
}
func (xssStored) Passive() bool { return false }

func (xssStored) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Param == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// Only a request that stores something can be the write half.
	if t.Request.IsSafeMethod() {
		return nil
	}
	// A page that already contains the marker cannot be used to detect it.
	if ct := t.Response.ContentType(); ct != "text/html" && ct != "application/xhtml+xml" && ct != "" {
		return nil
	}

	baseline := string(t.Response.Body)
	c.ProbeWAF(ctx, t)

	// The read is a GET of the location the write went to.
	read, err := httpmsg.NewRequest("GET", t.Request.URLString())
	if err != nil {
		return nil
	}

	var (
		stored  string
		context string
	)
	attempt, err := c.SendVariants(ctx, t, payload.XSS, "xss-stored", storedSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool {
			// A write that fails is not a write.
			if resp == nil || resp.Status >= 400 {
				return false
			}
			// Read it back.
			page, err := c.Do(ctx, read)
			if err != nil || page == nil {
				return false
			}
			body := string(page.Body)
			candidate := wireDecoded(variant.Value)
			if candidate == "" || !strings.Contains(body, candidate) {
				return false
			}
			// It has to be new to the page, and it has to have arrived somewhere
			// a browser would parse it as markup.
			if strings.Contains(baseline, candidate) || !executableContext(body, candidate) {
				return false
			}
			stored = candidate
			context = describeContext(body, candidate)
			return true
		})
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(xssStored{}, t,
		i18n.KeyCheckXSSStoredTitle, i18n.KeyCheckXSSStoredDesc, i18n.KeyCheckXSSStoredFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-79"
	f.References = []string{
		"https://owasp.org/www-community/attacks/xss/",
		"https://cwe.mitre.org/data/definitions/79.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate([]byte(attempt.Response.Body), 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"the value stored by " + t.Request.Method + " " + t.Request.URLString() +
			" came back as markup on the next read: " + stored,
		"landed " + context,
		variantNote(c, attempt),
	}
	return []*finding.Finding{f}
}
