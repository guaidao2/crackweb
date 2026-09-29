package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// cachePoisoning reports a response that can be poisoned through a request header.
//
// A cache decides what to keep under a key, and the key is usually the URL. Every header
// the application reads while building that response is therefore shared by everyone who
// asks for the URL: the value one caller sends is written into the copy the rest receive.
//
// The second request is what makes this a finding. A header reflected into the body is a
// reflection, which is a different problem with a much smaller blast radius. What turns it
// into poisoning is a request that never sent the header and is handed the value anyway —
// which can only have come from a stored copy.
//
// This is opt-in. Proving the point means writing into a shared cache on purpose, and the
// entry stays there until it expires. Against a host you do not own, that is an incident,
// not a test.
type cachePoisoning struct{}

func (cachePoisoning) ID() string { return "cache-poisoning" }
func (cachePoisoning) TitleKey() i18n.Key {
	return i18n.KeyCheckCachePoisonTitle
}
func (cachePoisoning) DescriptionKey() i18n.Key {
	return i18n.KeyCheckCachePoisonDesc
}
func (cachePoisoning) RemediationKey() i18n.Key {
	return i18n.KeyCheckCachePoisonFix
}
func (cachePoisoning) Severity() finding.Severity { return finding.SeverityHigh }
func (cachePoisoning) Tags() []string {
	return []string{"active", "cache", "injection", "misconfiguration"}
}
func (cachePoisoning) Passive() bool { return false }

// IsRequestLevel marks this as a check about the endpoint rather than about a parameter:
// the carrier is a header, and a page with no parameters at all is where this matters most.
func (cachePoisoning) IsRequestLevel() bool { return true }

// IsUnsafe marks this as a check that changes something beyond the request it was given.
// The poisoned entry is left in the cache for whoever asks for that URL next.
func (cachePoisoning) IsUnsafe() bool { return true }

// poisonCanary is a host that cannot resolve. Its appearance in a response that never
// carried it cannot be a coincidence.
const poisonCanary = "crackweb-cache-poison.invalid"

// poisonHeaders are the fields a cache commonly leaves out of its key while the application
// still reads them: the ones a proxy sets, and the ones frameworks trust in its place.
var poisonHeaders = []string{
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"X-Host",
	"X-Forwarded-Scheme",
	"X-Original-URL",
	"X-Rewrite-URL",
}

func (cachePoisoning) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil || t.Request.URL == nil {
		return nil
	}
	// Only a response a cache would keep is worth poisoning: a 4xx is not stored, and a
	// method other than GET is not cached by default.
	if t.Request.Method != "GET" || t.Response.Status >= 400 || len(t.Response.Body) == 0 {
		return nil
	}
	// A page that already mentions the canary cannot be evidence of anything.
	if strings.Contains(scanText(t.Response.Body), poisonCanary) {
		return nil
	}

	for _, header := range poisonHeaders {
		// Each attempt goes to a URL no cache has a copy of yet, and each header gets its
		// own: the buster keeps the request from reading whatever was stored earlier — the
		// scanner's own baseline, most likely — and keeps one attempt from filling the entry
		// the next one needs to write.
		target := t.Request.Clone()
		target.URL.RawQuery = appendQuery(target.URL.RawQuery, "cb", cacheBuster())
		clean := target.URLString()

		poisoned := target.Clone()
		poisoned.Header.Set(header, poisonCanary)

		echoed, err := c.Do(ctx, poisoned)
		if err != nil || echoed == nil || !strings.Contains(scanText(echoed.Body), poisonCanary) {
			// The header does not reach the response, so there is nothing for a cache to
			// store.
			continue
		}

		// The request that decides it: the same URL, without the header.
		stored, err := c.Do(ctx, target)
		if err != nil || stored == nil || !strings.Contains(scanText(stored.Body), poisonCanary) {
			continue
		}

		f := checks.NewFinding(cachePoisoning{}, t,
			i18n.KeyCheckCachePoisonTitle, i18n.KeyCheckCachePoisonDesc, i18n.KeyCheckCachePoisonFix)
		f.Severity = finding.SeverityHigh
		// Certain: a request that never sent the header was handed the value, and the only
		// way that happens is a stored copy.
		f.Confidence = finding.ConfidenceCertain
		f.CWE = "CWE-349"
		f.DedupHostOnly = true
		f.DedupExtra = header
		f.Payload = header + ": " + poisonCanary
		f.References = []string{
			"https://portswigger.net/web-security/web-cache-poisoning",
			"https://cwe.mitre.org/data/definitions/349.html",
		}
		f.Evidence.Request = poisoned.Raw()
		f.Evidence.Response = truncate(stored.Raw(), 8192)
		f.Evidence.Baseline = truncate(t.Response.Raw(), 4096)
		f.Evidence.Matches = []string{c.Bundle.T(i18n.KeyEvidenceCache, header)}
		f.Evidence.Diff = "the poisoned URL is " + clean
		return []*finding.Finding{f}
	}
	return nil
}

// appendQuery adds a parameter to a query string, keeping what is already there.
func appendQuery(raw, name, value string) string {
	if raw == "" {
		return name + "=" + value
	}
	return raw + "&" + name + "=" + value
}

// cacheBuster returns a value no cache has an entry for.
func cacheBuster() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "crackwebcachebuster"
	}
	return hex.EncodeToString(raw[:])
}
