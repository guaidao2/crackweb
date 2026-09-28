package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// secondOrderSeeds are chosen to be inert until something else consumes them.
//
// That is the defining property of a second-order bug: the payload is written
// through one request, stored, and only becomes dangerous when a different
// request reads the stored value back and puts it into a query or a template.
// The write itself looks harmless.
var secondOrderSeeds = []string{
	"1' AND 1=CONVERT(int, @@version)-- -",
	"1' OR '1'='1'-- -",
	"1' AND extractvalue(1,concat(0x7e,version()))-- -",
	"{{1999*1999}}",
	"${1999*1999}",
	"<script>alert(document.domain)</script>",
}

// secondOrderTriggerSignatures are the traces a stored value leaves when it is
// finally used unsafely.
var secondOrderTriggerSignatures = []string{
	"you have an error in your sql syntax",
	"sql syntax",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"sqlstate[",
	"microsoft ole db provider",
	"pg_query()",
	"sqlite3.operationalerror",
	"ora-0",
	"traceback (most recent call last)",
	"template syntax error",
	"internal server error",
	sstiProduct,
}

// secondOrderDetectorMaxTriggers bounds how many stored requests are replayed
// after a write. A store with hundreds of pages would otherwise turn one write
// into hundreds of reads.
const secondOrderDetectorMaxTriggers = 25

// secondOrder detects stored injection: a value that is harmless where it is
// written and dangerous where it is read.
//
// The shape of the test is dictated by the bug. A write is sent with a payload,
// then the requests already observed are replayed — because the page that reads
// the stored value is one the user already visited, not one the scanner can
// construct. Each replay is compared against the response recorded for it before
// the write, so the evidence is a change the write caused rather than a
// difference between two unrelated pages.
//
// It only runs when there is traffic to trigger with: on a single-request scan
// there is no second request to be second-order against, and inventing one would
// be guessing.
type secondOrder struct{}

func (secondOrder) ID() string                 { return "second-order-injection" }
func (secondOrder) TitleKey() i18n.Key         { return i18n.KeyCheckSecondOrderTitle }
func (secondOrder) DescriptionKey() i18n.Key   { return i18n.KeyCheckSecondOrderDesc }
func (secondOrder) RemediationKey() i18n.Key   { return i18n.KeyCheckSecondOrderFix }
func (secondOrder) Severity() finding.Severity { return finding.SeverityHigh }
func (secondOrder) Tags() []string {
	return []string{"active", "injection", "second-order", "owasp-top10"}
}
func (secondOrder) Passive() bool { return false }

func (secondOrder) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Param == nil || t.Request == nil {
		return nil
	}
	// Only a write can store something. Any method might be a write in a
	// REST-shaped application, but a GET is not one.
	if t.Request.IsSafeMethod() {
		return nil
	}

	// One observed read is enough to trigger with: the store only needs a page
	// that fetches the value back, and requiring more would skip the common
	// case of a two-request application.
	observed := c.Traffic()
	if len(observed) == 0 {
		return nil
	}

	// The requests worth replaying are the reads: they are the ones that fetch
	// the stored value back.
	triggers := make([]checks.Exchange, 0, secondOrderDetectorMaxTriggers)
	for _, exchange := range observed {
		if exchange.Request == nil || exchange.Response == nil {
			continue
		}
		if !exchange.Request.IsSafeMethod() {
			continue
		}
		triggers = append(triggers, exchange)
		if len(triggers) >= secondOrderDetectorMaxTriggers {
			break
		}
	}
	if len(triggers) == 0 {
		return nil
	}

	c.ProbeWAF(ctx, t)

	for _, seed := range secondOrderSeeds {
		// Step one: store the payload.
		if _, _, err := c.InjectEncoded(ctx, t, seed, checks.EncodeURL); err != nil {
			continue
		}

		// Step two: read everything back and see whether the stored value did
		// something on the way out.
		for _, trigger := range triggers {
			response, err := c.Do(ctx, trigger.Request)
			if err != nil || response == nil {
				continue
			}
			// A stored value is only responsible for a change it caused, so the
			// comparison is against what this request returned before the write.
			signature := firstNewSignature(
				strings.ToLower(string(response.Body)),
				strings.ToLower(string(trigger.Response.Body)),
				secondOrderTriggerSignatures,
			)
			if signature == "" {
				continue
			}

			f := checks.NewFinding(secondOrder{}, t,
				i18n.KeyCheckSecondOrderTitle, i18n.KeyCheckSecondOrderDesc, i18n.KeyCheckSecondOrderFix)
			f.Severity = finding.SeverityHigh
			// Firm rather than certain: the payload is demonstrably being used
			// unsafely, but which stored field carried it is left to the reader.
			f.Confidence = finding.ConfidenceFirm
			f.Payload = seed
			f.CWE = "CWE-89"
			f.References = []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
				"https://cwe.mitre.org/data/definitions/89.html",
			}
			f.Evidence.Request = trigger.Request.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(trigger.Response.Body, 4096)
			f.Evidence.Matches = []string{
				"the value stored by " + t.Request.Method + " " + t.Request.URLString() +
					" changed what " + trigger.Request.Method + " " + trigger.Request.URLString() + " returned",
				signature,
			}
			f.Evidence.Diff = extractAround(string(response.Body), signature, 240)
			return []*finding.Finding{f}
		}
	}
	return nil
}
