package checks

import (
	"context"
	"time"

	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/payload"
	"github.com/guaidao2/crackweb/internal/waf"
)

// Judge decides whether a response means the payload did what it was supposed
// to.
//
// It receives the variant that was actually sent, not just the response, because
// a check often has to look for the mutated form: a reflection test that always
// searched for `<script>` would miss the `<ScRiPt>` variation that got past the
// filter, and would report nothing exactly when the evasion worked.
type Judge func(req *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool

// assumeWAFGenerations is how far the walk goes on the assumption alone, with no evidence
// that anything is filtering.
//
// Two, not one, and not by guesswork: the first generation spends its whole budget on
// structural rewrites, so the encodings are reached only in the second — and a structural
// rewrite wrapped in an encoding is the combination that defeats a WAF which normalises
// once and matches once. The encoding gets past the normaliser, the rewrite gets past the
// rule. Stopping at one generation would send the half that does not work.
const assumeWAFGenerations = 2

// Attempt is one payload that got through and was judged.
type Attempt struct {
	// Request is what was sent, with the payload in place.
	Request *httpmsg.Request
	// Response is what came back.
	Response *httpmsg.Response
	// Variant records the payload string and which transformations produced it,
	// which is what makes a finding explainable and reproducible.
	Variant payload.Variant
	// Blocked records that the target's WAF refused this attempt. A blocked
	// attempt is never used as a finding, but it is what drives escalation.
	Blocked bool
	// Interactions holds the out-of-band callbacks that proved this attempt,
	// when the check relies on them. It is empty for checks that judge from the
	// response alone.
	Interactions []Interaction
	// Polluted records that the payload was sent as a second occurrence of the
	// parameter rather than as its value. It is what distinguishes a finding
	// that defeated a filter by disagreeing about parsing from one that simply
	// got through.
	Polluted bool
}

// SendVariants walks a payload's mutation generations against a target and
// returns the first attempt the judge accepts.
//
// The escalation rule is what keeps this affordable. Generation 0 is the plain
// payload, so an unprotected target costs one request per payload. Only if
// *every* payload in a generation is refused does the next generation run — and
// when a generation gets through, that fact is remembered for the target, so
// later checks start where the last one succeeded instead of rediscovering the
// WAF from scratch.
//
// A generation in which some payloads pass but none is accepted ends the walk:
// the target is answering, so a heavier mutation would only spend requests on a
// target that is not actually protected.
func (c *Context) SendVariants(
	ctx context.Context,
	t *Target,
	kind payload.Kind,
	checkID string,
	seeds []string,
	judge Judge,
) (*Attempt, error) {
	return c.SendVariantsTimed(ctx, t, kind, checkID, seeds, judge, 0)
}

// SendVariantsTimed is SendVariants with a deadline for each request it sends.
func (c *Context) SendVariantsTimed(
	ctx context.Context,
	t *Target,
	kind payload.Kind,
	checkID string,
	seeds []string,
	judge Judge,
	timeout time.Duration,
) (*Attempt, error) {
	if t == nil || t.Request == nil || t.Param == nil || len(seeds) == 0 {
		return nil, nil
	}

	host := t.Request.Hostname()
	generations := payload.Generations(kind, seeds)
	if len(generations) == 0 {
		return nil, nil
	}

	start := c.WAF.Floor(host, checkID)

	for generation := start; generation < len(generations); generation++ {
		variants := generations[generation]
		if len(variants) == 0 {
			continue
		}

		// Inside a generation every payload runs: stopping at the first refusal
		// would mistake one filtered payload for a filtered target, and stopping
		// at the first acceptance would miss the payload that actually works.
		//
		// What matters is whether *anything* was refused. A target that filtered
		// one payload and let another through is protected — it just has rules
		// that do not cover everything — so the next generation is worth trying.
		// A target that refused nothing is not filtering at all, and escalating
		// would only spend requests.
		blockedSomething := false

		for _, variant := range variants {
			attempt, err := c.tryVariantTimed(ctx, t, variant, timeout)
			if err != nil || attempt == nil {
				continue
			}
			if attempt.Blocked {
				// Before escalating the payload's wording, try the cheapest
				// trick there is: send it twice and let the layers disagree
				// about which occurrence counts.
				if polluted, pollErr := c.tryVariantHPP(ctx, t, variant); pollErr == nil &&
					polluted != nil && !polluted.Blocked &&
					judge(polluted.Request, polluted.Response, variant) {
					c.WAF.Raise(host, checkID, generation)
					return polluted, nil
				}
				blockedSomething = true
				continue
			}

			if judge(attempt.Request, attempt.Response, variant) {
				attempt.Variant = variant
				c.WAF.Raise(host, checkID, generation)
				return attempt, nil
			}
		}

		if !blockedSomething {
			// Nothing was refused, so the target is not filtering, and mutation would only
			// spend requests on a target that already answered.
			//
			// Unless the caller asked for the assumption to be made anyway. A target that
			// rewrites a payload instead of refusing it gives this loop no evidence to act
			// on, so under --assume-waf the first generation of mutations is tried even
			// though nothing was refused. The generations after it still need that
			// evidence: the assumption buys one round, not a blank cheque.
			if !(c.AssumeWAF && generation+1 < len(generations) && generation < assumeWAFGenerations) {
				return nil, nil
			}
		}
		// Something was refused: escalate and try a stealthier wording.
	}

	return nil, nil
}

// EncodingForVariant decides how a variant has to be encoded for transport.
//
// Exported because every path that sends a payload must agree on it: a variant
// whose last transformation already produced transport form must not be encoded
// again, and everything else needs exactly one round. A measurement helper that
// made its own choice would send something different from what was judged —
// which is silently worse than a wrong answer, because it looks like a target
// that is not vulnerable.
func EncodingForVariant(variant payload.Variant) Encoding {
	if variant.NeedsTransportEncoding() {
		return EncodeURL
	}
	return EncodeNone
}

// tryVariant sends one variant and reports whether the target refused it.
func (c *Context) tryVariant(ctx context.Context, t *Target, variant payload.Variant) (*Attempt, error) {
	return c.tryVariantTimed(ctx, t, variant, 0)
}

// tryVariantTimed sends one variant with a deadline of its own.
func (c *Context) tryVariantTimed(ctx context.Context, t *Target, variant payload.Variant, timeout time.Duration) (*Attempt, error) {
	encoding := EncodingForVariant(variant)

	request, response, err := c.InjectEncodedTimed(ctx, t, variant.Value, encoding, timeout)
	if err != nil {
		return nil, err
	}
	if request == nil || response == nil {
		return nil, nil
	}

	attempt := &Attempt{Request: request, Response: response, Variant: variant}
	// IsBlocked is safe on a nil state and still performs the generic check, so
	// escalation works whether or not detection was enabled.
	attempt.Blocked = c.WAF.IsBlocked(request.Hostname(), response)
	return attempt, nil
}

// ProbeEndpoints are the payloads used to decide whether a target is protected.
//
// They are the most-signatured strings in existence, chosen not to attack but
// to be recognised: any signature-based WAF refuses them, which is exactly the
// signal being looked for.
var ProbeEndpoints = []string{
	"' OR 1=1-- -",
	"<script>alert(1)</script>",
	"../../../../etc/passwd",
	"; cat /etc/passwd",
}

// ProbeWAF establishes whether a target is behind a web application firewall.
//
// It runs at most once per host, because the answer does not change per
// parameter and the probes are themselves requests. Detection is deliberately
// conservative — it needs a block status code, a vendor fingerprint or refusal
// wording — because a false positive escalates every later payload through
// extra generations for no benefit.
//
// Detection is also entirely optional: with it disabled the scanner still works
// and simply sends generation 0 until something gets through.
func (c *Context) ProbeWAF(ctx context.Context, t *Target) {
	if c.WAF == nil || t == nil || t.Request == nil || t.Param == nil {
		return
	}
	host := t.Request.Hostname()
	if !c.WAF.NeedsProbe(host) {
		return
	}

	// The baseline is the request as it stands, so the comparison is against
	// what this target does with ordinary input.
	baseline, err := c.DoWithoutSession(ctx, t.Request)
	if err != nil {
		// A target that will not answer at all cannot be probed; mark it so the
		// attempt is not repeated for every check.
		c.WAF.MarkProbed(host, "", waf.Signature{})
		return
	}

	vendor := ""
	for _, probe := range ProbeEndpoints {
		_, response, err := c.InjectEncoded(ctx, t, probe, EncodeURL)
		if err != nil || response == nil {
			continue
		}
		blocked, detected, signature := waf.Classify(baseline, response)
		if !blocked {
			continue
		}
		if detected != "" {
			vendor = detected
		}
		c.WAF.MarkProbed(host, vendor, signature)
		return
	}

	c.WAF.MarkProbed(host, "", waf.Signature{})
}
