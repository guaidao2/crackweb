package checks

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/waf"
)

// Encoding says how an injected value is encoded before it goes on the wire.
type Encoding int

// Encoding modes.
const (
	// EncodeNone sends the payload verbatim. Rarely right for a query string:
	// an unencoded space or ampersand corrupts the request.
	EncodeNone Encoding = iota
	// EncodeURL percent-encodes the payload. The server decodes it back, so the
	// target sees the same bytes while the request stays well-formed.
	EncodeURL
	// EncodeDouble encodes twice, for the layers of decoding that some
	// frameworks apply.
	EncodeDouble
)

// Context carries everything a check needs from the outside world.
type Context struct {
	// Client sends requests.
	Client *httpclient.Client
	// Bundle renders check messages in the user's language.
	Bundle *i18n.Bundle
	// OOB is the out-of-band interaction server; nil disables out-of-band
	// checks, which is a supported configuration for environments with no
	// external callbacks.
	OOB OOBProvider
	// Browser is the headless browser; nil disables the checks that need one to run the
	// page, which is a supported configuration on a machine without a browser.
	Browser Browser
	// AssumeWAF sends each payload in its first mutated form as well, whether or not a
	// firewall was detected.
	//
	// Detection works by recognising a refusal, and a modern edge frequently does not
	// refuse: it rewrites the payload and answers 200, leaving nothing in the response that
	// says it filtered anything. Against such a target the escalation rule never fires — the
	// evidence that would have prompted it is precisely what is withheld — and the payload
	// mutations, which are the part that gets through, are never sent. This is how a target
	// that filters silently is asked the second question anyway.
	AssumeWAF bool
	// Engine judges whether a response differs from its baseline.
	Engine *diff.Engine
	// Normalizer prepares response bodies for comparison.
	Normalizer *diff.Normalizer
	// Encode is the default encoding for injected values.
	Encode Encoding
	// Sessions are distinct authenticated identities, used by checks that need
	// to compare what two users can see. Fewer than two means those checks
	// cannot run, which is a supported configuration.
	Sessions []Session
	// JWTSecrets are signing keys the operator already knows: found in a config file, in a
	// bundle, in a repository. Each is tried as the key behind the tokens the target issues —
	// re-signing the token it accepted and asking whether that one is accepted too. It is an
	// online test of an offline discovery: a secret that produces a token the service takes
	// proves the identity is forgeable, which scouting a signature in a lab does not.
	JWTSecrets []string
	// WAF remembers what each target's firewall does and which payload
	// generation gets through it. A nil state means the scanner behaves as if
	// no target is protected, which is what a user gets with WAF handling
	// turned off.
	WAF *waf.State
	// OOBWait bounds how long an out-of-band check waits for a callback. Zero
	// means OOBWait's default.
	OOBWait time.Duration
	// Exchanges exposes the traffic seen so far, for checks that need to relate
	// one request to another. A check that does not need it can ignore it; a nil
	// value means the caller has no traffic store, and cross-request checks skip
	// themselves rather than guessing.
	Exchanges func() []Exchange

	// OnRequest, when set, is called with every request the checks send, just
	// before it goes out.
	//
	// It is what --verbose prints, and it lives here rather than in each check
	// because every request any check sends goes through Do. Calls arrive from the
	// checks running side by side, so an implementation that writes somewhere has
	// to serialise itself. A nil value means nothing is watched.
	OnRequest func(*httpmsg.Request)

	mu sync.Mutex

	// hostOnce remembers which host-level questions have already been asked, so a check whose
	// subject is the host answers once however many of its pages the run reaches.
	hostOnce map[string]bool
	requests int
	failures []string
}

// NewContext builds a check context, filling in the pieces a check assumes
// exist.
func NewContext(client *httpclient.Client, bundle *i18n.Bundle, engine *diff.Engine, normalizer *diff.Normalizer) *Context {
	return &Context{
		Client:     client,
		Bundle:     bundle,
		Engine:     engine,
		Normalizer: normalizer,
		Encode:     EncodeURL,
	}
}

// RequestCount returns how many requests the checks have sent, which the
// scanner reports so a user can see what a scan cost.
func (c *Context) RequestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

// Failures returns the transport errors seen so far, newest last.
//
// A check skips a payload whose request failed, which is right — there is
// nothing to compare — but it must not be silent: a target that refuses every
// second connection would otherwise look like a clean scan.
func (c *Context) Failures() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.failures))
	copy(out, c.failures)
	return out
}

// FailureCount returns how many requests failed outright.
func (c *Context) FailureCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.failures)
}

// Do sends a request and counts it.
func (c *Context) Do(ctx context.Context, req *httpmsg.Request) (*httpmsg.Response, error) {
	c.mu.Lock()
	c.requests++
	watch := c.OnRequest
	c.mu.Unlock()

	// Called outside the lock, and with the hook copied out of it: the hook
	// belongs to the caller, and holding the counter's lock across it would
	// serialise every check on whatever the hook writes.
	if watch != nil && req != nil {
		watch(req)
	}

	resp, err := c.Client.Do(ctx, req)
	if err != nil && ctx.Err() == nil {
		c.mu.Lock()
		// Bound the list: a target that is down would otherwise fill memory
		// with identical messages.
		if len(c.failures) < 50 {
			c.failures = append(c.failures, err.Error())
		}
		c.mu.Unlock()
	}
	return resp, err
}

// Exchange is one observed request and the response it produced.
//
// It is what a cross-request check reasons over: a stored value only becomes a
// second-order injection when some later request reads it back, and that
// relationship can only be seen across two exchanges.
type Exchange struct {
	Request  *httpmsg.Request
	Response *httpmsg.Response
}

// Traffic returns the observed exchanges, or nil when there is no store.
func (c *Context) Traffic() []Exchange {
	if c == nil || c.Exchanges == nil {
		return nil
	}
	return c.Exchanges()
}

// Session is one authenticated identity, expressed as the headers that carry
// it. Cookies cover most applications; the header list allows for a bearer
// token or a custom header instead.
type Session struct {
	// Label names the identity for reports, e.g. "user-a".
	Label string
	// Headers are applied to a request to authenticate as this identity.
	Headers []httpmsg.KV
}

// authHeaders are the request fields that carry an identity. They are stripped
// before a session is applied, so that a session replaces the request's own
// credentials rather than being appended to them.
var authHeaders = []string{"Cookie", "Authorization", "X-Api-Key", "X-Auth-Token"}

// DoWithSession sends a request as a specific identity.
func (c *Context) DoWithSession(ctx context.Context, req *httpmsg.Request, session Session) (*httpmsg.Response, error) {
	clone := withoutAuth(req)
	for _, header := range session.Headers {
		clone.Header.Set(header.Name, header.Value)
	}
	return c.Do(ctx, clone)
}

// DoWithoutSession sends a request with every identity removed, which is how a
// check establishes whether an object is protected at all.
func (c *Context) DoWithoutSession(ctx context.Context, req *httpmsg.Request) (*httpmsg.Response, error) {
	return c.Do(ctx, withoutAuth(req))
}

// withoutAuth returns a copy of a request with its credentials stripped.
func withoutAuth(req *httpmsg.Request) *httpmsg.Request {
	clone := req.Clone()
	for _, name := range authHeaders {
		clone.Header.Del(name)
	}
	return clone
}

// HostOnce reports whether a host-level question is being asked for the first time.
//
// A check whose subject is the host rather than a page — which paths a server publishes, what a
// socket accepts, which addresses it answers on — gives the same answer whichever page it was
// dispatched against, and a crawl hands it the same host once per discovered URL. Asking again
// spends the whole budget repeating one question, and the answer cannot have changed between
// two pages of the same site.
//
// The key names the question, so one host can be asked several different things exactly once
// each. The first caller for a given host and key gets true and should do the work; every later
// caller gets false and should do nothing.
func (c *Context) HostOnce(host, key string) bool {
	if host == "" || key == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hostOnce == nil {
		c.hostOnce = map[string]bool{}
	}
	composite := host + "\x00" + key
	if c.hostOnce[composite] {
		return false
	}
	c.hostOnce[composite] = true
	return true
}

// ErrNoParameter is returned when a check tries to inject into a target that
// has no parameter.
var ErrNoParameter = errors.New("checks: target has no parameter to inject into")

// Inject rewrites the target's parameter with payload and sends the request.
// It returns the mutated request as well as the response, so the finding can
// carry the exact bytes that triggered it.
func (c *Context) Inject(ctx context.Context, t *Target, payload string) (*httpmsg.Request, *httpmsg.Response, error) {
	return c.InjectEncoded(ctx, t, payload, c.Encode)
}

// InjectEncoded is Inject with an explicit encoding, for checks that need to
// control exactly what goes on the wire.
func (c *Context) InjectEncoded(ctx context.Context, t *Target, payload string, enc Encoding) (*httpmsg.Request, *httpmsg.Response, error) {
	return c.InjectEncodedTimed(ctx, t, payload, enc, 0)
}

// InjectEncodedTimed is InjectEncoded with a deadline for this request.
//
// A check whose method is to make the server wait needs one: the payload asks
// for a pause of several seconds, and a deadline set for ordinary requests ends
// the exchange before the answer arrives — which looks exactly like a target
// that did not pause, so the finding is silently lost. The budget is passed per
// call rather than set on the context because a target is shared by the checks
// running concurrently against it.
func (c *Context) InjectEncodedTimed(ctx context.Context, t *Target, payload string, enc Encoding, timeout time.Duration) (*httpmsg.Request, *httpmsg.Response, error) {
	if t == nil || t.Request == nil || t.Param == nil {
		return nil, nil, ErrNoParameter
	}
	mutated, err := Mutate(t.Request, *t.Param, payload, enc)
	if err != nil {
		return nil, nil, err
	}
	mutated.Timeout = timeout
	resp, err := c.Do(ctx, mutated)
	return mutated, resp, err
}

// InjectNamed sends the request with the parameter renamed as well as its value
// replaced. It is the transport half of parameter-name injection: `user[$ne]` is
// a different parameter to a document-oriented framework than `user` is, and the
// parser — not the check — decides what that difference means. The name is
// encoded by the same rule the value is, so the brackets and the dollar sign
// arrive as the bytes a form would have sent.
func (c *Context) InjectNamed(ctx context.Context, t *Target, name, payload string) (*httpmsg.Request, *httpmsg.Response, error) {
	if t == nil || t.Request == nil || t.Param == nil {
		return nil, nil, ErrNoParameter
	}
	mutated, err := MutateNamed(t.Request, *t.Param, name, payload, c.Encode)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.Do(ctx, mutated)
	return mutated, resp, err
}

// Fingerprint reduces a response to a comparable fingerprint, using the
// context's normalizer.
func (c *Context) Fingerprint(resp *httpmsg.Response, echoPairs ...string) *diff.Fingerprint {
	return diff.BuildFingerprint(resp, c.Normalizer, c.Engine.Keywords, echoPairs, false)
}

// StableBaseline fetches the request twice and returns a response that can be
// trusted as a comparison point, or nil when the target is too unstable to
// compare against.
//
// The response stored on the target is not usable for this. It was captured
// during discovery — before a form was submitted, or in a different session
// state — so a difference against it may be staleness rather than the probe's
// doing, and a check that reports staleness reports it on every page. Two fresh
// requests are made instead: if they disagree with each other, no single
// comparison against this target means anything, and the check should skip
// rather than guess.
func (c *Context) StableBaseline(ctx context.Context, req *httpmsg.Request, tolerance float64) *httpmsg.Response {
	if c == nil || req == nil {
		return nil
	}
	first, err := c.Do(ctx, req)
	if err != nil || first == nil {
		return nil
	}
	second, err := c.Do(ctx, req)
	if err != nil || second == nil {
		return nil
	}
	if diff.CompareFingerprints(c.Fingerprint(first), c.Fingerprint(second)).Score < tolerance {
		return nil
	}
	return second
}

// BaselineFingerprint fingerprints the target's original response.
func (c *Context) BaselineFingerprint(t *Target, echoPairs ...string) *diff.Fingerprint {
	if t == nil {
		return nil
	}
	return c.Fingerprint(t.Response, echoPairs...)
}

// Mutate returns a copy of req with param's value replaced by payload.
//
// The mutation is done on the raw on-the-wire text rather than on a parsed
// structure, so that every other parameter — and its encoding — survives
// untouched. That fidelity is what lets a finding be reproduced exactly.
func Mutate(req *httpmsg.Request, param httpmsg.Param, payload string, enc Encoding) (*httpmsg.Request, error) {
	if req == nil {
		return nil, errors.New("checks: cannot mutate a nil request")
	}
	out := req.Clone()

	// A value that lives inside a document carried as another parameter's value is
	// rebuilt together with its envelope, so the parameter still parses when the target
	// reads it.
	if param.Wrapper != httpmsg.WrapNone {
		rewritten, ok := httpmsg.RewriteWrapped(out, param, payload)
		if !ok {
			return nil, errors.New("checks: cannot rewrite nested parameter " + param.Name)
		}
		return rewritten, nil
	}

	// A JSON document and a multipart part are written as they stand — neither is
	// percent-encoded on the wire — so they rewrite their body directly instead of going
	// through the transport encoding the caller asked for.
	switch param.In {
	case httpmsg.LocJSON, httpmsg.LocJSONBase64, httpmsg.LocMultipart, httpmsg.LocMultipartFilename:
		updated, ok := httpmsg.RewriteBody(out.Body, out.Header.Get("Content-Type"), param, payload)
		if !ok {
			return nil, errors.New("checks: cannot rewrite " + string(param.In) + " parameter " + param.Name)
		}
		out.Body = updated
		out.Header.Set("Content-Length", strconv.Itoa(len(updated)))
		return out, nil
	}

	raw := encodeValue(payload, enc)

	switch param.In {
	case httpmsg.LocQuery:
		if out.URL == nil {
			return nil, errors.New("checks: request has no URL")
		}
		out.URL.RawQuery = replacePair(out.URL.RawQuery, param, raw)

	case httpmsg.LocBody:
		body := replacePair(string(out.Body), param, raw)
		out.Body = []byte(body)
		out.Header.Set("Content-Length", strconv.Itoa(len(body)))

	case httpmsg.LocCookie:
		cookie := replaceCookiePair(out.Header.Get("Cookie"), param, raw)
		out.Header.Set("Cookie", cookie)

	default:
		return nil, errors.New("checks: unsupported injection location " + string(param.In))
	}
	return out, nil
}

// replacePair rewrites one "name=value" pair inside an ampersand-separated
// list, matching on the raw name and skipping earlier namesakes.
// MutateNamed rewrites the parameter's name and value together.
//
// The rename is not cosmetic: to a document-oriented framework the name is the
// query, so a check that can only replace values cannot express the operator form
// at all. Only the locations whose name is written on the wire are supported —
// a name inside a JSON document is a field path, and renaming it is a different
// operation with its own rules.
func MutateNamed(req *httpmsg.Request, param httpmsg.Param, name, payload string, enc Encoding) (*httpmsg.Request, error) {
	if req == nil {
		return nil, errors.New("checks: cannot mutate a nil request")
	}
	if param.Wrapper != httpmsg.WrapNone {
		return nil, errors.New("checks: cannot rename a nested parameter")
	}
	rawName := encodeValue(name, enc)
	rawValue := encodeValue(payload, enc)

	out := req.Clone()
	switch param.In {
	case httpmsg.LocQuery:
		if out.URL == nil {
			return nil, errors.New("checks: request has no URL")
		}
		out.URL.RawQuery = replacePairNamed(out.URL.RawQuery, param, rawName, rawValue)

	case httpmsg.LocBody:
		body := replacePairNamed(string(out.Body), param, rawName, rawValue)
		out.Body = []byte(body)
		out.Header.Set("Content-Length", strconv.Itoa(len(body)))

	case httpmsg.LocCookie:
		cookie := replacePairNamed(out.Header.Get("Cookie"), param, rawName, rawValue)
		out.Header.Set("Cookie", cookie)

	default:
		return nil, errors.New("checks: unsupported rename location " + string(param.In))
	}
	return out, nil
}

// replacePairNamed is replacePair with a new name as well as a new value.
func replacePairNamed(raw string, param httpmsg.Param, newRawName, newRawValue string) string {
	if raw == "" {
		return newRawName + "=" + newRawValue
	}
	parts := strings.Split(raw, "&")
	seen := 0
	for i, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		if name != param.RawName {
			continue
		}
		if seen == param.Occurrence {
			parts[i] = newRawName + "=" + newRawValue
			return strings.Join(parts, "&")
		}
		seen++
	}
	return raw + "&" + newRawName + "=" + newRawValue
}

func replacePair(raw string, param httpmsg.Param, newRawValue string) string {
	if raw == "" {
		return param.RawName + "=" + newRawValue
	}
	parts := strings.Split(raw, "&")
	seen := 0
	for i, part := range parts {
		name, _, _ := strings.Cut(part, "=")
		if name != param.RawName {
			continue
		}
		if seen == param.Occurrence {
			parts[i] = name + "=" + newRawValue
			return strings.Join(parts, "&")
		}
		seen++
	}
	// The parameter was not found, which can happen when the request was
	// rewritten in between. Appending keeps the injection meaningful rather
	// than silently testing nothing.
	return raw + "&" + param.RawName + "=" + newRawValue
}

// replaceCookiePair rewrites one cookie value inside a Cookie header.
func replaceCookiePair(header string, param httpmsg.Param, newRawValue string) string {
	if header == "" {
		return param.RawName + "=" + newRawValue
	}
	parts := strings.Split(header, ";")
	seen := 0
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		name, _, _ := strings.Cut(trimmed, "=")
		if strings.TrimSpace(name) != param.RawName {
			continue
		}
		if seen == param.Occurrence {
			parts[i] = " " + param.RawName + "=" + newRawValue
			return strings.TrimSpace(strings.Join(parts, ";"))
		}
		seen++
	}
	return header + "; " + param.RawName + "=" + newRawValue
}

// encodeValue applies the requested encoding to a payload.
func encodeValue(payload string, enc Encoding) string {
	switch enc {
	case EncodeURL:
		return url.QueryEscape(payload)
	case EncodeDouble:
		return url.QueryEscape(url.QueryEscape(payload))
	default:
		return payload
	}
}

// NewFinding builds a finding from a check's declaration, filling in the parts
// every check would otherwise repeat.
func NewFinding(c Check, t *Target, title, description, remediation i18n.Key) *finding.Finding {
	f := &finding.Finding{
		CheckID:        c.ID(),
		TitleKey:       title,
		DescriptionKey: description,
		RemediationKey: remediation,
		Severity:       c.Severity(),
		Confidence:     finding.ConfidenceFirm,
		Tags:           c.Tags(),
	}
	if t != nil && t.Request != nil {
		f.Method = t.Request.Method
		f.URL = t.Request.URLString()
		f.Evidence.Request = t.Request.Raw()
	}
	if t != nil && t.Param != nil {
		f.Param = string(t.Param.In) + ":" + t.Param.Name
	}
	return f
}
