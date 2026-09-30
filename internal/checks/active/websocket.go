package active

import (
	"context"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// webSocketOrigin reports a WebSocket endpoint that upgrades for any origin.
//
// The reason this matters is the one thing a WebSocket handshake does not do: it is not subject
// to the same-origin policy. A page on another site opens a socket to this endpoint, the browser
// attaches the session cookie exactly as it would for a same-site page, and the application sees
// a request it is entitled to trust. Whether that is worth anything depends on what the endpoint
// carries, which this scan cannot know — which is why the severity is low and the evidence says
// what was done rather than what follows.
//
// Two things keep this from reporting every socket on the internet. The request has to look like
// it is being made by somebody with a session — a socket that authenticates nobody is not worth
// hijacking — and the endpoint has to answer the upgrade as a WebSocket, with the acceptance
// header, rather than merely answering 101 to anything.
type webSocketOrigin struct{}

func (webSocketOrigin) ID() string                 { return "websocket-origin" }
func (webSocketOrigin) TitleKey() i18n.Key         { return i18n.KeyCheckWebSocketTitle }
func (webSocketOrigin) DescriptionKey() i18n.Key   { return i18n.KeyCheckWebSocketDesc }
func (webSocketOrigin) RemediationKey() i18n.Key   { return i18n.KeyCheckWebSocketFix }
func (webSocketOrigin) Severity() finding.Severity { return finding.SeverityLow }
func (webSocketOrigin) Tags() []string {
	return []string{"active", "websocket", "access-control", "owasp-top10"}
}
func (webSocketOrigin) Passive() bool { return false }

// IsRequestLevel marks this as a check about the endpoint rather than about one parameter.
func (webSocketOrigin) IsRequestLevel() bool { return true }

// webSocketOriginProbe is an origin this application has no reason to accept. RFC 6455 uses it
// in its own examples, so a server that recognises the header treats it as any other origin.
const webSocketOriginProbe = "https://crackweb-ws.example"

// webSocketOriginHandshake is the opening key of a WebSocket handshake. The value is the one the
// RFC uses in its example: sixteen bytes, base64, and nothing about it is special.
const webSocketOriginHandshake = "dGhlIHNhbXBsZSBub25jZQ=="

func (webSocketOrigin) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// A socket that authenticates nobody is not worth hijacking: without a session to ride on,
	// another origin has nothing to gain.
	if t.Request.Header.Get("Cookie") == "" && t.Request.Header.Get("Authorization") == "" {
		return nil
	}
	// Something that is already a socket, or already refused, is not the baseline this needs.
	if !t.Request.IsSafeMethod() || t.Response.Status >= 400 {
		return nil
	}

	// Every origin a correct check refuses, because the mistake being looked for is a check that
	// is not a comparison: the same list the cross-origin check works from, since a policy that
	// matches a substring does it the same way in either answer. The plain name is tried first,
	// so the common case — a socket that checks nothing — costs one request.
	first, origin := "", ""
	var attempt *httpmsg.Request
	var response *httpmsg.Response
	for _, variant := range originVariants("crackweb-ws.example", t.Request.Hostname()) {
		if first == "" {
			first = variant
		}
		handshake := webSocketHandshake(t, variant)
		resp, err := c.Do(ctx, handshake)
		if err != nil || resp == nil {
			continue
		}
		if resp.Status != 101 || resp.Header.Get("Sec-WebSocket-Accept") == "" {
			continue
		}
		attempt, response, origin = handshake, resp, variant
		break
	}
	if attempt == nil || response == nil {
		return nil
	}

	f := checks.NewFinding(webSocketOrigin{}, t,
		i18n.KeyCheckWebSocketTitle, i18n.KeyCheckWebSocketDesc, i18n.KeyCheckWebSocketFix)
	f.Severity = finding.SeverityLow
	// Firm: the handshake demonstrably happened from an origin the application does not serve.
	// What the socket carries afterwards is not something this request can observe.
	f.Confidence = finding.ConfidenceFirm
	f.Method = attempt.Method
	f.URL = t.Request.URLString()
	f.Payload = "Origin: " + origin
	f.CWE = "CWE-1385"
	f.DedupHostOnly = true
	f.References = []string{
		"https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
		"https://cwe.mitre.org/data/definitions/1385.html",
	}
	f.Evidence.Request = attempt.Raw()
	f.Evidence.Response = truncate(response.Body, 2048)
	f.Evidence.Baseline = truncate(t.Response.Body, 2048)
	detail := "an origin it does not serve (" + origin + ")"
	if origin != first {
		detail = "an origin it does not serve — " + origin + " — where the plainly foreign name " +
			"was refused, so the check is matching a substring rather than comparing"
	}
	f.Evidence.Matches = []string{
		"the endpoint completed a WebSocket handshake for " + detail,
		"the request carried the session the caller already had, so the socket was opened with " +
			"that session's authority",
		"a page on another site can open this socket: the handshake is not subject to the " +
			"same-origin policy, and the browser attaches the cookie",
	}
	return []*finding.Finding{f}
}

// webSocketHandshake returns a copy of the request written as a WebSocket upgrade carrying the
// given origin. An upgrade has no body, and a stale length would make it unparseable.
func webSocketHandshake(t *checks.Target, origin string) *httpmsg.Request {
	out := t.Request.Clone()
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "websocket")
	out.Header.Set("Sec-WebSocket-Version", "13")
	out.Header.Set("Sec-WebSocket-Key", webSocketOriginHandshake)
	out.Header.Set("Origin", origin)
	out.Body = nil
	out.Header.Del("Content-Length")
	return out
}
