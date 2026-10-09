// Package httpclient is crackweb's request-sending engine: one place that knows
// about timeouts, redirects, proxies, retries, rate limiting and connection
// reuse, so the scanner, the crawler and the proxy all behave the same way and
// a target sees one consistent client.
package httpclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/version"
)

// DefaultMaxBody bounds how much of a response is read, so that a single large
// download cannot exhaust memory during a scan.
const DefaultMaxBody = 8 << 20 // 8 MiB

// Options configures a Client.
type Options struct {
	// Timeout is the per-request deadline.
	Timeout time.Duration
	// FollowRedirects enables following 3xx responses. Leaving it off keeps the
	// Location header visible, which is what open-redirect checks want.
	FollowRedirects bool
	// MaxRedirects bounds the redirect chain when following.
	MaxRedirects int
	// Proxy is an upstream proxy URL (http:// or socks5://) for outgoing
	// requests.
	Proxy string
	// Insecure skips TLS certificate verification.
	Insecure bool
	// UserAgent is sent on every request; RandomUA picks a random one instead.
	UserAgent string
	RandomUA  bool
	// Retry is how many extra attempts a failed request gets.
	Retry int
	// Rate caps requests per second; 0 means unlimited.
	Rate float64
	// Burst is the token-bucket depth for the rate limiter.
	Burst float64
	// MaxBody bounds the response size read into memory.
	MaxBody int64
	// MaxConnsPerHost bounds concurrent connections per host.
	MaxConnsPerHost int
	// DisableKeepAlives turns off connection reuse, which helps against servers
	// that misbehave on reused connections.
	DisableKeepAlives bool
	// Credentials are headers sent with every request, which is how the scanner
	// is given an identity.
	//
	// This is the difference between scanning a login page and scanning what is
	// behind it: without it the crawler can only reach what an anonymous visitor
	// can reach, and every active check is aimed at the anonymous view. Setting
	// them here rather than at each call site means checks that build their own
	// requests carry the identity too.
	Credentials []Credential
}

// Credential is one header applied to outgoing requests.
type Credential struct {
	// Name is the header name, e.g. "Cookie" or "Authorization".
	Name string
	// Value is the header value.
	Value string
}

// Client sends requests and normalises the results into httpmsg types.
type Client struct {
	opts    Options
	hg      *http.Client
	limiter *limiter
	noGzip  bool
}

// New builds a client from options, filling in defaults.
func New(opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = DefaultMaxBody
	}
	if opts.Burst <= 0 {
		opts.Burst = 1
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     opts.DisableKeepAlives,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
	}
	if opts.MaxConnsPerHost > 0 {
		transport.MaxConnsPerHost = opts.MaxConnsPerHost
	}
	if opts.Proxy != "" {
		proxyURL, err := parseProxy(opts.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	c := &Client{opts: opts}
	// The deadline is applied per request, from Request.Timeout or this default,
	// rather than set on the client. http.Client.Timeout cannot be narrowed or
	// widened for a single exchange, so a check that asks the server to wait
	// would be cut off by it with no way to say otherwise — and the failure
	// looks exactly like a target that did not wait.
	c.hg = &http.Client{
		Transport: transport,
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !opts.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= opts.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", opts.MaxRedirects)
			}
			return nil
		},
	}
	c.limiter = newLimiter(opts.Rate, opts.Burst)
	return c, nil
}

// parseProxy accepts http, https and socks5 proxy URLs.
func parseProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q: want http, https or socks5", u.Scheme)
	}
	return u, nil
}

// RedirectPolicy describes how a client treats 3xx responses.
//
// A nuclei template names its own redirect behaviour per request ("redirects",
// "host-redirects", "protocol-redirects", "max-redirects"), so it cannot live on
// the scan's client: one check wants the Location header a redirect carries and
// the next wants the page behind it.
type RedirectPolicy struct {
	// Follow enables following redirects at all. With it off the 3xx response
	// is the response, which is what a template matching on a 302 needs.
	Follow bool
	// SameHost follows only redirects that stay on the original host.
	SameHost bool
	// SameScheme follows only redirects that keep the scheme, so a target that
	// answers an http:// request with an https:// location is not followed.
	SameScheme bool
	// Max bounds the chain; zero means the client's own limit.
	Max int
}

// Derived returns a client that shares this client's transport, rate limiter and
// credentials, with its own redirect policy and — when asked for — its own
// cookie jar.
//
// Sharing the transport is the point: the derived client queues behind the same
// rate limiter and carries the same identity, so a template's requests are
// counted and authenticated like every other request the scan makes. What
// changes is only where a response is allowed to come from.
func (c *Client) Derived(policy RedirectPolicy, jar http.CookieJar, useJar bool) *Client {
	if c == nil {
		return nil
	}

	max := policy.Max
	if max <= 0 {
		max = c.opts.MaxRedirects
	}
	if max <= 0 {
		max = 10
	}

	// http.Client.Timeout stays 0 for the same reason it does on the scan's
	// client: the deadline belongs to the request.
	derived := &Client{opts: c.opts, limiter: c.limiter, noGzip: c.noGzip}
	httpClient := &http.Client{
		Transport:     c.hg.Transport,
		Timeout:       0,
		CheckRedirect: redirectHook(policy, max),
	}
	if useJar && jar != nil {
		httpClient.Jar = jar
	}
	derived.hg = httpClient
	return derived
}

// redirectHook turns a policy into net/http's redirect decision.
func redirectHook(policy RedirectPolicy, max int) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !policy.Follow {
			return http.ErrUseLastResponse
		}
		if len(via) >= max {
			return fmt.Errorf("stopped after %d redirects", max)
		}
		if len(via) == 0 {
			return nil
		}
		if policy.SameHost && req.URL.Hostname() != via[0].URL.Hostname() {
			return http.ErrUseLastResponse
		}
		if policy.SameScheme && req.URL.Scheme != via[0].URL.Scheme {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// Do sends a request and returns the response. A transport-level failure is
// returned as an error; an HTTP error status is a perfectly good response and
// comes back as one.
func (c *Client) Do(ctx context.Context, req *httpmsg.Request) (*httpmsg.Response, error) {
	return c.do(ctx, req, false)
}

// DoAnonymous sends a request without the configured credentials.
//
// It exists for the control a check runs against its own finding: to show that a resource is
// protected, the same request has to be sent with the identity removed. Deleting the header
// and calling Do is not enough — Do puts it back, because a configured credential is a default
// for requests that do not name one. The result is a control that authenticates, succeeds, and
// quietly cancels the finding it was meant to support.
func (c *Client) DoAnonymous(ctx context.Context, req *httpmsg.Request) (*httpmsg.Response, error) {
	return c.do(ctx, req, true)
}

func (c *Client) do(ctx context.Context, req *httpmsg.Request, anonymous bool) (*httpmsg.Response, error) {
	var lastErr error
	attempts := c.opts.Retry + 1

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Back off a little, so a struggling server gets breathing room.
			select {
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		resp, err := c.attempt(ctx, req, anonymous)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retryable(err) {
			break
		}
	}
	return nil, lastErr
}

// attempt performs a single request/response exchange.
func (c *Client) attempt(ctx context.Context, req *httpmsg.Request, anonymous bool) (*httpmsg.Response, error) {
	// A request may carry its own deadline; see httpmsg.Request.Timeout. It is
	// applied here rather than in buildRequest so the cancel can be deferred
	// until the response has been read — releasing it earlier would cut the
	// body off, and never releasing it would leak the timer.
	// One place decides the deadline: the request's own if it has one, otherwise
	// the client's default.
	deadline := req.Timeout
	if deadline <= 0 {
		deadline = c.opts.Timeout
	}
	if deadline > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deadline)
		defer cancel()
	}

	httpReq, err := c.buildRequest(ctx, req, anonymous)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	raw, err := c.hg.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer raw.Body.Close()

	// A response that carries no body by definition has nothing to read, and reading it means
	// waiting on a stream that never ends. An informational status is the one that matters: a
	// WebSocket upgrade answers 101 and then keeps the connection open, so asking for what
	// follows the handshake hangs the scan on a request that succeeded.
	body, truncated := []byte(nil), false
	if raw.StatusCode >= 200 && raw.StatusCode != 204 && raw.StatusCode != 304 {
		body, truncated, err = readBody(raw, c.opts.MaxBody)
		if err != nil {
			return nil, err
		}
	}
	elapsed := time.Since(start)

	finalURL := ""
	if raw.Request != nil && raw.Request.URL != nil {
		finalURL = raw.Request.URL.String()
	}

	return &httpmsg.Response{
		Proto:      raw.Proto,
		Status:     raw.StatusCode,
		Reason:     strings.TrimPrefix(raw.Status, fmt.Sprintf("%d ", raw.StatusCode)),
		Header:     httpmsg.HeaderFromStd(raw.Header),
		Body:       body,
		Duration:   elapsed,
		FinalURL:   finalURL,
		Truncated:  truncated,
		RequestID:  req.ID,
		ReceivedAt: time.Now(),
	}, nil
}

// buildRequest converts a message-model request into the standard library's
// representation, preserving the Host field and adding client defaults.
func (c *Client) buildRequest(ctx context.Context, req *httpmsg.Request, anonymous bool) (*http.Request, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("httpclient: request has no URL")
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), body)
	if err != nil {
		return nil, err
	}

	// Copy the wire headers across, skipping the ones the transport owns.
	for _, field := range req.Header.All() {
		switch strings.ToLower(field.Name) {
		case "host", "content-length", "connection", "transfer-encoding":
			continue
		}
		httpReq.Header.Add(field.Name, field.Value)
	}

	// Host is a field on the request object, not a header, in net/http.
	if host := req.Header.Get("Host"); host != "" {
		httpReq.Host = host
	}

	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", c.userAgent())
	}
	if len(req.Body) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if httpReq.Header.Get("Accept") == "" {
		httpReq.Header.Set("Accept", "*/*")
	}

	// An anonymous request is exactly what it says: the credentials stay off it. That matters
	// for the control a check runs to establish whether a resource is protected at all — a
	// control that carries the credential proves the opposite of what it is for.
	if !anonymous {
		c.applyCredentials(httpReq, req)
	}

	return httpReq, nil
}

// applyCredentials adds the configured identity to an outgoing request, and to the message
// model the checks read.
//
// Both have to be written. The wire request is what proves the identity was sent; the message
// model is what the checks see, and a check that looks at the request it was handed — anything
// testing a credential, and the passive checks that report on headers — reads that one. Writing
// only the wire request means every check runs against the anonymous view while the crawl
// browses as the authenticated user: the scanner believes it is testing what is behind the
// login, and reports on the login page.
func (c *Client) applyCredentials(httpReq *http.Request, req *httpmsg.Request) {
	set := func(name, value string) {
		httpReq.Header.Set(name, value)
		if req != nil {
			req.Header.Set(name, value)
		}
	}
	for _, cred := range c.opts.Credentials {
		if cred.Name == "" || cred.Value == "" {
			continue
		}
		if strings.EqualFold(cred.Name, "Cookie") {
			// Cookies are merged rather than replaced. A request may carry its
			// own — a CSRF token, a consent flag, a language preference — and
			// dropping them would break the very session this exists to
			// preserve.
			if existing := httpReq.Header.Get("Cookie"); existing != "" {
				set("Cookie", existing+"; "+cred.Value)
			} else {
				set("Cookie", cred.Value)
			}
			continue
		}
		// Every other header only fills a gap. A request that already names an
		// identity is more specific than a command-line default, and overriding
		// it would be the one thing a scanner must never do to an authenticated
		// request.
		if httpReq.Header.Get(cred.Name) == "" {
			set(cred.Name, cred.Value)
		}
	}
}

// userAgent returns the User-Agent to send.
func (c *Client) userAgent() string {
	if c.opts.RandomUA {
		return randomUserAgent()
	}
	if c.opts.UserAgent != "" {
		return c.opts.UserAgent
	}
	return DefaultUserAgent()
}

// readBody reads a response body up to max bytes, transparently gunzipping when
// the server compressed the response and net/http did not already do it.
func readBody(resp *http.Response, max int64) ([]byte, bool, error) {
	var reader io.Reader = resp.Body
	if isGzip(resp) {
		gz, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gz.Close()
			reader = gz
		}
	}

	limited := io.LimitReader(reader, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

// isGzip reports whether the body still needs decompressing.
//
// net/http decompresses transparently when *it* added Accept-Encoding, and
// strips the Content-Encoding field when it does. A body is therefore still
// compressed exactly when the field is present and the transport did not
// already handle it — which is the case when the caller supplied its own
// Accept-Encoding, as a replayed capture does.
func isGzip(resp *http.Response) bool {
	if resp.Uncompressed {
		return false
	}
	return strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
}

// retryable reports whether a failure is worth another attempt: connection
// problems and timeouts are, malformed requests are not.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	return false
}

// DefaultUserAgent identifies crackweb clearly in target logs.
//
// It is the default because being identified is the honest thing: a scan should
// be visible to whoever runs the target, and a scanner that hides by default
// would be built for the wrong purpose. Users who have a reason to rotate — a
// lab that treats scanner fingerprints as noise in its own logs, a WAF test
// where the point is the payload rather than the client — can ask for it.
func DefaultUserAgent() string {
	return "crackweb/" + version.Version
}

// userAgentPools are combined to build a realistic pool, rather than listed as a
// finished set.
//
// A fixed list is a fingerprint in itself: eight entries means every request
// from this tool carries one of eight strings, and after a minute of scanning
// that is as recognisable as shipping its own name. Composing the pool from the
// parts real browsers advertise — engine, platform, version — yields hundreds of
// well-formed combinations, so rotation looks like the traffic a site already
// receives instead of like a scanner picking from a list.
var (
	// Chromium-based, which is most of the web.
	chromeVersions = []string{"131.0.0.0", "130.0.0.0", "129.0.0.0", "127.0.0.0", "126.0.0.0", "125.0.0.0"}
	edgeVersions   = []string{"131.0.0.0", "130.0.0.0", "129.0.0.0", "127.0.0.0"}
	firefoxVersion = []string{"133.0", "132.0", "131.0", "130.0", "129.0", "128.0"}
	safariVersions = []string{"18.1", "18.0", "17.6", "17.5", "17.4"}

	windowsPlatforms = []string{
		"Windows NT 10.0; Win64; x64",
		"Windows NT 10.0; WOW64",
		"Windows NT 11.0; Win64; x64",
	}
	macPlatforms = []string{
		"Macintosh; Intel Mac OS X 10_15_7",
		"Macintosh; Intel Mac OS X 14_6_1",
		"Macintosh; Intel Mac OS X 13_6_4",
	}
	linuxPlatforms = []string{
		"X11; Linux x86_64",
		"X11; Ubuntu; Linux x86_64",
		"X11; Fedora; Linux x86_64",
	}
	mobilePlatforms = []string{
		"Linux; Android 14; Pixel 8",
		"Linux; Android 13; SM-S918B",
		"Linux; Android 14; SM-S928B",
	}
)

// randomUserAgent composes a plausible User-Agent on each call.
//
// Composed rather than drawn from a list, and composed fresh each time rather
// than once per client: a scanner that picks one identity and keeps it produces
// the same grouping in a log as a scanner that sends its own name.
func randomUserAgent() string {
	chromeLike := func(platform string, token string) string {
		return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
			token + " Safari/537.36"
	}
	pick := func(values []string) string { return values[rand.IntN(len(values))] }

	switch rand.IntN(10) {
	case 0, 1, 2, 3:
		return chromeLike(pick(append(append([]string{}, windowsPlatforms...), macPlatforms...)), pick(chromeVersions))
	case 4:
		return chromeLike(pick(windowsPlatforms), pick(edgeVersions)) + " Edg/" + pick(edgeVersions)
	case 5:
		return "Mozilla/5.0 (" + pick(macPlatforms) + ") AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" +
			pick(safariVersions) + " Safari/605.1.15"
	case 6, 7:
		return "Mozilla/5.0 (" + pick(linuxPlatforms) + "; rv:" + pick(firefoxVersion) +
			") Gecko/20100101 Firefox/" + pick(firefoxVersion)
	case 8:
		return "Mozilla/5.0 (" + pick(windowsPlatforms) + "; rv:" + pick(firefoxVersion) +
			") Gecko/20100101 Firefox/" + pick(firefoxVersion)
	default:
		return chromeLike(pick(mobilePlatforms), pick(chromeVersions)) + " Mobile Safari/537.36"
	}
}

// userAgentPoolSize reports how many distinct values the composer can produce,
// which is what the tests assert on.
func userAgentPoolSize() int {
	return len(chromeVersions) + len(edgeVersions) + len(firefoxVersion) + len(safariVersions) +
		len(windowsPlatforms) + len(macPlatforms) + len(linuxPlatforms) + len(mobilePlatforms)
}
