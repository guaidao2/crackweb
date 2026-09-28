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
	c.hg = &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
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

// Do sends a request and returns the response. A transport-level failure is
// returned as an error; an HTTP error status is a perfectly good response and
// comes back as one.
func (c *Client) Do(ctx context.Context, req *httpmsg.Request) (*httpmsg.Response, error) {
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
		resp, err := c.attempt(ctx, req)
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
func (c *Client) attempt(ctx context.Context, req *httpmsg.Request) (*httpmsg.Response, error) {
	httpReq, err := c.buildRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	raw, err := c.hg.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer raw.Body.Close()

	body, truncated, err := readBody(raw, c.opts.MaxBody)
	if err != nil {
		return nil, err
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
func (c *Client) buildRequest(ctx context.Context, req *httpmsg.Request) (*http.Request, error) {
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

	return httpReq, nil
}

// userAgent returns the User-Agent to send.
func (c *Client) userAgent() string {
	if c.opts.RandomUA {
		return randomUserAgent()
	}
	if c.opts.UserAgent != "" {
		return c.opts.UserAgent
	}
	return DefaultUserAgent
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

// randomUserAgent picks from the built-in pool.
func randomUserAgent() string {
	return userAgents[rand.IntN(len(userAgents))]
}

// DefaultUserAgent identifies crackweb clearly in target logs, which is the
// honest thing to do and makes a scan easy to spot and stop.
const DefaultUserAgent = "crackweb/0.1"

// userAgents is the pool used when random rotation is requested.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}
