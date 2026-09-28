package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/ca"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/scope"
)

// DefaultListen is where the proxy listens when the user does not say.
const DefaultListen = "127.0.0.1:7777"

// DefaultTimeout bounds a single outgoing request.
const DefaultTimeout = 30 * time.Second

// DefaultMaxBody bounds how much of any body the proxy buffers.
const DefaultMaxBody = 8 << 20 // 8 MiB

// Options configures the intercepting proxy.
type Options struct {
	// Listen is the address to accept client connections on.
	Listen string
	// Scope lists the hosts to intercept. Empty means everything.
	Scope []string
	// Upstream is an optional proxy to send outgoing traffic through.
	Upstream string
	// CA signs the certificates used for interception. Required.
	CA *ca.CA
	// Insecure skips verification of the target's own certificate, which is
	// normal when testing a staging box with a self-signed cert.
	Insecure bool
	// Timeout bounds a single outgoing request.
	Timeout time.Duration
	// MaxBody bounds buffered bodies.
	MaxBody int64
	// OnRequest is called for every request that passes through, before it is
	// forwarded. This is the scanner's hook into live traffic.
	OnRequest func(*httpmsg.Request)
	// OnResponse is called with the response to a forwarded request.
	OnResponse func(*httpmsg.Request, *httpmsg.Response)
	// OnError receives non-fatal transport problems.
	OnError func(error)
	// Logf receives human-readable status messages.
	Logf func(format string, args ...any)
}

// Proxy is an intercepting HTTP proxy with TLS man-in-the-middle.
type Proxy struct {
	opts      Options
	scope     *scope.Scope
	transport *http.Transport
	upstream  *url.URL

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
}

// New builds a proxy. Nothing is bound until Serve is called.
func New(opts Options) (*Proxy, error) {
	if opts.CA == nil {
		return nil, errors.New("proxy: a CA is required for TLS interception")
	}
	if opts.Listen == "" {
		opts.Listen = DefaultListen
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = DefaultMaxBody
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.OnError == nil {
		opts.OnError = func(error) {}
	}

	p := &Proxy{opts: opts, scope: scope.NewScope(opts.Scope)}

	// The transport carries only the settings that apply to every connection.
	// Proxy is left nil so outgoing traffic goes direct unless the user
	// explicitly asked for an upstream — following the ambient HTTP_PROXY
	// would make the proxy proxy itself.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
	}

	if opts.Upstream != "" {
		upstreamURL, err := url.Parse(opts.Upstream)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid upstream %q: %w", opts.Upstream, err)
		}
		switch strings.ToLower(upstreamURL.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("proxy: unsupported upstream scheme %q", upstreamURL.Scheme)
		}
		p.upstream = upstreamURL
		transport.Proxy = http.ProxyURL(upstreamURL)
	}
	p.transport = transport
	return p, nil
}

// Scope returns the proxy's host scope.
func (p *Proxy) Scope() *scope.Scope { return p.scope }

// Addr returns the address the proxy is listening on, once Serve has started.
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener == nil {
		return p.opts.Listen
	}
	return p.listener.Addr().String()
}

// Serve listens and handles connections until ctx is cancelled.
func (p *Proxy) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.opts.Listen)
	if err != nil {
		return fmt.Errorf("proxy: listen on %s: %w", p.opts.Listen, err)
	}

	p.mu.Lock()
	p.listener = listener
	p.server = &http.Server{
		Handler: p,
		// Only the header read is bounded. A write deadline would kill the
		// long-lived tunnels and WebSockets the proxy is meant to carry.
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	server := p.server
	p.mu.Unlock()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// Close stops the proxy.
func (p *Proxy) Close() error {
	p.mu.Lock()
	server := p.server
	p.mu.Unlock()
	if server == nil {
		return nil
	}
	return server.Close()
}

// ServeHTTP dispatches a client connection to the right handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlainHTTP(w, r)
}

// handlePlainHTTP forwards an unencrypted proxy request. The request target is
// an absolute URL, as HTTP proxying requires.
func (p *Proxy) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "crackweb: expected an absolute request URL", http.StatusBadRequest)
		return
	}

	body, _, err := readLimited(r.Body, p.opts.MaxBody)
	if r.Body != nil {
		_ = r.Body.Close()
	}
	if err != nil {
		http.Error(w, "crackweb: "+err.Error(), http.StatusBadRequest)
		return
	}

	captured := captureRequest(r, body, httpmsg.OriginProxy)

	// WebSocket and other upgrades cannot go through RoundTrip; relay them as
	// opaque byte streams instead.
	if isUpgrade(r.Header) {
		p.relayUpgrade(w, r, body, r.Host, "http")
		return
	}

	resp, err := p.roundTrip(r, body)
	if err != nil {
		p.opts.OnError(err)
		http.Error(w, "crackweb: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, truncated, err := readLimited(resp.Body, p.opts.MaxBody)
	if err != nil {
		p.opts.OnError(err)
	}

	capturedResponse := captureResponse(resp, respBody, truncated)
	p.emit(captured, capturedResponse)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// handleConnect handles a CONNECT request, either terminating TLS to inspect
// the traffic or relaying it untouched when the host is out of scope.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		http.Error(w, "crackweb: CONNECT without a host", http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "crackweb: connection does not support hijacking", http.StatusInternalServerError)
		return
	}

	if !p.scope.Contains(target) {
		p.opts.Logf("tunnel (out of scope): %s", target)
		p.tunnelConnect(hijacker, target)
		return
	}

	p.opts.Logf("intercept: %s", target)
	p.mitmConnect(hijacker, target)
}

// tunnelConnect relays a CONNECT byte-for-byte without inspecting it.
func (p *Proxy) tunnelConnect(hijacker http.Hijacker, target string) {
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.opts.OnError(err)
		return
	}
	defer clientConn.Close()

	upstreamConn, err := p.dialTarget(target)
	if err != nil {
		p.opts.OnError(err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstreamConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	tunnel(clientConn, upstreamConn)
}

// mitmConnect establishes a CONNECT tunnel and then terminates TLS on it, so
// that the requests inside can be seen and tested.
func (p *Proxy) mitmConnect(hijacker http.Hijacker, target string) {
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.opts.OnError(err)
		return
	}
	defer clientConn.Close()

	cert, err := p.opts.CA.LeafFor(target)
	if err != nil {
		p.opts.OnError(err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Only HTTP/1.1 is offered. Advertising h2 here while speaking h1 inside
	// would break clients that take the hint, and HTTP/1.1 is what the vast
	// majority of scan targets speak anyway.
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	handshakeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		p.opts.OnError(fmt.Errorf("TLS handshake with client for %s: %w", target, err))
		return
	}
	defer tlsConn.Close()

	p.serveMITM(tlsConn, target)
}

// serveMITM reads requests off an intercepted TLS connection until the client
// closes it.
func (p *Proxy) serveMITM(conn *tls.Conn, host string) {
	reader := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isClosedConnError(err) {
				p.opts.OnError(fmt.Errorf("read request for %s: %w", host, err))
			}
			return
		}

		// ReadRequest yields a server-style request: origin-form target, no
		// scheme. Restore the absolute URL so it can be forwarded.
		req.URL.Scheme = "https"
		req.URL.Host = host
		if req.Host == "" {
			req.Host = host
		}
		req.RemoteAddr = conn.RemoteAddr().String()

		body, _, err := readLimited(req.Body, p.opts.MaxBody)
		_ = req.Body.Close()
		if err != nil {
			p.opts.OnError(err)
			return
		}

		if isUpgrade(req.Header) {
			p.relayUpgradeConn(conn, req, body, host, "https")
			return
		}

		if err := p.forwardMITM(conn, req, body, host); err != nil {
			p.opts.OnError(err)
			return
		}
		if req.Close {
			return
		}
	}
}

// forwardMITM sends one intercepted request onward and writes the response back
// down the intercepted connection.
func (p *Proxy) forwardMITM(conn net.Conn, req *http.Request, body []byte, host string) error {
	captured := captureRequest(req, body, httpmsg.OriginProxy)

	resp, err := p.roundTrip(req, body)
	if err != nil {
		// Tell the client something went wrong rather than silently dropping the
		// request, which would leave the browser hanging.
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return err
	}
	defer resp.Body.Close()

	respBody, truncated, readErr := readLimited(resp.Body, p.opts.MaxBody)
	if readErr != nil {
		p.opts.OnError(readErr)
	}

	p.emit(captured, captureResponse(resp, respBody, truncated))

	// Re-framing with a known length is safer than trying to replay an upstream
	// chunked encoding onto this connection.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	resp.TransferEncoding = nil
	resp.Close = req.Close
	resp.Request = req

	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write response for %s: %w", host, err)
	}
	return nil
}

// roundTrip forwards a request to its origin.
func (p *Proxy) roundTrip(r *http.Request, body []byte) (*http.Response, error) {
	outReq := r.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Body = io.NopCloser(bytes.NewReader(body))
	outReq.ContentLength = int64(len(body))
	if len(body) == 0 {
		outReq.Body = http.NoBody
		outReq.ContentLength = 0
	}
	removeHopByHop(outReq.Header)

	// The standard library needs a getter to replay the body on redirect or
	// retry; without it, any request with a body fails at the second hop.
	if len(body) > 0 {
		snapshot := body
		outReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshot)), nil
		}
	}
	return p.transport.RoundTrip(outReq)
}

// emit hands a captured exchange to the scanner's callbacks.
func (p *Proxy) emit(req *httpmsg.Request, resp *httpmsg.Response) {
	if p.opts.OnRequest != nil {
		p.opts.OnRequest(req)
	}
	if p.opts.OnResponse != nil {
		p.opts.OnResponse(req, resp)
	}
}

// tunnel copies bytes in both directions until either side closes.
func tunnel(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Closing the write half lets the peer see EOF without tearing down the
		// other direction's in-flight data.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}

// StripPort is re-exported for callers that already import this package.
func StripPort(host string) string { return scope.StripPort(host) }

// dialTarget opens a connection to host:port, through the upstream proxy when
// one is configured.
func (p *Proxy) dialTarget(host string) (net.Conn, error) {
	address := hostWithDefaultPort(host)
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

	if p.upstream == nil {
		return dialer.Dial("tcp", address)
	}

	// Reach the target through the upstream by asking it for a CONNECT tunnel.
	upstreamAddr := p.upstream.Host
	if _, _, err := net.SplitHostPort(upstreamAddr); err != nil {
		upstreamAddr = net.JoinHostPort(upstreamAddr, "3128")
	}
	conn, err := dialer.Dial("tcp", upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to upstream %s: %w", upstreamAddr, err)
	}
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
	if _, err := conn.Write([]byte(request)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT to upstream: %w", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT reply from upstream: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream refused CONNECT to %s: %s", address, resp.Status)
	}
	return conn, nil
}

// captureRequest converts a server-side request into the shared message model.
func captureRequest(r *http.Request, body []byte, origin httpmsg.Origin) *httpmsg.Request {
	header := httpmsg.HeaderFromStd(r.Header)
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if host != "" {
		header.Set("Host", host)
	}
	return &httpmsg.Request{
		Method:     r.Method,
		URL:        r.URL,
		Proto:      r.Proto,
		Header:     header,
		Body:       body,
		Origin:     origin,
		CapturedAt: time.Now(),
	}
}

// captureResponse converts an upstream response into the shared message model.
func captureResponse(resp *http.Response, body []byte, truncated bool) *httpmsg.Response {
	return &httpmsg.Response{
		Proto:      resp.Proto,
		Status:     resp.StatusCode,
		Reason:     statusReason(resp),
		Header:     httpmsg.HeaderFromStd(resp.Header),
		Body:       body,
		Truncated:  truncated,
		ReceivedAt: time.Now(),
	}
}

// statusReason extracts the reason phrase from a status line.
func statusReason(resp *http.Response) string {
	if resp.Status == "" {
		return ""
	}
	if i := strings.IndexByte(resp.Status, ' '); i >= 0 {
		return resp.Status[i+1:]
	}
	return ""
}

// readLimited reads at most max bytes, reporting whether the input was longer.
func readLimited(r io.Reader, max int64) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

// copyHeader copies response headers onto the writer.
func copyHeader(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// hopByHopHeaders are connection-scoped and must not be forwarded.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHop strips headers that belong to a single hop, plus anything the
// Connection field names.
func removeHopByHop(header http.Header) {
	for _, name := range header.Values("Connection") {
		for _, token := range strings.Split(name, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		header.Del(name)
	}
}

// isUpgrade reports whether a request asks to switch protocols, as WebSocket
// and HTTP/2 cleartext upgrades do.
func isUpgrade(header http.Header) bool {
	if header.Get("Upgrade") != "" {
		return true
	}
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// hostWithDefaultPort adds the scheme-appropriate port when it is missing.
func hostWithDefaultPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "443")
}

// isClosedConnError reports whether the error is the ordinary consequence of a
// peer closing a connection, which is not worth reporting.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}
