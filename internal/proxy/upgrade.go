package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// relayingUpgrade handles a protocol upgrade (WebSocket, or a raw Upgrade) that
// arrived through the plain-HTTP proxy path.
//
// These cannot go through RoundTrip: an upgrade response is a 101 and both
// directions of the connection stay open afterwards. The proxy therefore stops
// speaking HTTP at this point and becomes a byte pump, while still reporting the
// handshake to the scanner.
func (p *Proxy) relayUpgrade(w http.ResponseWriter, r *http.Request, body []byte, host, scheme string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "crackweb: connection does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.opts.OnError(err)
		return
	}
	defer clientConn.Close()

	p.relayUpgradeTo(clientConn, r, body, host, scheme)
}

// relayingUpgradeConn handles an upgrade that arrived inside an intercepted TLS
// connection.
func (p *Proxy) relayUpgradeConn(conn net.Conn, req *http.Request, body []byte, host, scheme string) {
	p.relayUpgradeTo(conn, req, body, host, scheme)
}

// relayingUpgradeTo performs the upgrade handshake against the origin and then
// splices the two connections together.
func (p *Proxy) relayUpgradeTo(clientConn net.Conn, req *http.Request, body []byte, host, scheme string) {
	address := withDefaultPort(host, scheme)
	targetConn, err := p.dialTarget(address)
	if err != nil {
		p.opts.OnError(fmt.Errorf("upgrade to %s: %w", address, err))
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	if scheme == "https" {
		tlsConn := tls.Client(targetConn, &tls.Config{
			ServerName:         StripPort(host),
			InsecureSkipVerify: p.opts.Insecure,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			p.opts.OnError(fmt.Errorf("TLS handshake with %s: %w", address, err))
			_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		targetConn = tlsConn
	}

	// Rewrite the request into origin form for the server, preserving the Host
	// the client asked for.
	outReq := req.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.URL.Scheme = ""
	outReq.URL.Host = ""
	outReq.Body = io.NopCloser(bytes.NewReader(body))
	outReq.ContentLength = int64(len(body))
	if len(body) == 0 {
		outReq.Body = http.NoBody
	}
	outReq.Close = false

	if err := outReq.Write(targetConn); err != nil {
		p.opts.OnError(fmt.Errorf("write upgrade request to %s: %w", address, err))
		return
	}

	reader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(reader, outReq)
	if err != nil {
		p.opts.OnError(fmt.Errorf("read upgrade response from %s: %w", address, err))
		return
	}

	// Report the handshake, so a scanner can see WebSocket endpoints even
	// though it cannot inspect the frames that follow.
	responseBody, _, _ := readLimited(resp.Body, p.opts.MaxBody)
	_ = resp.Body.Close()

	captured := captureRequest(req, body, "proxy")
	capturedResp := captureResponse(resp, responseBody, false)
	p.emit(captured, capturedResp)

	// Re-serialise the upgrade response for the client. The body of a 101 is
	// empty by definition, so writing the head and then handing over the socket
	// is enough.
	if err := resp.Write(clientConn); err != nil {
		p.opts.OnError(fmt.Errorf("write upgrade response to client: %w", err))
		return
	}

	// From here the connection is opaque. Copy in both directions, draining
	// whatever the reader already buffered along the way.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(clientConn, reader)
		closeWrite(clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		closeWrite(targetConn)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// closeWrite half-closes a connection when the underlying type supports it.
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// withDefaultPort adds the scheme's default port when the authority has none.
func withDefaultPort(host, scheme string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	return net.JoinHostPort(StripPort(host), port)
}
