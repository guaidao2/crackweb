package httpmsg

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// DefaultProto is assumed when a message does not carry a version, which is
// common for hand-written and Burp-exported requests.
const DefaultProto = "HTTP/1.1"

// minRequestLineFields is "METHOD TARGET" — the version is optional.
const minRequestLineFields = 2

// ParseOptions tunes how a raw message is interpreted.
type ParseOptions struct {
	// ForceHTTPS builds an https URL regardless of the port or forwarded
	// headers, for capture files that lost the scheme.
	ForceHTTPS bool
	// DefaultScheme is used when neither the port nor a forwarded header
	// indicates one. Empty means "http".
	DefaultScheme string
}

// ErrEmptyMessage is returned when there is nothing to parse.
var ErrEmptyMessage = errors.New("httpmsg: message is empty")

// ErrNoHost is returned when a raw request does not say where to send it.
var ErrNoHost = errors.New("httpmsg: request has no Host field and no absolute target")

// ParseRequest parses a raw HTTP request as exported by Burp Suite, ZAP or
// curl -v, or hand-written. The request line may use an origin-form target
// (/path?query) or an absolute URL; the version is optional.
//
// The result is a fully resolved *Request: the header list is kept in wire
// order with casing intact, and the URL is reconstructed from the target plus
// the Host field.
func ParseRequest(data []byte, opts ParseOptions) (*Request, error) {
	head, body, err := splitHeadBody(data)
	if err != nil {
		return nil, err
	}

	lines := splitLines(head)
	if len(lines) == 0 {
		return nil, ErrEmptyMessage
	}

	fields := strings.Fields(lines[0])
	if len(fields) < minRequestLineFields {
		return nil, fmt.Errorf("httpmsg: malformed request line %q: want \"METHOD target [HTTP/x.y]\"", lines[0])
	}

	req := &Request{
		Method: strings.ToUpper(fields[0]),
		Proto:  DefaultProto,
		Body:   body,
	}
	if len(fields) >= 3 && strings.HasPrefix(strings.ToUpper(fields[2]), "HTTP/") {
		req.Proto = fields[2]
	}
	target := fields[1]

	req.Header = parseHeaderLines(lines[1:])

	rawURL, err := buildURL(target, req.Header, opts)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("httpmsg: invalid URL %q: %w", rawURL, err)
	}
	req.URL = u

	// The Host field is kept on the wire, but make sure the URL agrees with it
	// so replaying the request and displaying it never disagree.
	if host := req.Header.Get("Host"); host != "" {
		req.URL.Host = host
	} else {
		req.Header.Set("Host", u.Host)
	}

	return req, nil
}

// ParseResponse parses a raw HTTP response, e.g. one captured by the proxy or
// pasted from a tool.
func ParseResponse(data []byte) (*Response, error) {
	head, body, err := splitHeadBody(data)
	if err != nil {
		return nil, err
	}

	lines := splitLines(head)
	if len(lines) == 0 {
		return nil, ErrEmptyMessage
	}

	fields := strings.SplitN(lines[0], " ", 3)
	if len(fields) < 2 || !strings.HasPrefix(strings.ToUpper(fields[0]), "HTTP/") {
		return nil, fmt.Errorf("httpmsg: malformed status line %q: want \"HTTP/x.y status [reason]\"", lines[0])
	}
	status, err := strconv.Atoi(strings.TrimSpace(fields[1]))
	if err != nil {
		return nil, fmt.Errorf("httpmsg: malformed status code in %q: %w", lines[0], err)
	}

	resp := &Response{
		Proto:  fields[0],
		Status: status,
		Header: parseHeaderLines(lines[1:]),
		Body:   body,
	}
	if len(fields) == 3 {
		resp.Reason = strings.TrimSpace(fields[2])
	}
	return resp, nil
}

// Raw renders the request back into wire format: request line, fields, blank
// line, body. Lines end with CRLF as HTTP requires.
//
// Two things are deliberately repaired rather than echoed verbatim, because a
// capture that is replayed with them missing would be malformed: a missing Host
// field is filled in from the URL, and a body with no framing field gets a
// Content-Length. Everything else round-trips byte-for-byte.
func (r *Request) Raw() []byte {
	var buf bytes.Buffer
	buf.WriteString(r.Method)
	buf.WriteByte(' ')
	buf.WriteString(r.Target())
	buf.WriteByte(' ')
	buf.WriteString(r.ProtoOrDefault())
	buf.WriteString("\r\n")

	header := r.Header.Clone()
	if !header.Has("Host") {
		if host := r.URLHost(); host != "" {
			header.Set("Host", host)
		}
	}
	if len(r.Body) > 0 && !header.Has("Content-Length") && !header.Has("Transfer-Encoding") {
		header.Set("Content-Length", strconv.Itoa(len(r.Body)))
	}
	writeHeader(&buf, header)

	buf.WriteString("\r\n")
	buf.Write(r.Body)
	return buf.Bytes()
}

// Raw renders the response back into wire format.
func (r *Response) Raw() []byte {
	var buf bytes.Buffer
	buf.WriteString(r.Proto)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(r.Status))
	if r.Reason != "" {
		buf.WriteByte(' ')
		buf.WriteString(r.Reason)
	}
	buf.WriteString("\r\n")
	writeHeader(&buf, r.Header)
	buf.WriteString("\r\n")
	buf.Write(r.Body)
	return buf.Bytes()
}

// URLHost returns the authority from the URL, or "" when there is none.
func (r *Request) URLHost() string {
	if r.URL == nil {
		return ""
	}
	return r.URL.Host
}

// writeHeader emits fields in wire order, one CRLF-terminated line each.
func writeHeader(buf *bytes.Buffer, header Header) {
	for _, field := range header.All() {
		buf.WriteString(field.Name)
		buf.WriteString(": ")
		buf.WriteString(field.Value)
		buf.WriteString("\r\n")
	}
}

// splitHeadBody separates the head from the entity body at the first blank
// line. Line endings are normalised to LF for parsing; the body is returned
// untouched apart from that normalisation, which never changes body semantics
// for the textual formats crackweb deals with.
func splitHeadBody(data []byte) (string, []byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return "", nil, ErrEmptyMessage
	}
	normalised := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if i := bytes.Index(normalised, []byte("\n\n")); i >= 0 {
		head := string(normalised[:i])
		body := normalised[i+2:]
		return head, body, nil
	}
	return string(normalised), nil, nil
}

// splitLines splits a head block into lines, dropping a trailing empty line.
func splitLines(head string) []string {
	trimmed := strings.TrimLeft(head, "\n")
	if trimmed == "" {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	// Drop any trailing blank lines left over from the head/body split.
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// parseHeaderLines turns header lines into a Header, unfolding obs-fold
// continuations and skipping lines that are not fields.
func parseHeaderLines(lines []string) Header {
	header := Header{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if isHeaderFolded(line) && header.Len() > 0 {
			items := header.items
			items[len(items)-1].Value += " " + strings.TrimSpace(line)
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		header.Add(strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]))
	}
	return header
}

// buildURL reconstructs an absolute URL from a request target and its header
// list, inferring the scheme from an explicit port, forwarded headers, or the
// caller's preference.
func buildURL(target string, header Header, opts ParseOptions) (string, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target, nil
	}
	host := header.Get("Host")
	if host == "" {
		return "", ErrNoHost
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	if strings.HasPrefix(target, "//") {
		// Network-path reference: the authority lives inside the target.
		return schemeFor(host, header, opts) + ":" + target, nil
	}
	return schemeFor(host, header, opts) + "://" + host + target, nil
}

// schemeFor decides between http and https for a capture that does not say.
func schemeFor(host string, header Header, opts ParseOptions) string {
	if opts.ForceHTTPS || hasForwardedHTTPS(header) {
		return "https"
	}
	if isTLSPort(host) {
		return "https"
	}
	if opts.DefaultScheme != "" {
		return opts.DefaultScheme
	}
	return "http"
}

// hasForwardedHTTPS reports whether a reverse-proxy header states that the
// client-facing leg was encrypted — the usual way an export from a TLS-
// terminating setup still tells us the original scheme.
func hasForwardedHTTPS(header Header) bool {
	for _, name := range []string{"X-Forwarded-Proto", "X-Forwarded-Protocol", "Front-End-Https"} {
		value := strings.ToLower(strings.TrimSpace(header.Get(name)))
		if value == "https" || value == "on" {
			return true
		}
	}
	return false
}

// isTLSPort reports whether the authority's port is conventionally TLS.
func isTLSPort(host string) bool {
	i := strings.LastIndex(host, ":")
	if i < 0 {
		return false
	}
	switch host[i+1:] {
	case "443", "8443":
		return true
	}
	return false
}
