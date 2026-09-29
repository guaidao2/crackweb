package httpmsg

import (
	"net/url"
	"strings"
	"time"
)

// Origin records where a message entered crackweb. It is surfaced in reports so
// a finding can be traced back to the browser traffic, the crawler or a manual
// paste.
type Origin string

// Message origins.
const (
	// OriginProxy marks traffic captured off the intercepting proxy.
	OriginProxy Origin = "proxy"
	// OriginCrawler marks requests discovered by the crawler.
	OriginCrawler Origin = "crawler"
	// OriginManual marks requests imported from a file.
	OriginManual Origin = "manual"
	// OriginReplay marks requests the scanner built while mutating a parameter.
	OriginReplay Origin = "replay"
)

// Request is one HTTP request.
type Request struct {
	// Method is upper-cased on construction.
	Method string
	// URL is the fully resolved request URL.
	URL *url.URL
	// Proto is the HTTP version, e.g. "HTTP/1.1". Empty means HTTP/1.1.
	Proto string
	// Header holds the request fields in wire order, Host included.
	Header Header
	// Body is the raw entity body, possibly empty but never nil after parsing.
	Body []byte

	// ID identifies the request for the lifetime of a run. It is what links a
	// finding, an out-of-band callback and a stored capture back together.
	ID string
	// Origin records how the request entered the tool.
	Origin Origin
	// CapturedAt is when the request was observed.
	CapturedAt time.Time
	// Timeout overrides the client's per-request deadline for this request
	// alone. Zero means the client's value applies.
	//
	// It exists for the checks whose whole method is waiting: a time-based
	// injection probe asks the server to pause for several seconds, and a
	// deadline chosen for ordinary requests cuts it off before the answer
	// arrives. Raising the client's timeout instead would slow every other
	// request in the scan, so the budget belongs to the request that needs it.
	Timeout time.Duration
}

// NewRequest builds a request from a method and an absolute URL.
func NewRequest(method, rawURL string) (*Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	r := &Request{
		Method: strings.ToUpper(method),
		URL:    u,
		Proto:  "HTTP/1.1",
	}
	if u.Host != "" {
		r.Header.Set("Host", u.Host)
	}
	return r, nil
}

// Clone returns a deep copy: the URL, the header list and the body are all
// independent, so mutating one request while keeping the baseline is safe.
func (r *Request) Clone() *Request {
	if r == nil {
		return nil
	}
	out := *r
	if r.URL != nil {
		u := *r.URL
		out.URL = &u
	}
	out.Header = r.Header.Clone()
	if r.Body != nil {
		out.Body = make([]byte, len(r.Body))
		copy(out.Body, r.Body)
	}
	return &out
}

// Host returns the authority the request is addressed to, preferring the Host
// field on the wire over the one embedded in the URL.
func (r *Request) Host() string {
	if host := r.Header.Get("Host"); host != "" {
		return host
	}
	if r.URL != nil {
		return r.URL.Host
	}
	return ""
}

// Scheme returns the URL scheme, defaulting to http.
func (r *Request) Scheme() string {
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	return "http"
}

// Hostname returns the host without its port.
func (r *Request) Hostname() string {
	host := r.Host()
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// Guard against IPv6 literals such as [::1]:8080.
		if !strings.Contains(host[i:], "]") {
			return host[:i]
		}
	}
	return host
}

// Target returns the request target for the request line: the path plus query,
// never a full URL.
func (r *Request) Target() string {
	if r.URL == nil {
		return "/"
	}
	target := r.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	return target
}

// URLString renders the absolute URL.
func (r *Request) URLString() string {
	if r.URL == nil {
		return ""
	}
	return r.URL.String()
}

// ProtoOrDefault returns the HTTP version, defaulting to HTTP/1.1.
func (r *Request) ProtoOrDefault() string {
	if r.Proto == "" {
		return "HTTP/1.1"
	}
	return r.Proto
}

// ContentType returns the media type with any parameters stripped, lower-cased.
func (r *Request) ContentType() string {
	return mediaType(r.Header.Get("Content-Type"))
}

// ContentLength returns the body length as advertised on the wire, falling back
// to the actual body size when the field is absent.
func (r *Request) ContentLength() int {
	if v := r.Header.Get("Content-Length"); v != "" {
		if n, err := parseInt(v); err == nil && n >= 0 {
			return n
		}
	}
	return len(r.Body)
}

// HasBody reports whether there is an entity body to send.
func (r *Request) HasBody() bool { return len(r.Body) > 0 }

// IsSafeMethod reports whether the method is defined as safe in RFC 9110, which
// the scanner uses to decide how freely it may replay a request.
func (r *Request) IsSafeMethod() bool {
	switch r.Method {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

// Response is one HTTP response.
type Response struct {
	// Proto is the HTTP version, e.g. "HTTP/1.1".
	Proto string
	// Status is the numeric status code.
	Status int
	// Reason is the reason phrase as received, e.g. "OK".
	Reason string
	// Header holds the response fields in wire order.
	Header Header
	// Body is the raw entity body.
	Body []byte
	// Duration is how long the exchange took, from first byte sent to last byte
	// received.
	Duration time.Duration
	// RequestID links this response to the request that produced it.
	RequestID string
	// ReceivedAt is when the response was observed.
	ReceivedAt time.Time
	// FinalURL is where the request ended up after redirects, when they were
	// followed. It differs from the requested URL only on a redirect, which
	// makes it a useful signal on its own.
	FinalURL string
	// Truncated records that Body was cut short at the reader's size limit.
	Truncated bool
}

// Clone returns a deep copy.
func (r *Response) Clone() *Response {
	if r == nil {
		return nil
	}
	out := *r
	out.Header = r.Header.Clone()
	if r.Body != nil {
		out.Body = make([]byte, len(r.Body))
		copy(out.Body, r.Body)
	}
	return &out
}

// ContentType returns the media type with parameters stripped, lower-cased.
func (r *Response) ContentType() string {
	return mediaType(r.Header.Get("Content-Type"))
}

// IsRedirect reports whether the status is a 3xx redirect.
func (r *Response) IsRedirect() bool {
	return r.Status >= 300 && r.Status < 400
}
