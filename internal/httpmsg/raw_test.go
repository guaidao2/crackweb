package httpmsg

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// mustURL parses a URL or fails the test.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestParseRequestBasic(t *testing.T) {
	raw := "GET /news?id=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: crackweb-test\r\n" +
		"Accept: */*\r\n" +
		"\r\n"

	req, err := ParseRequest([]byte(raw), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.Proto != "HTTP/1.1" {
		t.Errorf("Proto = %q, want HTTP/1.1", req.Proto)
	}
	if got, want := req.URLString(), "http://example.com/news?id=1"; got != want {
		t.Errorf("URLString() = %q, want %q", got, want)
	}
	if got, want := req.Target(), "/news?id=1"; got != want {
		t.Errorf("Target() = %q, want %q", got, want)
	}
	if got, want := req.Host(), "example.com"; got != want {
		t.Errorf("Host() = %q, want %q", got, want)
	}
	if got, want := req.Hostname(), "example.com"; got != want {
		t.Errorf("Hostname() = %q, want %q", got, want)
	}
	if req.HasBody() {
		t.Error("HasBody() = true, want false")
	}
}

func TestParseRequestFromBurpExport(t *testing.T) {
	// The shape Burp writes when you copy a POST out of the proxy history:
	// no version on the request line, CRLF endings, a form body.
	raw := "POST /login HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 27\r\n" +
		"\r\n" +
		"user=admin&pass=hunter2"

	req, err := ParseRequest([]byte(raw), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	if got, want := string(req.Body), "user=admin&pass=hunter2"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if got, want := req.ContentLength(), 27; got != want {
		t.Errorf("ContentLength() = %d, want %d", got, want)
	}
	if got, want := req.ContentType(), "application/x-www-form-urlencoded"; got != want {
		t.Errorf("ContentType() = %q, want %q", got, want)
	}
}

func TestParseRequestWithoutVersion(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	// Strip the version to mimic the terse form some tools emit.
	terse := strings.Replace(raw, " HTTP/1.1", "", 1)

	req, err := ParseRequest([]byte(terse), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if got, want := req.ProtoOrDefault(), DefaultProto; got != want {
		t.Errorf("ProtoOrDefault() = %q, want %q", got, want)
	}
}

func TestParseRequestSchemeInference(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		opts ParseOptions
		want string
	}{
		{
			name: "plain host defaults to http",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "http://example.com/",
		},
		{
			name: "port 443 implies https",
			raw:  "GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			want: "https://example.com:443/",
		},
		{
			name: "port 8443 implies https",
			raw:  "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			want: "https://example.com:8443/",
		},
		{
			name: "X-Forwarded-Proto wins over the port",
			raw:  "GET / HTTP/1.1\r\nHost: example.com:80\r\nX-Forwarded-Proto: https\r\n\r\n",
			want: "https://example.com:80/",
		},
		{
			name: "Front-End-Https: on also counts",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\nFront-End-Https: on\r\n\r\n",
			want: "https://example.com/",
		},
		{
			name: "force https overrides everything",
			raw:  "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
			opts: ParseOptions{ForceHTTPS: true},
			want: "https://example.com:80/",
		},
		{
			name: "default scheme applies when nothing else does",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			opts: ParseOptions{DefaultScheme: "https"},
			want: "https://example.com/",
		},
		{
			name: "absolute target is used verbatim",
			raw:  "GET https://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "https://example.com/a?b=c",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tc.raw), tc.opts)
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if got := req.URLString(); got != tc.want {
				t.Errorf("URLString() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseRequestErrors(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{"empty", "", ErrEmptyMessage},
		{"whitespace only", "\r\n\r\n", ErrEmptyMessage},
		{"no host", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", ErrNoHost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRequest([]byte(tc.raw), ParseOptions{})
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ParseRequest error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseRequestMalformedLine(t *testing.T) {
	_, err := ParseRequest([]byte("GARBAGE\r\nHost: example.com\r\n\r\n"), ParseOptions{})
	if err == nil {
		t.Fatal("ParseRequest accepted a malformed request line")
	}
	if !strings.Contains(err.Error(), "malformed request line") {
		t.Errorf("error = %v, want it to mention the request line", err)
	}
}

func TestParseRequestUnfoldsContinuationLines(t *testing.T) {
	raw := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Folded: first\r\n" +
		"\tsecond\r\n" +
		"\r\n"

	req, err := ParseRequest([]byte(raw), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if got, want := req.Header.Get("X-Folded"), "first second"; got != want {
		t.Errorf("X-Folded = %q, want %q", got, want)
	}
}

// TestRequestRawRoundTrip is the property the whole tool leans on: a capture
// that is parsed and re-serialised must come back byte-for-byte identical, or
// replays and reports would drift away from what was actually sent.
func TestRequestRawRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "simple GET",
			raw: "GET /a?b=c HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Accept: */*\r\n" +
				"\r\n",
		},
		{
			name: "POST with form body",
			raw: "POST /login HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 20\r\n" +
				"\r\n" +
				"user=admin&pass=12345",
		},
		{
			name: "custom header casing survives",
			raw: "GET / HTTP/1.1\r\n" +
				"host: example.com\r\n" +
				"X-Custom-HEADER: VaLuE\r\n" +
				"\r\n",
		},
		{
			name: "duplicate headers keep their order",
			raw: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Cookie: a=1\r\n" +
				"Cookie: b=2\r\n" +
				"\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tc.raw), ParseOptions{})
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if got := string(req.Raw()); got != tc.raw {
				t.Errorf("round trip mismatch\n got: %q\nwant: %q", got, tc.raw)
			}
		})
	}
}

func TestRequestRawFillsInMissingFraming(t *testing.T) {
	req := &Request{
		Method: "POST",
		URL:    mustURL(t, "http://example.com/login"),
		Proto:  "HTTP/1.1",
		Body:   []byte("a=1"),
	}

	raw := string(req.Raw())
	if !strings.Contains(raw, "Host: example.com\r\n") {
		t.Errorf("Raw() did not add a Host field:\n%s", raw)
	}
	if !strings.Contains(raw, "Content-Length: 3\r\n") {
		t.Errorf("Raw() did not add a Content-Length field:\n%s", raw)
	}
}

func TestParseResponse(t *testing.T) {
	raw := "HTTP/1.1 302 Found\r\n" +
		"Location: /next\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello"

	resp, err := ParseResponse([]byte(raw))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}

	if resp.Status != 302 {
		t.Errorf("Status = %d, want 302", resp.Status)
	}
	if resp.Reason != "Found" {
		t.Errorf("Reason = %q, want Found", resp.Reason)
	}
	if !resp.IsRedirect() {
		t.Error("IsRedirect() = false, want true")
	}
	if got, want := string(resp.Body), "hello"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if got := string(resp.Raw()); got != raw {
		t.Errorf("round trip mismatch\n got: %q\nwant: %q", got, raw)
	}
}

func TestParseResponseWithoutReason(t *testing.T) {
	resp, err := ParseResponse([]byte("HTTP/1.1 204\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != 204 || resp.Reason != "" {
		t.Errorf("got %d %q, want 204 \"\"", resp.Status, resp.Reason)
	}
}

func TestParseResponseErrors(t *testing.T) {
	if _, err := ParseResponse(nil); !errors.Is(err, ErrEmptyMessage) {
		t.Errorf("empty response error = %v, want ErrEmptyMessage", err)
	}
	if _, err := ParseResponse([]byte("NOT HTTP\r\n\r\n")); err == nil {
		t.Error("ParseResponse accepted a malformed status line")
	}
	if _, err := ParseResponse([]byte("HTTP/1.1 abc\r\n\r\n")); err == nil {
		t.Error("ParseResponse accepted a non-numeric status code")
	}
}

func TestCloneIsDeep(t *testing.T) {
	req, err := ParseRequest([]byte("POST /a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\nbody"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	clone := req.Clone()
	clone.Header.Set("Host", "evil.example")
	clone.Body[0] = 'B'
	clone.URL.Path = "/changed"

	if got := req.Header.Get("Host"); got != "example.com" {
		t.Errorf("original Host mutated: %q", got)
	}
	if got := string(req.Body); got != "body" {
		t.Errorf("original body mutated: %q", got)
	}
	if got := req.URL.Path; got != "/a" {
		t.Errorf("original URL mutated: %q", got)
	}
}

func TestIsSafeMethod(t *testing.T) {
	safe := []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	for _, method := range safe {
		req := &Request{Method: method}
		if !req.IsSafeMethod() {
			t.Errorf("IsSafeMethod(%s) = false, want true", method)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		req := &Request{Method: method}
		if req.IsSafeMethod() {
			t.Errorf("IsSafeMethod(%s) = true, want false", method)
		}
	}
}
