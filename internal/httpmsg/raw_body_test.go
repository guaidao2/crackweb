package httpmsg

import (
	"bytes"
	"testing"
)

// TestParseRequestPreservesBinaryBodyBytes is the regression test for a parser that
// normalised CRLF throughout the whole message. A multipart upload, a gzip stream and
// any other binary entity carries CRLF inside its own framing; rewriting those bytes
// corrupts the capture, and the upload check then tests a file the browser never sent.
func TestParseRequestPreservesBinaryBodyBytes(t *testing.T) {
	body := []byte("GIF89a\x00\x01\r\n\x02\r\n\r\nend")
	raw := append([]byte("POST /upload HTTP/1.1\r\n"+
		"Host: example.test\r\n"+
		"Content-Type: application/octet-stream\r\n\r\n"), body...)

	req, err := ParseRequest(raw, ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if !bytes.Equal(req.Body, body) {
		t.Errorf("body was rewritten:\n got %q\nwant %q", req.Body, body)
	}
}

// TestParseRequestAcceptsLFAndMixedLineEndings: the boundary is still found when a
// capture uses LF, or a mixed pair, but the body that follows it is untouched.
func TestParseRequestAcceptsLFAndMixedLineEndings(t *testing.T) {
	body := []byte("a\r\nb\x00c")
	heads := []string{
		"POST /x HTTP/1.1\nHost: example.test\n\n",
		"POST /x HTTP/1.1\r\nHost: example.test\n\r\n",
		"POST /x HTTP/1.1\r\nHost: example.test\r\n\n",
	}
	for _, head := range heads {
		req, err := ParseRequest(append([]byte(head), body...), ParseOptions{})
		if err != nil {
			t.Fatalf("ParseRequest(%q): %v", head, err)
		}
		if !bytes.Equal(req.Body, body) {
			t.Errorf("body after %q was rewritten: got %q, want %q", head, req.Body, body)
		}
		if got := req.Header.Get("Host"); got != "example.test" {
			t.Errorf("Host after %q = %q, want example.test", head, got)
		}
	}
}

// TestParseRequestKeepsALeadingNewlineOnABodilessMessage: the old parser trimmed
// leading newlines before reading the request line, and a capture saved with one must
// keep parsing.
func TestParseRequestKeepsALeadingNewlineOnABodilessMessage(t *testing.T) {
	req, err := ParseRequest([]byte("\nPOST /x HTTP/1.1\nHost: example.test"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if req.Method != "POST" || req.Header.Get("Host") != "example.test" {
		t.Errorf("parsed %s with Host %q", req.Method, req.Header.Get("Host"))
	}
}
