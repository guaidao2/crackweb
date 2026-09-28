package active

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// smugglingTimeout bounds both the connection and the read. A desynchronised
// connection can hang while the front end waits for bytes the back end will
// never ask for, and a check must not hang with it.
const smugglingTimeout = 6 * time.Second

// smugglingReadLimit bounds what is read back. Two responses are enough to make
// the point; a third would just be noise.
const smugglingReadLimit = 64 << 10

// requestSmuggling detects a front end and a back end that disagree about where
// a request ends.
//
// It is the only check that does not go through the HTTP client, and the reason
// is inherent to the technique: the payload is a request whose framing headers
// contradict each other, which a request built by net/http cannot be. So the
// bytes are assembled and written over a raw socket.
//
// It is also the only check that can leave the target worse off. The leftover
// bytes stay queued on the connection and are read as the beginning of whatever
// request comes next — possibly someone else's. That is why it is marked unsafe
// and never selected unless the user asks for it by name or enables unsafe
// checks explicitly.
type requestSmuggling struct{}

func (requestSmuggling) ID() string                 { return "request-smuggling" }
func (requestSmuggling) TitleKey() i18n.Key         { return i18n.KeyCheckSmugglingTitle }
func (requestSmuggling) DescriptionKey() i18n.Key   { return i18n.KeyCheckSmugglingDesc }
func (requestSmuggling) RemediationKey() i18n.Key   { return i18n.KeyCheckSmugglingFix }
func (requestSmuggling) Severity() finding.Severity { return finding.SeverityHigh }
func (requestSmuggling) Tags() []string {
	return []string{"active", "smuggling", "protocol", "owasp-top10"}
}
func (requestSmuggling) Passive() bool { return false }

// IsRequestLevel marks this as a check that writes its own bytes.
func (requestSmuggling) IsRequestLevel() bool { return true }

// IsUnsafe marks this as a check that must be opted into: its probes leave
// queued bytes behind.
func (requestSmuggling) IsUnsafe() bool { return true }

func (requestSmuggling) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// A response that already failed tells us nothing: a second response from a
	// broken front end would be indistinguishable from the first.
	if t.Response.Status >= 400 {
		return nil
	}

	host := t.Request.Host()
	if host == "" {
		return nil
	}
	address := host
	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if t.Request.Scheme() == "https" {
			port = "443"
		}
		address = net.JoinHostPort(host, port)
	}
	secure := t.Request.Scheme() == "https"

	// Two classic disagreements. CL.TE: the front end counts bytes, the back end
	// reads chunks. TE.CL: the other way round.
	probes := []struct {
		name    string
		payload []byte
	}{
		{"CL.TE", buildCLTEProbe(t.Request)},
		{"TE.CL", buildTECLProbe(t.Request)},
	}

	for _, probe := range probes {
		raw, err := rawExchange(ctx, address, secure, probe.payload)
		if err != nil || len(raw) == 0 {
			continue
		}
		// One response is normal. Two mean the back end resumed parsing at the
		// leftover bytes — the definition of the bug.
		if countHTTPResponses(raw) < 2 {
			continue
		}

		f := checks.NewFinding(requestSmuggling{}, t,
			i18n.KeyCheckSmugglingTitle, i18n.KeyCheckSmugglingDesc, i18n.KeyCheckSmugglingFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Method = t.Request.Method
		f.URL = t.Request.URLString()
		f.Payload = probe.name + " framing conflict"
		f.CWE = "CWE-444"
		f.References = []string{
			"https://portswigger.net/web-security/request-smuggling",
			"https://cwe.mitre.org/data/definitions/444.html",
		}
		f.Evidence.Request = probe.payload
		f.Evidence.Response = truncate(raw, 8192)
		f.Evidence.Matches = []string{
			fmt.Sprintf("the %s probe produced %d responses on one connection", probe.name, countHTTPResponses(raw)),
			"the target must be considered desynchronised; do not send further requests until it is restarted",
		}
		return []*finding.Finding{f}
	}
	return nil
}

// buildCLTEProbe sends a request that declares a content length and a chunked
// encoding, with a body that satisfies the chunked reading immediately and the
// declared length later.
func buildCLTEProbe(req *httpmsg.Request) []byte {
	chunked := "0\r\n\r\n"
	following := "GET " + req.Target() + " HTTP/1.1\r\nHost: " + req.Host() + "\r\n\r\n"
	body := chunked + following

	var b strings.Builder
	writeRequestLine(&b, req, "POST")
	// The declared length covers the chunk terminator only, so a front end that
	// counts bytes stops early and a back end that reads chunks stops at the
	// right place — leaving the rest as the next request.
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(chunked))
	b.WriteString("Transfer-Encoding: chunked\r\n")
	writeForwardedHeaders(&b, req)
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// buildTECLProbe is the mirror image: chunked framing that hides an extra
// request from a front end which counts bytes instead.
func buildTECLProbe(req *httpmsg.Request) []byte {
	following := "GET " + req.Target() + " HTTP/1.1\r\nHost: " + req.Host() + "\r\n\r\n"
	hidden := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(following), following)

	var b strings.Builder
	writeRequestLine(&b, req, "POST")
	b.WriteString("Transfer-Encoding: chunked\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(hidden)-4)
	writeForwardedHeaders(&b, req)
	b.WriteString("\r\n")
	b.WriteString(hidden)
	return []byte(b.String())
}

// writeRequestLine writes the start of a probe request.
func writeRequestLine(b *strings.Builder, req *httpmsg.Request, method string) {
	fmt.Fprintf(b, "%s %s HTTP/1.1\r\n", method, req.Target())
	fmt.Fprintf(b, "Host: %s\r\n", req.Host())
}

// writeForwardedHeaders copies the request's own headers, minus the ones the
// probe sets itself and the ones a proxy would rewrite.
func writeForwardedHeaders(b *strings.Builder, req *httpmsg.Request) {
	for _, field := range req.Header.All() {
		switch strings.ToLower(field.Name) {
		case "host", "content-length", "transfer-encoding", "connection":
			continue
		}
		fmt.Fprintf(b, "%s: %s\r\n", field.Name, field.Value)
	}
}

// rawExchange writes a byte string over a fresh connection and reads whatever
// comes back.
//
// A fresh connection per probe matters: smuggling is about what happens on one
// connection, so reusing a pooled one would make the result depend on unrelated
// traffic.
func rawExchange(ctx context.Context, address string, secure bool, payload []byte) ([]byte, error) {
	dialer := &net.Dialer{Timeout: smugglingTimeout}

	var conn net.Conn
	var err error
	if secure {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(smugglingTimeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	var (
		out = make([]byte, 0, 4096)
		buf = make([]byte, 4096)
	)
	for len(out) < smugglingReadLimit {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
			// Keep reading until the deadline: a second response may arrive a
			// moment after the first.
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		}
		if err != nil {
			break
		}
	}
	return out, nil
}

// statusLineRe matches a status line terminated by CRLF.
//
// The CRLF is what makes this usable rather than merely plausible. A
// desynchronised connection produces a second response immediately after the
// first response's body, with nothing separating them — so requiring a line
// start would miss the very thing being looked for. Requiring the terminator
// recovers the discrimination from the other end: prose that happens to mention
// "HTTP/1.1 200 OK" does not carry CRLF after it, and a real response header
// always does.
var statusLineRe = regexp.MustCompile(`HTTP/1\.[01] [0-9]{3}[^\r\n]*\r\n`)

// countHTTPResponses counts status lines in a raw byte stream.
func countHTTPResponses(data []byte) int {
	return len(statusLineRe.FindAll(data, -1))
}
