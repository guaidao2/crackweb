package crawl

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// fileFieldFragments are the field names an upload form uses for its file part. The shape
// of the part is what makes an upload endpoint testable, so a name that says "file" gets
// one.
var fileFieldFragments = []string{"file", "upload", "attach", "image", "photo", "avatar", "document", "media"}

// replayScriptCall sends the request the page's script would have sent, with the method and
// body shape it uses.
//
// This is the difference between discovering an endpoint and testing it. An upload endpoint
// reached with GET has nothing to say — the reason to test it is the multipart body, and no
// amount of GET reveals it. Sending the body the page sends is what lets the checks that
// care about the shape of the request see it at all.
func (c *Crawler) replayScriptCall(ctx context.Context, call scriptCall) {
	if _, ok := c.accept(call.URL, 0); !ok {
		return
	}
	request, ok := scriptCallRequest(call)
	if !ok {
		return
	}
	c.deliver(ctx, request)
}

// scriptCallRequest builds the request a script call makes, or reports that it cannot.
//
// Split out of the replay so that a one-shot scan can send the same shape without crawling:
// the body is the whole reason to test an upload endpoint, and a scan that only knew how to
// send a bare GET would never reach the code behind it.
func scriptCallRequest(call scriptCall) (*httpmsg.Request, bool) {
	request, err := httpmsg.NewRequest(call.Method, call.URL)
	if err != nil {
		return nil, false
	}
	request.Origin = httpmsg.OriginCrawler

	switch call.Body {
	case bodyMultipart:
		body, contentType := encodeScriptMultipart(call.Fields)
		request.Body = body
		request.Header.Set("Content-Type", contentType)
	case bodyJSON:
		request.Body = []byte(encodeScriptJSON(call.Fields))
		request.Header.Set("Content-Type", "application/json")
	}
	if len(request.Body) > 0 {
		request.Header.Set("Content-Length", strconv.Itoa(len(request.Body)))
	}
	return request, true
}

// ScriptCall is one request a page's script makes, as the crawler reads it.
//
// Exported so that "scan --forms" can send the requests a page's script would send, and not
// only the ones its HTML forms declare. A modern page often has no form at all: the search
// box and the upload widget are script calls with a JSON or multipart body, and a scan that
// ignores them reports nothing about the endpoints they reach.
type ScriptCall = scriptCall

// ScriptCalls returns the requests a page's script makes, resolved against the page's URL.
//
// allowStateChange decides whether calls that only ever run with a writing method are
// included: they are left out by default, because the request a scan makes is a request the
// page's own script only makes on purpose.
func ScriptCalls(body string, base *url.URL, allowStateChange bool) []ScriptCall {
	return scriptCalls(body, base, allowStateChange)
}

// ScriptRequests turns a discovered script call into the request it makes.
func ScriptRequests(call ScriptCall) []*httpmsg.Request {
	request, ok := scriptCallRequest(call)
	if !ok {
		return nil
	}
	return []*httpmsg.Request{request}
}

// encodeScriptMultipart builds the body a FormData produces: one part per field, with a
// file part for the names that ask for one.
func encodeScriptMultipart(fields []string) ([]byte, string) {
	boundary := randomBoundary()
	var body strings.Builder
	for _, field := range fields {
		if field == "" {
			continue
		}
		body.WriteString("--" + boundary + "\r\n")
		if isFileField(field) {
			body.WriteString("Content-Disposition: form-data; name=\"" + field +
				"\"; filename=\"" + placeholderUploadName + "\"\r\n")
			// A picture's media type, because an endpoint that checks the type before it
			// looks at anything else is checking this header.
			body.WriteString("Content-Type: image/png\r\n\r\n")
			body.WriteString(placeholderUploadBody)
		} else {
			body.WriteString("Content-Disposition: form-data; name=\"" + field + "\"\r\n\r\n")
			body.WriteString("crackweb")
		}
		body.WriteString("\r\n")
	}
	body.WriteString("--" + boundary + "--\r\n")
	return []byte(body.String()), "multipart/form-data; boundary=" + boundary
}

// isFileField reports whether a field name asks for a file.
func isFileField(name string) bool {
	lower := strings.ToLower(name)
	for _, fragment := range fileFieldFragments {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}

// encodeScriptJSON builds a body with one string field per name the script sent. The values
// are placeholders: the point is to reach the handler with the shape it expects, and a
// check that injects will replace whatever is there.
func encodeScriptJSON(fields []string) string {
	var body strings.Builder
	body.WriteString("{")
	for index, field := range fields {
		if field == "" {
			continue
		}
		if body.Len() > 1 {
			body.WriteString(",")
		}
		_ = index
		body.WriteString(strconv.Quote(field) + ":\"crackweb\"")
	}
	body.WriteString("}")
	return body.String()
}
