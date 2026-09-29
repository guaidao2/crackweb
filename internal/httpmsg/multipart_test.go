package httpmsg

import (
	"strings"
	"testing"
)

const testBoundary = "crackwebBoundary"

// multipartBody builds the envelope a browser sends for a form with one text field and
// one file field.
func multipartBody() string {
	return "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="title"` + "\r\n" +
		"\r\n" +
		"hello\r\n" +
		"--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="upload"; filename="a.txt"` + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"file-contents\r\n" +
		"--" + testBoundary + "--\r\n"
}

const testMultipartType = "multipart/form-data; boundary=" + testBoundary

func multipartRequest(t *testing.T, body string) *Request {
	t.Helper()
	req, err := NewRequest("POST", "http://example.com/upload")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", testMultipartType)
	req.Body = []byte(body)
	return req
}

func TestMultipartTextContentAndFileNameAreBothAddressable(t *testing.T) {
	params := multipartRequest(t, multipartBody()).BodyParams()
	if len(params) != 2 {
		t.Fatalf("got %d parameters, want 2", len(params))
	}
	if params[0].In != LocMultipart || params[0].Value != "hello" {
		t.Errorf("text part = %+v", params[0])
	}
	// The file's content is not a value to replace; the name the server will store it
	// under is.
	if params[1].In != LocMultipartFilename || params[1].Value != "a.txt" {
		t.Errorf("file part = %+v", params[1])
	}
}

func TestMultipartValueRewriteLeavesTheEnvelopeIntact(t *testing.T) {
	body := multipartBody()
	updated, ok := RewriteBody([]byte(body), testMultipartType,
		Param{In: LocMultipart, RawName: "title", Name: "title"}, "INJECTED")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	got := string(updated)
	for _, kept := range []string{
		"--" + testBoundary + "\r\n",
		"--" + testBoundary + "--\r\n",
		`name="upload"; filename="a.txt"`,
		"file-contents",
	} {
		if !strings.Contains(got, kept) {
			t.Errorf("rewrite lost %q:\n%s", kept, got)
		}
	}
	if !strings.Contains(got, "INJECTED\r\n") {
		t.Errorf("rewrite did not place the payload as a part value:\n%s", got)
	}
	if strings.Contains(got, "hello") {
		t.Errorf("rewrite left the original value behind:\n%s", got)
	}
}

func TestMultipartFileNameRewriteTouchesOnlyTheName(t *testing.T) {
	updated, ok := RewriteBody([]byte(multipartBody()), testMultipartType,
		Param{In: LocMultipartFilename, RawName: "upload", Name: "upload"}, "../../shell.php")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	got := string(updated)
	if !strings.Contains(got, `name="upload"; filename="../../shell.php"`) {
		t.Errorf("file name was not rewritten:\n%s", got)
	}
	if !strings.Contains(got, "file-contents") || !strings.Contains(got, "hello") {
		t.Errorf("rewrite touched something other than the name:\n%s", got)
	}
}

func TestMultipartRepeatedFieldNamesUseOccurrence(t *testing.T) {
	body := "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="tag"` + "\r\n\r\n" +
		"first\r\n" +
		"--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="tag"` + "\r\n\r\n" +
		"second\r\n" +
		"--" + testBoundary + "--\r\n"

	params := multipartRequest(t, body).BodyParams()
	if len(params) != 2 || params[1].Occurrence != 1 {
		t.Fatalf("unexpected parameters: %+v", params)
	}

	updated, ok := RewriteBody([]byte(body), testMultipartType, params[1], "changed")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	if !strings.Contains(string(updated), "first") || !strings.Contains(string(updated), "changed") {
		t.Errorf("rewrite touched the wrong part:\n%s", updated)
	}
}

func TestMultipartUnquotedFileNameIsAddressable(t *testing.T) {
	body := "--" + testBoundary + "\r\n" +
		"Content-Disposition: form-data; name=upload; filename=a.txt\r\n\r\n" +
		"contents\r\n" +
		"--" + testBoundary + "--\r\n"
	params := multipartRequest(t, body).BodyParams()
	if len(params) != 1 || params[0].In != LocMultipartFilename || params[0].Value != "a.txt" {
		t.Fatalf("unexpected parameters: %+v", params)
	}
}

func TestMultipartTruncatedBodyIsNotAddressable(t *testing.T) {
	body := "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="title"` + "\r\n\r\n" +
		"hello\r\n"
	if params := multipartRequest(t, body).BodyParams(); len(params) != 0 {
		t.Errorf("truncated body produced %d parameters, want none", len(params))
	}
}
