package active

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// multipartRequest builds an upload request carrying one file.
func multipartRequest(t *testing.T, rawURL, field, filename, content string) *httpmsg.Request {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.WriteField("description", "a test upload"); err != nil {
		t.Fatalf("WriteField: %v", err)
	}
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	request, err := httpmsg.NewRequest("POST", rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Body = buf.Bytes()
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Content-Length", fmt.Sprint(len(request.Body)))
	return request
}

// TestUploadFiresOnTraversalFilename: a server that accepts a name containing
// path separators has a filesystem problem, not just a naming one.
func TestUploadFiresOnTraversalFilename(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A target that stores whatever it is given, keeping the name.
		fmt.Fprint(w, "<html><body>Upload complete. "+strings.Repeat("thank you ", 30)+"</body></html>")
	}))
	defer server.Close()

	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an upload endpoint that accepted a traversal name was not reported")
	}
	if findings[0].CWE != "CWE-434" {
		t.Errorf("CWE = %q, want CWE-434", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "..") {
		t.Errorf("payload = %q, want a traversal name", findings[0].Payload)
	}
}

// TestUploadStaysQuietWhenNamesAreRejected is the other half: an endpoint that
// answers differently for a dangerous name is doing its job.
func TestUploadStaysQuietWhenNamesAreRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The name is read from the raw body rather than from r.FormFile.
		//
		// Go's multipart reader rewrites a filename through filepath.Base, so
		// `../../shell.php` arrives as `shell.php` and the request looks
		// harmless. Older applications — a PHP script concatenating
		// $_FILES['f']['name'] onto a directory — do not do that, and they are
		// the ones this check is for. Reading the body reproduces what such a
		// server actually sees.
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if name := filenameFromBody(string(raw)); name != "" && isDangerousUploadName(name) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprint(w, "<html><body>Error: that file name or type is not permitted.</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>Upload complete. "+strings.Repeat("thank you ", 30)+"</body></html>")
	}))
	defer server.Close()

	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)

	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) != 0 {
		t.Errorf("a server that rejects dangerous names was reported; accepted payload = %q", findings[0].Payload)
	}
}

// filenameFromBody pulls the first filename= occurrence out of a multipart body,
// which is what a server that does not sanitise the name would use.
func filenameFromBody(body string) string {
	const marker = `filename="`
	index := strings.Index(body, marker)
	if index < 0 {
		return ""
	}
	rest := body[index+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// isDangerousUploadName is what a hardened endpoint does: normalise the way the
// filesystem will, then look at every path segment for an executable extension.
//
// A simpler `HasSuffix(name, ".php")` is not a defence, and this test harness
// has to be a real one — a harness that accepts `crackweb-test.php.` and
// `crackweb-test.php7` would make the check look broken when it is right.
func isDangerousUploadName(name string) bool {
	// Any path separator at all, not just a traversal sequence: an absolute
	// name like "/tmp/x.txt" leaves the upload directory just as surely.
	if strings.ContainsAny(name, "/\\") {
		return true
	}
	// A NUL byte truncates the name in some runtimes, turning
	// "shell.php%00.png" into "shell.php".
	if strings.Contains(name, "%00") || strings.ContainsRune(name, 0) {
		return true
	}
	// Windows strips trailing dots and spaces before resolving a name, so
	// "shell.php." and "shell.php " both end up as "shell.php".
	normalised := strings.TrimRight(name, ". ")
	for _, segment := range strings.FieldsFunc(normalised, func(r rune) bool {
		return r == '/' || r == '\\' || r == '.'
	}) {
		switch strings.ToLower(segment) {
		case "php", "phtml", "php3", "php4", "php5", "php7", "php8", "phar", "pht",
			"jsp", "jspx", "jsw", "jsv", "asp", "aspx", "ashx", "asmx", "ascx",
			"svg", "exe", "dll", "sh", "cgi", "pl", "py", "rb":
			return true
		}
	}
	return false
}

// TestUploadSkipsNonMultipartRequests: a form post is not an upload.
func TestUploadSkipsNonMultipartRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer server.Close()

	request, _ := httpmsg.NewRequest("POST", server.URL+"/form")
	request.Body = []byte("name=value")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Length", "10")

	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)
	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a urlencoded form was treated as an upload: %+v", findings)
	}
}

func TestParseUploadForm(t *testing.T) {
	request := multipartRequest(t, "http://example.com/upload", "avatar", "photo.png", "PNG")
	form, ok := parseUploadForm(request)
	if !ok {
		t.Fatal("a well-formed multipart request was not parsed")
	}
	if form.fileField != "avatar" {
		t.Errorf("fileField = %q, want avatar", form.fileField)
	}
	if string(form.content) != "PNG" {
		t.Errorf("content = %q, want PNG", form.content)
	}
	if len(form.fields) != 1 || form.fields[0].Name != "description" {
		t.Errorf("fields = %+v, want one named description", form.fields)
	}

	// Rebuilding keeps the other fields and swaps only the filename.
	body, contentType := form.build("evil.php")
	if !strings.Contains(string(body), "description") {
		t.Error("the rebuild dropped a field")
	}
	if !strings.Contains(string(body), "evil.php") {
		t.Error("the rebuild did not use the new filename")
	}
	if !strings.Contains(string(body), "filename=\"evil.php\"") {
		t.Errorf("the filename is not in the part header: %s", body)
	}
	if contentType == "" {
		t.Error("the rebuild produced no content type")
	}
}

// TestDeserializationFiresOnParserError: a runtime complaining about the bytes
// proves it tried to parse them.
func TestDeserializationFiresOnParserError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("data")
		if strings.Contains(value, "rO0AB") {
			fmt.Fprint(w, "<html><body>java.io.StreamCorruptedException: invalid stream header: 72303041</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>Processed "+strings.Repeat("data ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, deserialization{}, server.URL+"/api?data=c29tZXRoaW5n")
	if len(findings) == 0 {
		t.Fatal("a deserialisation error was not reported")
	}
	if findings[0].CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", findings[0].CWE)
	}
}

// TestDeserializationStaysQuietOnATargetThatIgnoresIt: a parameter that is just
// a string must not be reported.
func TestDeserializationStaysQuietOnATargetThatIgnoresIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Processed "+strings.Repeat("data ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, deserialization{}, server.URL+"/api?data=c29tZXRoaW5n"); len(findings) != 0 {
		t.Errorf("an ordinary string parameter was reported: %+v", findings)
	}
}

func TestNewestChecksAreRegistered(t *testing.T) {
	for _, id := range []string{"upload", "deserialization"} {
		if checks.ByID(id) == nil {
			t.Errorf("check %q is not registered", id)
		}
	}
}
