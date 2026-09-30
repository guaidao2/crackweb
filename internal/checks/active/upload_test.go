package active

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"strings"
	"sync"
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

// judgingUploadSite is an endpoint that does judge the names it is handed — it
// refuses one that no filesystem could hold — but has no defence worth the name
// against the dangerous ones. Without the first half the check cannot tell its
// answers apart from a page that never varies, which is why every "this endpoint
// accepted a dangerous name" test needs a target like this one rather than a
// target that accepts everything.
func judgingUploadSite(t *testing.T) *httptest.Server {
	t.Helper()
	// An endpoint with no list of names it refuses, and no confinement either: what it
	// accepts it stores where it can be fetched again. Acceptance alone is not the finding —
	// an endpoint that writes to a temporary directory accepts just as readily — so the
	// fixture has to serve the file back for the check to have something to report.
	var (
		mu     sync.Mutex
		stored = map[string][]byte{}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			body, ok := stored[r.URL.Path]
			mu.Unlock()
			if ok {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(body)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		names := allFilenames(string(raw))
		for _, name := range names {
			if len(name) > 200 {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, "<html><body>Error: that file name is too long.</body></html>")
				return
			}
		}
		mu.Lock()
		for _, name := range names {
			stored["/"+name] = uploadContentMarker
		}
		mu.Unlock()
		fmt.Fprint(w, "<html><body>Upload complete. "+strings.Repeat("thank you ", 30)+"</body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadFiresOnTraversalFilename: a server that accepts a name containing
// path separators has a filesystem problem, not just a naming one.
// escapingUploadSite stores what it is given at the path the name spells out, one level up
// included, and then serves it — the shape a traversal writes into and a read confirms.
func escapingUploadSite(t *testing.T) *httptest.Server {
	t.Helper()
	files := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for _, headers := range r.MultipartForm.File {
				for _, header := range headers {
					name := header.Filename
					if raw := header.Header.Get("Content-Disposition"); raw != "" {
						if index := strings.Index(raw, "filename="); index >= 0 {
							name = strings.Trim(raw[index+len("filename="):], `"`)
						}
					}
					if len(name) > 200 {
						w.WriteHeader(http.StatusUnprocessableEntity)
						fmt.Fprint(w, "<html><body>Error: that file name is too long.</body></html>")
						return
					}
					file, err := header.Open()
					if err != nil {
						continue
					}
					data, _ := io.ReadAll(file)
					file.Close()
					// No confinement: the name builds the path as it stands, from the
					// upload directory the site keeps its files in. A `../` entry lands one
					// level up, where the web server serves from; the same name without the
					// path stays inside.
					files[strings.TrimPrefix(path.Clean("/up/"+name), "/")] = string(data)
				}
			}
			fmt.Fprintf(w, "<html><body>Upload complete. %s</body></html>", strings.Repeat("thank you ", 30))
			return
		}
		if content, ok := files[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			fmt.Fprint(w, content)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestUploadFiresOnTraversalFilename(t *testing.T) {
	server := escapingUploadSite(t)

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
		// Every entry, not just the first: a check that reads one of two is the
		// duplicate-field finding, and this fixture is meant to be the endpoint that refuses.
		for _, name := range allFilenames(string(raw)) {
			if name != "" && isDangerousUploadName(name) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, "<html><body>Error: that file name or type is not permitted.</body></html>")
				return
			}
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
// filenameInBodyRe matches every file name a multipart body carries.
var filenameInBodyRe = regexp.MustCompile(`(?i)filename="([^"]*)"`)

// allFilenames returns every file name in the body, not just the first. A hardened endpoint
// checks all of them; a fixture that looks only at the first is the endpoint this check is
// about, and would be reported — correctly.
func allFilenames(body string) []string {
	var out []string
	for _, match := range filenameInBodyRe.FindAllStringSubmatch(body, 32) {
		out = append(out, match[1])
	}
	return out
}

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
		case "php", "phtml", "php3", "php4", "php5", "php7", "php8", "phps", "phar", "pht",
			"jsp", "jspx", "jsw", "jsv", "asp", "aspx", "ashx", "asmx", "ascx",
			"svg", "exe", "dll", "sh", "cgi", "pl", "py", "rb",
			"war", "ear", "cer", "cdx", "asa", "shtml", "htaccess", "htpasswd":
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

// TestUploadFiresOnArchiveAndConfigNames covers the names the extension list was
// missing: the older PHP spellings, the JavaEE archive, the IIS handlers, and the
// Apache configuration file. Each is a name a hardened endpoint refuses and a
// deny-list written for `.php` alone lets through.
func TestUploadFiresOnArchiveAndConfigNames(t *testing.T) {
	for _, name := range []string{
		"crackweb-test.war",
		"crackweb-test.php4",
		"crackweb-test.htaccess",
		"crackweb-test.shtml",
	} {
		server := judgingUploadSite(t)
		request := multipartRequest(t, server.URL+"/upload", "avatar", name, "data")
		h := newHarness(t)
		baseline, _ := h.client.Do(context.Background(), request)
		findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
		if len(findings) == 0 {
			t.Errorf("%s was accepted by the endpoint but not reported", name)
		}
	}
}

// TestUploadStaysQuietWhenThePageNeverVaries is the false positive this check had
// on a real target: an upload handler whose confirmation page is the same for
// every request. The names it is handed make no difference to the answer, so
// "the response matched a genuine upload" is not evidence that a dangerous name
// was stored — and treating it as evidence reports the endpoint as vulnerable
// whatever it was given.
func TestUploadStaysQuietWhenThePageNeverVaries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One page, always, regardless of the name in the body.
		fmt.Fprint(w, "<html><body>Vulinbox - File Upload to: /upload/case/safe "+
			strings.Repeat("Choose file ", 30)+"</body></html>")
	}))
	defer server.Close()

	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("an endpoint whose page never varies was reported: %v", findings[0].Evidence.Matches)
	}
}
