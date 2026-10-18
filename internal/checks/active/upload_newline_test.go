package active

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// withoutLineBreaks is the spelling a layer that reads the name to the closing quote, or that
// strips the breaks out of it, ends up with.
func withoutLineBreaks(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, name)
}

// lineBreakSite is the endpoint CVE-2017-15715 describes: the layer that validates the name
// reads it as a line, and the layer that stores it reads it to the closing quote. A name whose
// break hides an executable extension is therefore never judged, and is stored under the
// spelling the break was hiding.
//
// It is not an endpoint that accepts everything, because that is the endpoint no answer of
// which means anything: a dangerous name written on one line is refused, and so is one no
// filesystem could hold. serve=false keeps the storing half away, which is the endpoint that
// accepts the name and writes it somewhere nothing can read it back from; acceptPlain=true
// drops the refusal, which is the endpoint the plain names probe already reports.
func lineBreakSite(t *testing.T, serve, acceptPlain bool) *httptest.Server {
	t.Helper()
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
		// Decide first and store second: a body carrying a name this endpoint refuses stores
		// nothing, which is what a rejected request amounts to.
		for _, name := range names {
			if !acceptPlain && !strings.ContainsAny(name, "\r\n") && isDangerousUploadName(name) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
				return
			}
		}
		mu.Lock()
		for _, name := range names {
			switch {
			case serve && strings.ContainsAny(name, "\r\n"):
				// The storing layer keeps the name without the breaks it never looked at.
				stored["/uploads/"+withoutLineBreaks(name)] = uploadContentMarker
			case acceptPlain && isDangerousUploadName(name):
				stored["/uploads/"+name] = uploadContentMarker
			}
		}
		mu.Unlock()
		fmt.Fprint(w, "<html><body>Upload complete. "+strings.Repeat("thank you ", 30)+"</body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

// hardenedLineBreakSite is the fix: it refuses a name carrying a control character before
// anything else looks at it, so the break cannot be the reason a validator and a filesystem
// read two different names.
func hardenedLineBreakSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		for _, name := range allFilenames(string(raw)) {
			if len(name) > 200 || isDangerousUploadName(withoutLineBreaks(name)) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
				return
			}
		}
		fmt.Fprint(w, "<html><body>Upload complete. "+strings.Repeat("thank you ", 30)+"</body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadFiresOnALineBreakInTheName: the name is refused as written and accepted with a
// break in it, and the file is served back under the extension the break was hiding. That is
// the whole of CVE-2017-15715 as a scanner can see it.
func TestUploadFiresOnALineBreakInTheName(t *testing.T) {
	server := lineBreakSite(t, true, false)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint that accepted a refused name once it carried a line break was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-434" {
		t.Errorf("CWE = %q, want CWE-434", f.CWE)
	}
	if !strings.Contains(f.Payload, `\n`) {
		t.Errorf("payload = %q, want the break spelled out", f.Payload)
	}
	if strings.ContainsAny(f.Payload, "\r\n") {
		t.Errorf("payload = %q, want a single line a report can print", f.Payload)
	}
	// The bytes are the evidence: the request this finding records has to be the one that
	// carried the break in the part header.
	if !strings.Contains(string(f.Evidence.Request), `.php`+"\n") {
		t.Errorf("the evidence request does not carry a line break in the name:\n%s", f.Evidence.Request)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "was refused on its own") {
		t.Errorf("the evidence does not name the refusal it rests on: %v", f.Evidence.Matches)
	}
}

// TestUploadStaysQuietWhenTheBreakIsRefused: the same shape against the endpoint that is doing
// its job — a control character is refused outright, so no differential is left to exploit.
func TestUploadStaysQuietWhenTheBreakIsRefused(t *testing.T) {
	server := hardenedLineBreakSite(t)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("an endpoint that refuses names carrying a control character was reported: %v",
			findings[0].Evidence.Matches)
	}
}

// TestUploadStaysQuietWhenTheBreakIsAcceptedAndNothingIsServed: acceptance is not the finding.
// An endpoint that reads the name and writes the file where nothing can fetch it answers
// exactly as the vulnerable one does, and reporting it would be a finding about a temporary
// directory.
func TestUploadStaysQuietWhenTheBreakIsAcceptedAndNothingIsServed(t *testing.T) {
	server := lineBreakSite(t, false, false)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a file that could not be fetched back was reported as stored: %v",
			findings[0].Evidence.Matches)
	}
}

// TestUploadPrefersThePlainNameWhenItIsAccepted: with no refusal there is nothing the break
// could have got past, and the finding that names the extension is the one that belongs here.
// A second finding saying "and it also took a line break" would be the same defect counted
// twice.
func TestUploadPrefersThePlainNameWhenItIsAccepted(t *testing.T) {
	server := lineBreakSite(t, true, true)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint that accepted an executable name was not reported at all")
	}
	if strings.Contains(findings[0].Payload, "line break") {
		t.Errorf("payload = %q, want the plain name: the refusal the break had to get past was absent",
			findings[0].Payload)
	}
	if findings[0].Payload != uploadExtensionNames[0] {
		t.Errorf("payload = %q, want the first name the plain probe tries (%q)",
			findings[0].Payload, uploadExtensionNames[0])
	}
}

// TestRawPartWritesTheNameAsBytes pins the difference the probe rests on. Neither builder can
// put the break on the wire: the declared-type path spells it `\n` through %q, and the plain
// path goes through the standard library's form field, which percent-encodes it to `%0A`. Both
// are names no parser disagrees about, which is why the probe writes its own header line.
func TestRawPartWritesTheNameAsBytes(t *testing.T) {
	const name = "crackweb-test.php\n"
	fields := []httpmsg.KV{{Name: "description", Value: "a test upload"}}

	typed := &uploadForm{
		fields: fields, fileField: "avatar", content: []byte("PNG"), contentType: "image/gif",
	}
	if body, _ := typed.build(name); !strings.Contains(string(body), `filename="crackweb-test.php\n"`) {
		t.Errorf("the escaped builder no longer spells the break: %q", body)
	}

	plain := &uploadForm{fields: fields, fileField: "avatar", content: []byte("PNG")}
	if body, _ := plain.build(name); !strings.Contains(string(body), "filename=\"crackweb-test.php%0A\"") {
		t.Errorf("the standard writer no longer encodes the break: %q", body)
	}

	raw, contentType := plain.buildRawPart(name)
	if !strings.Contains(string(raw), "filename=\"crackweb-test.php\n\"") {
		t.Errorf("the raw builder escaped the break: %q", raw)
	}
	if strings.Contains(string(raw), `crackweb-test.php\n`) ||
		strings.Contains(string(raw), "crackweb-test.php%0A") {
		t.Errorf("the raw builder wrote the break as something other than the byte: %q", raw)
	}
	if !strings.HasPrefix(contentType, "multipart/form-data; boundary=") {
		t.Errorf("content type = %q, want the writer's own", contentType)
	}
	if !strings.Contains(string(raw), "description") {
		t.Error("the raw builder dropped a field")
	}
}

// TestRawPartKeepsTheFraming: only the one header line is written by hand. The boundary, the
// delimiters and the closing delimiter are the writer's, so a body the raw builder produced is
// parsed by a standard reader into the same parts the escaped builder's is — and it still ends
// correctly when the name it carries has split the header line in two.
func TestRawPartKeepsTheFraming(t *testing.T) {
	form := &uploadForm{
		fields:    []httpmsg.KV{{Name: "description", Value: "a test upload"}},
		fileField: "avatar",
		content:   []byte("PNG"),
	}

	body, contentType := form.buildRawPart("photo.png")
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatal("the raw builder declared no boundary")
	}
	if !bytes.HasPrefix(body, []byte("--"+boundary+"\r\n")) {
		t.Errorf("the body does not open with the first delimiter: %q", body)
	}
	if !bytes.HasSuffix(body, []byte("\r\n--"+boundary+"--\r\n")) {
		t.Errorf("the body does not end with the closing delimiter: %q", body)
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var fields []string
	fileName, fileContent := "", ""
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("a raw body framed by the writer's own boundary did not parse: %v\n%s", err, body)
		}
		if part.FileName() != "" {
			fileName = part.FileName()
			content, _ := io.ReadAll(part)
			fileContent = string(content)
			continue
		}
		value, _ := io.ReadAll(part)
		fields = append(fields, part.FormName()+"="+string(value))
	}
	if len(fields) != 1 || fields[0] != "description=a test upload" {
		t.Errorf("fields = %v, want the form's own", fields)
	}
	if fileName != "photo.png" {
		t.Errorf("file name = %q, want photo.png", fileName)
	}
	if fileContent != "PNG" {
		t.Errorf("file content = %q, want PNG", fileContent)
	}

	// The same body with a break in the name: the header line is split, which is the point of
	// the probe, and the framing around it is untouched — the body still opens with its first
	// delimiter, still carries both dispositions and still ends with the closing one.
	split, splitType := form.buildRawPart("crackweb-test.php\n.jpg")
	_, splitParams, err := mime.ParseMediaType(splitType)
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	splitBoundary := splitParams["boundary"]
	if splitBoundary == "" {
		t.Fatal("the raw builder declared no boundary for a split header")
	}
	if !bytes.HasPrefix(split, []byte("--"+splitBoundary+"\r\n")) {
		t.Errorf("the body with a split header does not open with its first delimiter: %q", split)
	}
	if !bytes.HasSuffix(split, []byte("\r\n--"+splitBoundary+"--\r\n")) {
		t.Errorf("the body with a split header does not end with the closing delimiter: %q", split)
	}
	if got := bytes.Count(split, []byte("Content-Disposition: form-data")); got != 2 {
		t.Errorf("the body with a split header carries %d dispositions, want 2", got)
	}
}

// TestLineBreakUploadNamesCarryTheBreakEverywhere pins the seed set: every name has to carry a
// break — that is the only reason this probe exists — and the shapes have to cover both
// readings, one where the break ends the name and one where something follows it.
func TestLineBreakUploadNamesCarryTheBreakEverywhere(t *testing.T) {
	names := lineBreakUploadNames("crackwebmarker")
	if len(names) == 0 {
		t.Fatal("the line-break probe has no names to send")
	}
	trailing, inner := false, false
	for _, name := range names {
		index := strings.IndexAny(name, "\r\n")
		if index < 0 {
			t.Errorf("%q carries no break, so it is not this probe's name", name)
			continue
		}
		if strings.HasSuffix(name, ".php\n") {
			trailing = true
		}
		if trailingRest := strings.TrimLeft(name[index+1:], "\r\n"); trailingRest != "" && index > 0 {
			inner = true
		}
	}
	if !trailing {
		t.Error("no name ends in a line feed: that is the CVE-2017-15715 shape")
	}
	if !inner {
		t.Error("no name has anything after the break: a truncating layer would never be seen")
	}
}

// TestLineBreakNameSpellingsCoverEveryReading: the retrieval is only as good as the names it
// asks for, and the spellings are what a server that won the argument would have stored.
func TestLineBreakNameSpellingsCoverEveryReading(t *testing.T) {
	cases := map[string][]string{
		"x.php\n":     {"x.php\n", "x.php"},
		"x.php\r\n":   {"x.php\r\n", "x.php"},
		"x.p\nhp":     {"x.p\nhp", "x.p", "x.php"},
		"x.php\n.jpg": {"x.php\n.jpg", "x.php", "x.php.jpg"},
	}
	for name, want := range cases {
		got := lineBreakNameSpellings(name)
		if len(got) != len(want) {
			t.Errorf("lineBreakNameSpellings(%q) = %q, want %q", name, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("lineBreakNameSpellings(%q)[%d] = %q, want %q", name, i, got[i], want[i])
			}
		}
	}
}
