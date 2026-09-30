package crawl

import (
	"net/url"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

func parseSingleForm(t *testing.T, document string) Form {
	t.Helper()
	base, err := url.Parse("http://example.com/page")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	page, err := Parse(document, base, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(page.Forms) != 1 {
		t.Fatalf("got %d forms, want 1", len(page.Forms))
	}
	return page.Forms[0]
}

// scannerSees reports how many addressable fields the scanner finds in a body. A crawled
// upload form has to be reachable by the same reader that handles captured traffic, or
// the two paths would be tested differently.
func scannerSees(t *testing.T, body []byte, contentType string) int {
	t.Helper()
	req, err := httpmsg.NewRequest("POST", "http://example.com/upload")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Body = body
	return len(req.BodyParams())
}

func TestFormRecordsItsEncoding(t *testing.T) {
	form := parseSingleForm(t, `<html><body>
		<form action="/upload" method="post" enctype="multipart/form-data">
			<input type="file" name="filename">
		</form></body></html>`)

	if form.Enctype != "multipart/form-data" {
		t.Errorf("Enctype = %q", form.Enctype)
	}
	if !form.IsMultipart() {
		t.Error("form with a file input should be submitted as multipart")
	}
}

func TestFormWithFileInputIsMultipartEvenWithoutEnctype(t *testing.T) {
	// A page that omits the attribute still carries a file input, and a server expecting
	// an upload refuses a urlencoded body outright.
	form := parseSingleForm(t, `<html><body>
		<form action="/upload" method="post">
			<input type="file" name="attachment">
		</form></body></html>`)

	if !form.IsMultipart() {
		t.Error("form carrying a file input should be submitted as multipart")
	}
}

func TestOrdinaryFormIsNotMultipart(t *testing.T) {
	form := parseSingleForm(t, `<html><body>
		<form action="/login" method="post">
			<input type="text" name="user" value="admin">
		</form></body></html>`)

	if form.IsMultipart() {
		t.Error("plain form should not be submitted as multipart")
	}
	if got, want := form.EncodeBody(), "user=admin"; got != want {
		t.Errorf("EncodeBody() = %q, want %q", got, want)
	}
}

func TestEncodeMultipartCarriesFieldsAndAFilePart(t *testing.T) {
	form := parseSingleForm(t, `<html><body>
		<form action="/upload" method="post" enctype="multipart/form-data">
			<input type="text" name="title" value="report">
			<input type="file" name="filename">
			<input type="submit" name="go" value="Send">
		</form></body></html>`)

	body, contentType := form.EncodeMultipart()

	if !strings.HasPrefix(contentType, "multipart/form-data; boundary=") {
		t.Fatalf("Content-Type = %q", contentType)
	}
	boundary := strings.TrimPrefix(contentType, "multipart/form-data; boundary=")
	if boundary == "" {
		t.Fatal("empty boundary")
	}

	text := string(body)
	for _, want := range []string{
		"--" + boundary + "\r\n",
		`name="title"`,
		"report",
		`name="filename"; filename="` + placeholderUploadName + `"`,
		placeholderUploadBody,
		"--" + boundary + "--\r\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("body is missing %q:\n%s", want, text)
		}
	}
	// The submit button is submitted: a handler that runs only when it is present would
	// otherwise see a request that was never submitted. It is addressable, so the scanner
	// sees three fields, not two.
	if !strings.Contains(text, `name="go"`) {
		t.Errorf("submit control was dropped from the body:\n%s", text)
	}

	if got := scannerSees(t, body, contentType); got != 3 {
		t.Errorf("scanner sees %d addressable fields, want 3 (text, file and submit)", got)
	}
}

// TestFormRequestsBuildsWhatTheFormDeclares pins the shape a scan depends on: a form is only
// testable through the request it produces, so the verb, the action, the encoding and the
// fields all have to survive the conversion.
func TestFormRequestsBuildsWhatTheFormDeclares(t *testing.T) {
	base, _ := url.Parse("http://target.example/account/login")

	post := Form{
		Action: "/account/session",
		Method: "POST",
		Fields: []Field{{Name: "user", Value: "a", Type: "text"}, {Name: "pass", Value: "b", Type: "password"}},
	}
	requests := FormRequests(post, base)
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(requests))
	}
	if got := requests[0].Method; got != "POST" {
		t.Errorf("method = %q, want POST", got)
	}
	if got := requests[0].URLString(); got != "http://target.example/account/session" {
		t.Errorf("url = %q", got)
	}
	if got := requests[0].Header.Get("Content-Type"); !strings.Contains(got, "x-www-form-urlencoded") {
		t.Errorf("content type = %q", got)
	}
	if body := string(requests[0].Body); !strings.Contains(body, "user=a") || !strings.Contains(body, "pass=b") {
		t.Errorf("body = %q, want both fields", body)
	}

	get := Form{Action: "/search", Method: "GET", Fields: []Field{{Name: "q", Value: "x"}}}
	requests = FormRequests(get, base)
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(requests))
	}
	if got := requests[0].URLString(); !strings.HasPrefix(got, "http://target.example/search?") {
		t.Errorf("url = %q, want the fields in the query", got)
	}

	// An empty action posts back to the page the form was found on.
	empty := Form{Method: "POST", Fields: []Field{{Name: "a", Value: "1"}}}
	requests = FormRequests(empty, base)
	if len(requests) != 1 || requests[0].URLString() != "http://target.example/account/login" {
		t.Errorf("an empty action did not resolve to the page itself: %v", requests)
	}
}

// TestEncodedFormKeepsTheControlsThePageUsesToRecogniseItself pins the fix that made
// pikachu's forms testable at all: a body without the submit button is a request the
// application ignores, because `isset($_POST['submit'])` is how a PHP handler decides
// whether it was submitted. sqlmap keeps these controls for the same reason.
func TestEncodedFormKeepsTheControlsThePageUsesToRecogniseItself(t *testing.T) {
	form := Form{
		Action: "/vul/sqli/x.php",
		Method: "POST",
		Fields: []Field{
			{Name: "name", Value: "k", Type: "text"},
			{Name: "submit", Value: "查询", Type: "submit"},
			{Name: "remember", Value: "1", Type: "checkbox"},
			{Name: "kind", Value: "x", Type: "radio"},
			{Name: "hidden_token", Value: "t", Type: "hidden"},
		},
	}

	body := form.EncodeBody()
	for _, want := range []string{"name=k", "submit=", "remember=1", "kind=x", "hidden_token=t"} {
		if !strings.Contains(body, want) {
			t.Errorf("urlencoded body %q is missing %q", body, want)
		}
	}

	multipart, contentType := form.EncodeMultipart()
	if !strings.Contains(contentType, "multipart/form-data") {
		t.Errorf("content type = %q", contentType)
	}
	for _, want := range []string{`name="name"`, `name="submit"`, `name="remember"`, `name="kind"`, `name="hidden_token"`} {
		if !strings.Contains(string(multipart), want) {
			t.Errorf("multipart body is missing %s", want)
		}
	}
}

// TestUrlencodedFormStillLeavesOutFiles: a file part cannot go into a urlencoded body, and a
// form carrying one is sent as multipart instead.
func TestUrlencodedFormStillLeavesOutFiles(t *testing.T) {
	form := Form{Fields: []Field{
		{Name: "note", Value: "hi", Type: "text"},
		{Name: "attachment", Value: "", Type: "file"},
	}}
	if body := form.EncodeBody(); strings.Contains(body, "attachment") {
		t.Errorf("a file field reached a urlencoded body: %q", body)
	}
}
