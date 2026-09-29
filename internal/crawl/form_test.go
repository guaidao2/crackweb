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
	if strings.Contains(text, `name="go"`) {
		t.Errorf("submit control should not be submitted:\n%s", text)
	}

	if got := scannerSees(t, body, contentType); got != 2 {
		t.Errorf("scanner sees %d addressable fields, want 2 (the text field and the file name)", got)
	}
}
