package httpmsg

import (
	"strings"
	"testing"
)

// TestMultipartEmptyFilenameIsAddressable: an upload form declares its file input with
// no name until the user chooses a file. The empty value is still the field an upload
// endpoint turns into the stored name, so it has to be an injection point like any
// other.
func TestMultipartEmptyFilenameIsAddressable(t *testing.T) {
	body := "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="upload"; filename=""` + "\r\n" +
		"Content-Type: image/png\r\n" +
		"\r\n" +
		"\r\n" +
		"--" + testBoundary + "--\r\n"

	params := multipartRequest(t, body).BodyParams()
	if len(params) != 1 {
		t.Fatalf("got %d parameters, want one file name: %+v", len(params), params)
	}
	if params[0].In != LocMultipartFilename || params[0].Value != "" {
		t.Fatalf("unexpected parameter: %+v", params[0])
	}

	updated, ok := RewriteBody([]byte(body), testMultipartType, params[0], "crackweb.php")
	if !ok {
		t.Fatal("rewrite reported failure")
	}
	if !strings.Contains(string(updated), `filename="crackweb.php"`) {
		t.Errorf("file name was not replaced:\n%s", updated)
	}
}
