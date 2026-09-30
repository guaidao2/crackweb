package active

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDecodedViewsLeavesAnOrdinaryPageAlone is the bound the whole function rests on: a page
// that is not an encoding of anything must not be read as one.
func TestDecodedViewsLeavesAnOrdinaryPageAlone(t *testing.T) {
	page := "<html><body><h1>Welcome to the application</h1>" +
		"<p>Sign in with your account to continue. Contact support if you need help.</p></body></html>"
	views := decodedViews([]byte(page))
	if len(views) != 1 || views[0] != page {
		t.Errorf("an ordinary page produced %d views", len(views))
	}
}

// TestDecodedViewsFindsBase64AndHex: the two encodings a target prints a file through.
func TestDecodedViewsFindsBase64AndHex(t *testing.T) {
	file := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	cases := map[string]string{
		"base64": "<pre>" + base64.StdEncoding.EncodeToString([]byte(file)) + "</pre>",
		"hex":    "<pre>" + hex.EncodeToString([]byte(file)) + "</pre>",
	}
	for name, body := range cases {
		views := decodedViews([]byte(body))
		joined := strings.Join(views, "\n")
		if !strings.Contains(joined, "root:x:0:0") {
			t.Errorf("%s: the file's own line was not recovered from %q", name, body[:40])
		}
	}
}

// TestDecodedViewsIgnoresShortRuns: a word that happens to use the alphabet is not an encoding.
func TestDecodedViewsIgnoresShortRuns(t *testing.T) {
	page := "<p>token: abc123def456ghi789</p>"
	if views := decodedViews([]byte(page)); len(views) != 1 {
		t.Errorf("a short alphanumeric run was treated as an encoding: %v", views)
	}
}

// TestDecodedViewsIgnoresRunsThatDecodeToNoise: a long base64-looking run that decodes to bytes
// no page would contain is not evidence of anything.
func TestDecodedViewsIgnoresRunsThatDecodeToNoise(t *testing.T) {
	noise := make([]byte, 64)
	for i := range noise {
		noise[i] = byte(i*7%251 + 1) // control characters and high bytes
	}
	body := "<pre>" + base64.StdEncoding.EncodeToString(noise) + "</pre>"
	if views := decodedViews([]byte(body)); len(views) != 1 {
		t.Errorf("a run that decodes to noise was treated as text: %v", views)
	}
}
