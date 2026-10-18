package httpmsg

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// cookieRequest builds a GET whose Cookie field carries the given header value.
func cookieRequest(t *testing.T, header string) *Request {
	t.Helper()
	req, err := NewRequest("GET", "http://example.test/prefs")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Cookie", header)
	return req
}

// textPartBody builds a one-part multipart body whose content is value.
func textPartBody(value string) string {
	return "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="v"` + "\r\n\r\n" +
		value + "\r\n" +
		"--" + testBoundary + "--\r\n"
}

// TestBase64ScalarParameterIsAddressable: a parameter whose value is base64 text is
// addressed as the text the application decodes, and a mutation is re-encoded before it
// is sent. Without this, a payload is written into the base64 text itself and the
// application decodes it to something that is not the payload.
func TestBase64ScalarParameterIsAddressable(t *testing.T) {
	req, err := NewRequest("GET", "http://example.test/search?nameb64=YQ%3D%3D")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	var param *Param
	for _, candidate := range req.Params() {
		if candidate.Wrapper == WrapBase64 {
			copied := candidate
			param = &copied
			break
		}
	}
	if param == nil {
		t.Fatal("the base64 scalar was not addressed")
	}
	if got := req.Params(); len(got) != 2 {
		t.Fatalf("got %d parameters, want the original and the decoded value", len(got))
	}
	if got := req.Params()[0]; got.Wrapper != WrapNone || got.Name != "nameb64" {
		t.Errorf("the original parameter was not retained: %+v", got)
	}
	if param.Name != "nameb64.base64" || param.Value != "a" || param.Base64Style != base64StyleStd {
		t.Errorf("param = %+v, want nameb64.base64 with value a in std style", param)
	}
	if got, want := param.Key(), "query:nameb64#0/base64#0"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}

	payload := "' OR 1=1-- -"
	mutated, ok := RewriteWrapped(req, *param, payload)
	if !ok {
		t.Fatal("the base64 scalar could not be rewritten")
	}
	encoded := mutated.URL.Query().Get("nameb64")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("the rewritten value is not base64: %v", err)
	}
	if string(decoded) != payload {
		t.Errorf("decoded value = %q, want the payload %q", decoded, payload)
	}
}

// TestBase64ScalarKeepsTheOriginalAlphabet: URL-safe, unpadded input stays URL-safe and
// unpadded. Sending the standard padded form back changes the value's shape as well as
// its content.
func TestBase64ScalarKeepsTheOriginalAlphabet(t *testing.T) {
	original := base64.RawURLEncoding.EncodeToString([]byte("hello??"))
	req, err := NewRequest("GET", "http://example.test/search?v="+original)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	var param *Param
	for _, candidate := range req.Params() {
		if candidate.Wrapper == WrapBase64 {
			copied := candidate
			param = &copied
			break
		}
	}
	if param == nil {
		t.Fatal("the URL-safe base64 scalar was not addressed")
	}
	if param.Base64Style != base64StyleURLRaw {
		t.Errorf("style = %q, want %q", param.Base64Style, base64StyleURLRaw)
	}
	payload := "x' OR '1'='1"
	mutated, ok := RewriteWrapped(req, *param, payload)
	if !ok {
		t.Fatal("rewrite failed")
	}
	encoded := mutated.URL.Query().Get("v")
	if strings.ContainsAny(encoded, "+/=") {
		t.Errorf("rewritten value %q is not URL-safe and unpadded", encoded)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || string(decoded) != payload {
		t.Errorf("decoded value = %q (err=%v), want %q", decoded, err, payload)
	}
}

// TestBase64ScalarLeavesTokensAndHashesAlone: a base64 alphabet is not evidence of text.
// A JWT, a hex digest and a binary-looking session id are not turned into injection points.
func TestBase64ScalarLeavesTokensAndHashesAlone(t *testing.T) {
	for _, value := range []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature",
		"5f4dcc3b5aa765d61d8327deb882cf99",
		"AAECAwQFBgcICQ==",
	} {
		req, err := NewRequest("GET", "http://example.test/x?v="+value)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		for _, param := range req.Params() {
			if param.Wrapper == WrapBase64 {
				t.Errorf("%q was addressed as a base64 scalar", value)
			}
		}
	}
}

// TestShortOrdinaryValuesAreNotBase64: a two- or three-letter value decodes under a
// non-padded decoder, but its canonical base64 spelling is different. It is an ordinary
// value, not an encoded one.
func TestShortOrdinaryValuesAreNotBase64(t *testing.T) {
	for _, value := range []string{"en", "all", "and", "any", "US"} {
		req, err := NewRequest("GET", "http://example.test/x?p="+value)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		for _, param := range req.Params() {
			if param.Wrapper == WrapBase64 {
				t.Errorf("%q was addressed as a base64 scalar", value)
			}
		}
	}
}

// TestBase64ScalarInAFormBody: the same decoding applies to a form value, not only to a
// query parameter.
func TestBase64ScalarInAFormBody(t *testing.T) {
	req, err := NewRequest("POST", "http://example.test/search")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Body = []byte("nameb64=YQ%3D%3D")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	found := false
	for _, param := range req.Params() {
		if param.Wrapper == WrapBase64 && param.In == LocBody && param.Value == "a" {
			found = true
		}
	}
	if !found {
		t.Error("the base64 scalar in the form body was not addressed")
	}
}

// TestBase64ScalarInACookieIsAddressable: a cookie value that is base64 text is addressed
// as the text the application decodes, and a mutation is re-encoded and written back into
// the Cookie field beside its neighbours.
func TestBase64ScalarInACookieIsAddressable(t *testing.T) {
	original := base64.StdEncoding.EncodeToString([]byte("hello"))
	req := cookieRequest(t, "sid=9f8c2; prefs="+original)

	params := req.Params()
	if len(params) != 3 {
		t.Fatalf("got %d parameters, want two cookies and the decoded value: %+v", len(params), params)
	}
	// The cookie keeps its own entry: a target may use the value as well as decode it.
	if params[1].Name != "prefs" || params[1].Wrapper != WrapNone {
		t.Errorf("the original cookie was not retained: %+v", params[1])
	}
	param := params[2]
	if param.Name != "prefs.base64" || param.In != LocCookie || param.Value != "hello" ||
		param.Wrapper != WrapBase64 || param.Base64Style != base64StyleStd {
		t.Fatalf("param = %+v, want prefs.base64 in the cookie location carrying %q", param, "hello")
	}
	if got, want := param.Key(), "cookie:prefs#0/base64#0"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}

	payload := "a' OR '1'='1"
	mutated, ok := RewriteWrapped(req, param, payload)
	if !ok {
		t.Fatal("the base64 cookie could not be rewritten")
	}
	header := mutated.Header.Get("Cookie")
	if !strings.Contains(header, "sid=9f8c2") {
		t.Errorf("the neighbouring cookie was disturbed: %q", header)
	}
	// The Cookie field is read back by hand rather than through CookieParams: the query
	// decoder it shares turns '+' into a space, which is not what a cookie value means.
	var rewritten string
	for _, segment := range strings.Split(header, ";") {
		if name, value, ok := strings.Cut(strings.TrimSpace(segment), "="); ok && name == "prefs" {
			rewritten = value
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(rewritten)
	if err != nil {
		t.Fatalf("the rewritten cookie is not base64 (%v): %q", err, rewritten)
	}
	if string(decoded) != payload {
		t.Errorf("decoded cookie = %q, want the payload %q", decoded, payload)
	}
}

// TestBase64ScalarInACookieKeepsItsPlusSigns: a cookie value is not form-encoded, so a '+'
// in it is a literal plus. The query decoder the other locations share turns it into a
// space, which would leave every standard-alphabet base64 cookie whose encoding contains
// one unaddressed — and a value that is not addressed reads in the report as one that was
// tested and found clean.
func TestBase64ScalarInACookieKeepsItsPlusSigns(t *testing.T) {
	// "a~~" encodes to "YX5+": printable text with an alphanumeric byte, and a '+' that a
	// form decoder would eat.
	original := base64.StdEncoding.EncodeToString([]byte("a~~"))
	if !strings.Contains(original, "+") {
		t.Fatalf("the fixture %q does not contain the '+' this test is about", original)
	}
	req := cookieRequest(t, "blob="+original)

	var param *Param
	for _, candidate := range req.Params() {
		if candidate.Wrapper == WrapBase64 {
			copied := candidate
			param = &copied
			break
		}
	}
	if param == nil {
		t.Fatal("the base64 cookie carrying a plus was not addressed")
	}
	if param.Name != "blob.base64" || param.Value != "a~~" || param.Base64Style != base64StyleStd {
		t.Fatalf("param = %+v, want blob.base64 carrying %q in std style", param, "a~~")
	}

	payload := "'; cat /etc/passwd; '"
	mutated, ok := RewriteWrapped(req, *param, payload)
	if !ok {
		t.Fatal("the base64 cookie could not be rewritten")
	}
	var rewritten string
	for _, segment := range strings.Split(mutated.Header.Get("Cookie"), ";") {
		if name, value, ok := strings.Cut(strings.TrimSpace(segment), "="); ok && name == "blob" {
			rewritten = value
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(rewritten)
	if err != nil {
		t.Fatalf("the rewritten cookie is not base64 (%v): %q", err, rewritten)
	}
	if string(decoded) != payload {
		t.Errorf("decoded cookie = %q, want the payload %q", decoded, payload)
	}
}

// TestBase64ScalarInAJSONFieldIsAddressable: a JSON field whose string value is base64 is
// addressed as the text it decodes to, and a mutation is re-encoded into the document with
// every other field left as it was.
func TestBase64ScalarInAJSONFieldIsAddressable(t *testing.T) {
	original := base64.StdEncoding.EncodeToString([]byte("hello"))
	req := jsonRequest(t, `{"name":"`+original+`","page":2}`)

	params := req.Params()
	if len(params) != 3 {
		t.Fatalf("got %d parameters, want name, page and name.base64: %+v", len(params), params)
	}
	if params[0].Name != "name" || params[0].Wrapper != WrapNone {
		t.Errorf("the original field was not retained: %+v", params[0])
	}
	param := params[2]
	if param.Name != "name.base64" || param.In != LocJSON || param.Value != "hello" ||
		param.Wrapper != WrapBase64 || !reflect.DeepEqual(param.Path, []string{"name"}) {
		t.Fatalf("param = %+v, want name.base64 in the json location carrying %q", param, "hello")
	}
	if got, want := param.Key(), "json:name#0/base64#0"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}

	payload := `' OR 1=1-- -`
	mutated, ok := RewriteWrapped(req, param, payload)
	if !ok {
		t.Fatal("the base64 field could not be rewritten")
	}
	want := `{"name":"` + base64.StdEncoding.EncodeToString([]byte(payload)) + `","page":2}`
	if got := string(mutated.Body); got != want {
		t.Fatalf("rewritten body\n got: %s\nwant: %s", got, want)
	}
	var document map[string]any
	if err := json.Unmarshal(mutated.Body, &document); err != nil {
		t.Fatalf("the rewritten body is no longer JSON (%v): %s", err, mutated.Body)
	}
	decoded, err := base64.StdEncoding.DecodeString(document["name"].(string))
	if err != nil || string(decoded) != payload {
		t.Errorf("decoded field = %q (err=%v), want the payload %q", decoded, err, payload)
	}
}

// TestBase64ScalarInsideABase64JSONBodyIsRewritten: a JSON document that arrives
// base64-encoded is decoded once for its fields, and the base64 scalar inside one of them
// is decoded a second time. Both envelopes are rebuilt around the mutation, and the inner
// value keeps its own alphabet.
func TestBase64ScalarInsideABase64JSONBodyIsRewritten(t *testing.T) {
	inner := base64.RawURLEncoding.EncodeToString([]byte("hello??"))
	document := `{"q":"` + inner + `"}`
	req := jsonRequest(t, base64.StdEncoding.EncodeToString([]byte(document)))

	params := req.Params()
	if len(params) != 2 {
		t.Fatalf("got %d parameters, want q and q.base64: %+v", len(params), params)
	}
	param := params[1]
	if param.Name != "q.base64" || param.In != LocJSONBase64 || param.Value != "hello??" {
		t.Fatalf("param = %+v, want q.base64 in the base64 json location carrying %q", param, "hello??")
	}
	if param.Base64Style != base64StyleURLRaw {
		t.Errorf("style = %q, want %q", param.Base64Style, base64StyleURLRaw)
	}

	payload := "x' OR '1'='1"
	mutated, ok := RewriteWrapped(req, param, payload)
	if !ok {
		t.Fatal("rewrite failed")
	}
	decodedBody, ok := decodeBase64JSON(mutated.Body)
	if !ok {
		t.Fatalf("the rewritten body is no longer base64 JSON: %s", mutated.Body)
	}
	var rewritten map[string]any
	if err := json.Unmarshal(decodedBody, &rewritten); err != nil {
		t.Fatalf("the rewritten document is no longer JSON (%v): %s", err, decodedBody)
	}
	field, ok := rewritten["q"].(string)
	if !ok {
		t.Fatalf("q is not a string any more: %v", rewritten["q"])
	}
	if strings.ContainsAny(field, "+/=") {
		t.Errorf("rewritten value %q is not URL-safe and unpadded", field)
	}
	value, err := base64.RawURLEncoding.DecodeString(field)
	if err != nil || string(value) != payload {
		t.Errorf("decoded field = %q (err=%v), want %q", value, err, payload)
	}
}

// TestBase64ScalarInAMultipartTextPart: a text part whose content is base64 is addressed as
// the decoded text, and a mutation is re-encoded into that part alone.
func TestBase64ScalarInAMultipartTextPart(t *testing.T) {
	body := "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="payload"` + "\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte("hello")) + "\r\n" +
		"--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="note"` + "\r\n\r\n" +
		"thanks\r\n" +
		"--" + testBoundary + "--\r\n"
	req := multipartRequest(t, body)

	params := req.Params()
	if len(params) != 3 {
		t.Fatalf("got %d parameters, want payload, note and payload.base64: %+v", len(params), params)
	}
	param := params[2]
	if param.Name != "payload.base64" || param.In != LocMultipart || param.Value != "hello" ||
		param.Wrapper != WrapBase64 {
		t.Fatalf("param = %+v, want payload.base64 in the multipart location carrying %q", param, "hello")
	}
	if got, want := param.Key(), "multipart:payload#0/base64#0"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}

	payload := "'; cat /etc/passwd; '"
	mutated, ok := RewriteWrapped(req, param, payload)
	if !ok {
		t.Fatal("the base64 part could not be rewritten")
	}
	got := string(mutated.Body)
	if !strings.Contains(got, "--"+testBoundary+"--\r\n") {
		t.Errorf("the closing boundary was lost:\n%s", got)
	}
	if !strings.Contains(got, "thanks") {
		t.Errorf("the sibling part changed:\n%s", got)
	}
	parts := multipartRequest(t, got).BodyParams()
	if len(parts) != 2 || parts[0].Name != "payload" || parts[0].Value == "" {
		t.Fatalf("the rewritten body no longer parses into the same parts: %+v", parts)
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[0].Value)
	if err != nil || string(decoded) != payload {
		t.Errorf("part content = %q (err=%v), want base64 of %q", parts[0].Value, err, payload)
	}
}

// TestBase64ScalarInAMultipartFileName: a file name that is base64 text is addressed the
// same way, and a mutation is re-encoded into the part's Content-Disposition while the file
// itself is left alone.
func TestBase64ScalarInAMultipartFileName(t *testing.T) {
	body := "--" + testBoundary + "\r\n" +
		`Content-Disposition: form-data; name="upload"; filename="` +
		base64.StdEncoding.EncodeToString([]byte("invoice")) + `"` + "\r\n" +
		"Content-Type: application/pdf\r\n\r\n" +
		"file-contents\r\n" +
		"--" + testBoundary + "--\r\n"
	req := multipartRequest(t, body)

	params := req.Params()
	if len(params) != 2 {
		t.Fatalf("got %d parameters, want the file name and its decoded value: %+v", len(params), params)
	}
	param := params[1]
	if param.Name != "upload.base64" || param.In != LocMultipartFilename || param.Value != "invoice" ||
		param.Wrapper != WrapBase64 {
		t.Fatalf("param = %+v, want upload.base64 carrying %q in the file name", param, "invoice")
	}

	payload := "../../shell.php"
	mutated, ok := RewriteWrapped(req, param, payload)
	if !ok {
		t.Fatal("the base64 file name could not be rewritten")
	}
	want := `filename="` + base64.StdEncoding.EncodeToString([]byte(payload)) + `"`
	if !strings.Contains(string(mutated.Body), want) {
		t.Errorf("the file name was not re-encoded (%s missing):\n%s", want, mutated.Body)
	}
	if !strings.Contains(string(mutated.Body), "file-contents") {
		t.Errorf("the rewrite touched the file content:\n%s", mutated.Body)
	}
}

// TestBase64ScalarGuardsHoldInEveryLocation: the checks that keep a token, a hash or an
// ordinary short value out of the parameter list are the same wherever the value sits.
func TestBase64ScalarGuardsHoldInEveryLocation(t *testing.T) {
	// A hex digest, bytes rather than text, two values that decode only under a
	// non-padded decoder (and not canonically), and a JWT, whose segments are not one
	// base64 value.
	values := []string{
		"5f4dcc3b5aa765d61d8327deb882cf99",
		"AAECAwQFBgcICQ==",
		"en",
		"all",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature",
	}
	for _, value := range values {
		requests := []*Request{
			cookieRequest(t, "v="+value),
			jsonRequest(t, `{"v":"`+value+`"}`),
			multipartRequest(t, textPartBody(value)),
		}
		for _, req := range requests {
			for _, param := range req.Params() {
				if param.Wrapper == WrapBase64 {
					t.Errorf("%q was addressed as a base64 scalar at %s:%s", value, param.In, param.Name)
				}
			}
		}
	}
}

// TestBase64ScalarNeedsItsEnclosingValuePresent: a rewrite that cannot find the value it
// addresses reports failure instead of sending a request the parameter never reached.
func TestBase64ScalarNeedsItsEnclosingValuePresent(t *testing.T) {
	req := cookieRequest(t, "prefs="+base64.StdEncoding.EncodeToString([]byte("hello")))
	var param Param
	for _, candidate := range req.Params() {
		if candidate.Wrapper == WrapBase64 {
			param = candidate
		}
	}
	if param.Name == "" {
		t.Fatal("the base64 cookie was not addressed")
	}
	req.Header.Del("Cookie")
	if _, ok := RewriteWrapped(req, param, "x"); ok {
		t.Error("a rewrite with no cookie to write into reported success")
	}
}
