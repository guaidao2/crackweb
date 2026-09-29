package httpmsg

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

// jsonRequest builds a POST carrying a JSON body, which is what an API client would send.
func jsonRequest(t *testing.T, body string) *Request {
	t.Helper()
	req, err := NewRequest("POST", "http://example.com/api/items")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Body = []byte(body)
	return req
}

func paramNames(params []Param) []string {
	out := make([]string, 0, len(params))
	for _, param := range params {
		out = append(out, param.Name)
	}
	return out
}

func TestJSONBodyFieldsAreAddressable(t *testing.T) {
	req := jsonRequest(t, `{"id":1,"user":{"name":"bob"},"tags":["a","b"]}`)

	params := req.BodyParams()
	want := []string{"id", "user.name", "tags.0", "tags.1"}
	if got := paramNames(params); !reflect.DeepEqual(got, want) {
		t.Fatalf("field names = %v, want %v", got, want)
	}
	if params[0].In != LocJSON {
		t.Errorf("location = %q, want %q", params[0].In, LocJSON)
	}
	if params[1].Value != "bob" {
		t.Errorf("nested value = %q, want %q", params[1].Value, "bob")
	}
	if got, want := strings.Join(params[2].Path, "/"), "tags/0"; got != want {
		t.Errorf("array path = %q, want %q", got, want)
	}
}

func TestJSONRewriteKeepsEveryOtherByte(t *testing.T) {
	body := `{"a":1,"b":"two","c":{"d":3}}`
	updated, ok := RewriteBody([]byte(body), "application/json",
		Param{In: LocJSON, Path: []string{"c", "d"}, Name: "c.d"}, "9")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	for _, kept := range []string{`"a":1`, `"b":"two"`, `"c":{`} {
		if !strings.Contains(string(updated), kept) {
			t.Errorf("rewrite lost %s: %s", kept, updated)
		}
	}
	if want := `{"a":1,"b":"two","c":{"d":"9"}}`; string(updated) != want {
		t.Errorf("rewritten body\n got: %s\nwant: %s", updated, want)
	}
}

func TestJSONRewriteQuotesPayloadButKeepsAngleBrackets(t *testing.T) {
	// The angle brackets are left as they are on purpose: escaping them would hide the
	// reflection a cross-site scripting check is looking for.
	updated, ok := RewriteBody([]byte(`{"name":"x"}`), "application/json",
		Param{In: LocJSON, Path: []string{"name"}, Name: "name"}, `a"<script>b`)
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	if want := `{"name":"a\"<script>b"}`; string(updated) != want {
		t.Errorf("rewritten body\n got: %s\nwant: %s", updated, want)
	}
}

func TestJSONRewriteEscapesControlCharacters(t *testing.T) {
	updated, ok := RewriteBody([]byte(`{"k":"x"}`), "application/json",
		Param{In: LocJSON, Path: []string{"k"}, Name: "k"}, "a\nb\\c\x01")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	if want := `{"k":"a\nb\\c\u0001"}`; string(updated) != want {
		t.Errorf("rewritten body\n got: %s\nwant: %s", updated, want)
	}
}

func TestJSONRewriteUsesOccurrenceForRepeatedKeys(t *testing.T) {
	body := `{"id":1,"id":2}`
	params := jsonRequest(t, body).BodyParams()
	if len(params) != 2 || params[1].Occurrence != 1 {
		t.Fatalf("unexpected parameters: %+v", params)
	}
	updated, ok := RewriteBody([]byte(body), "application/json", params[1], "7")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	if want := `{"id":1,"id":"7"}`; string(updated) != want {
		t.Errorf("rewritten body\n got: %s\nwant: %s", updated, want)
	}
}

func TestJSONBodyRejectsScalarAndMalformedDocuments(t *testing.T) {
	for _, body := range []string{`12345`, `"just a string"`, `{"a":`, `{`, `not json at all`} {
		if params := jsonRequest(t, body).BodyParams(); params != nil {
			t.Errorf("body %q produced %d parameters, want none", body, len(params))
		}
	}
}

func TestJSONBodyHandlesDeepNestingWithoutFailing(t *testing.T) {
	body := strings.Repeat(`{"k":`, 40) + "1" + strings.Repeat("}", 40)
	if params := jsonRequest(t, body).BodyParams(); len(params) != 0 {
		t.Errorf("deeply nested document produced %d parameters, want none", len(params))
	}
}

func TestBase64JSONBodyIsUnwrappedAndRewritten(t *testing.T) {
	document := `{"id":"1"}`
	body := base64.StdEncoding.EncodeToString([]byte(document))
	req := jsonRequest(t, body)

	params := req.BodyParams()
	if len(params) != 1 || params[0].In != LocJSONBase64 {
		t.Fatalf("unexpected parameters: %+v", params)
	}

	updated, ok := RewriteBody([]byte(body), "application/json", params[0], "1'")
	if !ok {
		t.Fatalf("rewrite reported failure")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(updated))
	if err != nil {
		t.Fatalf("rewritten body is not valid base64: %v", err)
	}
	if want := `{"id":"1'"}`; string(decoded) != want {
		t.Errorf("decoded body\n got: %s\nwant: %s", decoded, want)
	}
}

func TestVendorJSONContentTypeIsRecognised(t *testing.T) {
	req := jsonRequest(t, `{"id":1}`)
	req.Header.Set("Content-Type", "application/vnd.api+json; charset=utf-8")
	if params := req.BodyParams(); len(params) != 1 {
		t.Errorf("vendor JSON type produced %d parameters, want 1", len(params))
	}
}
