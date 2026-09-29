package httpmsg

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// wrappedRequest builds a request whose parameter carries a JSON document.
func wrappedRequest(t *testing.T, value string) *Request {
	t.Helper()
	req, err := NewRequest("GET", "http://example.com/user?id="+url.QueryEscape(value))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func TestWrappedJSONDocumentFieldsAreAddressable(t *testing.T) {
	req := wrappedRequest(t, `{"uid":1,"id":"1"}`)

	params := req.Params()
	want := []string{"id", "id.uid", "id.id"}
	if got := paramNames(params); !reflect.DeepEqual(got, want) {
		t.Fatalf("parameter names = %v, want %v", got, want)
	}
	// The parameter itself keeps its place: a target may use the value as a whole as well
	// as parse it, and dropping it would lose that.
	if params[0].Wrapper != WrapNone {
		t.Errorf("the outer parameter was wrapped: %+v", params[0])
	}
	if params[1].Wrapper != WrapJSON || params[1].Outer != "id" || params[1].Value != "1" {
		t.Errorf("unexpected inner parameter: %+v", params[1])
	}
	if got, want := params[1].Key(), "query:id#0/uid#0"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
}

func TestWrappedJSONRewriteKeepsTheEnvelopeValid(t *testing.T) {
	req := wrappedRequest(t, `{"uid":1,"id":"1"}`)

	var target Param
	for _, param := range req.Params() {
		if param.Name == "id.uid" {
			target = param
		}
	}
	if target.Name == "" {
		t.Fatal("the field inside the document was not addressable")
	}

	updated, ok := RewriteWrapped(req, target, "1'")
	if !ok {
		t.Fatal("rewrite reported failure")
	}

	value := updated.URL.Query().Get("id")
	var document map[string]any
	if err := json.Unmarshal([]byte(value), &document); err != nil {
		t.Fatalf("the rewritten value is no longer JSON (%v): %s", err, value)
	}
	if document["uid"] != "1'" {
		t.Errorf("uid = %v, want %q", document["uid"], "1'")
	}
	if document["id"] != "1" {
		t.Errorf("the sibling field changed: %v", document["id"])
	}
}

func TestWrappedBase64JSONDocumentIsUnwrappedAndRewritten(t *testing.T) {
	document := `{"uid":1,"id":"1"}`
	req := wrappedRequest(t, base64.StdEncoding.EncodeToString([]byte(document)))

	params := req.Params()
	if len(params) != 3 {
		t.Fatalf("got %d parameters, want 3", len(params))
	}
	if params[1].Wrapper != WrapBase64JSON {
		t.Fatalf("wrapper = %v, want base64 JSON", params[1].Wrapper)
	}

	updated, ok := RewriteWrapped(req, params[1], "1'")
	if !ok {
		t.Fatal("rewrite reported failure")
	}
	decoded, err := base64.StdEncoding.DecodeString(updated.URL.Query().Get("id"))
	if err != nil {
		t.Fatalf("the rewritten value is no longer base64: %v", err)
	}
	if want := `{"uid":"1'","id":"1"}`; string(decoded) != want {
		t.Errorf("decoded = %s, want %s", decoded, want)
	}
}

func TestWrappedNestedPathIsAddressable(t *testing.T) {
	req := wrappedRequest(t, `{"user":{"name":"bob"},"tags":["a"]}`)
	if got, want := paramNames(req.Params()), []string{"id", "id.user.name", "id.tags.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parameter names = %v, want %v", got, want)
	}
}

func TestOrdinaryValuesAreNotUnwrapped(t *testing.T) {
	// A value that merely looks encoded is not a document, and treating it as one would
	// add parameters that do not exist.
	for _, value := range []string{"hello", "12345", "aGVsbG8=", "{not json", "1,2,3"} {
		req := wrappedRequest(t, value)
		if got := req.Params(); len(got) != 1 {
			t.Errorf("value %q produced %d parameters, want 1", value, len(got))
		}
	}
}

func TestWrappedDocumentInsideAFormBodyIsAddressable(t *testing.T) {
	req, err := NewRequest("POST", "http://example.com/api")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = []byte("id=" + url.QueryEscape(`{"uid":7}`) + "&other=x")

	names := paramNames(req.Params())
	if !reflect.DeepEqual(names, []string{"id", "other", "id.uid"}) {
		t.Fatalf("parameter names = %v", names)
	}
}

// TestOversizedValuesAreNotDecoded: the parameter list is built on the deduplication path,
// once per submitted request. A value large enough to take real time to decode is a payload
// rather than a parameter, and the fields inside it are not worth the cost.
func TestOversizedValuesAreNotDecoded(t *testing.T) {
	large := `{"uid":"` + strings.Repeat("A", 70<<10) + `"}`
	req := wrappedRequest(t, large)
	if got := req.Params(); len(got) != 1 {
		t.Errorf("an oversized value produced %d parameters, want 1", len(got))
	}
}
