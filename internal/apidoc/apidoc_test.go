package apidoc

import (
	"net/url"
	"strings"
	"testing"
)

func parseAt(t *testing.T, documentURL, body string) *Document {
	t.Helper()
	location, err := url.Parse(documentURL)
	if err != nil {
		t.Fatalf("parse document URL: %v", err)
	}
	doc, ok := Parse([]byte(body), location)
	if !ok {
		t.Fatalf("Parse reported %q is not a description", body)
	}
	return doc
}

func requestsFor(t *testing.T, doc *Document) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, request := range doc.Requests {
		out[request.Method+" "+request.URLString()] = string(request.Body)
	}
	return out
}

const swagger2 = `
swagger: "2.0"
info:
  title: eConfirmations API
  version: "1.0"
host: api.example.com
basePath: /v1.0
schemes: [https]
paths:
  /health:
    get:
      parameters:
        - name: verbose
          in: query
          type: boolean
  /econfirmations/{propertyId}:
    post:
      parameters:
        - name: propertyId
          in: path
          required: true
          type: string
        - name: body
          in: body
          schema:
            type: object
            required: [title]
            properties:
              title: {type: string}
              note: {type: string}
`

func TestSwagger2OperationsBecomeRequests(t *testing.T) {
	doc := parseAt(t, "https://www.example.com/swagger/v1/swagger.json", swagger2)

	if doc.Title != "eConfirmations API" {
		t.Errorf("title = %q", doc.Title)
	}
	requests := requestsFor(t, doc)
	if len(requests) != 2 {
		t.Fatalf("got %d requests, want 2: %v", len(requests), requests)
	}

	// 2.0 keeps the host and base path at the top level, and the scheme alongside them.
	if _, ok := requests["GET https://api.example.com/v1.0/health?verbose=true"]; !ok {
		t.Errorf("the health operation is missing or misaddressed: %v", requests)
	}
	// A path parameter has to be filled in: the literal "{propertyId}" matches no route.
	for key, body := range requests {
		if strings.Contains(key, "{propertyId}") {
			t.Errorf("a placeholder survived into the address: %q", key)
		}
		if strings.HasPrefix(key, "POST ") {
			if want := `{"title":"a"}`; body != want {
				t.Errorf("body = %s, want %s (only the required field is invented)", body, want)
			}
		}
	}
}

const openapi3 = `{
  "openapi": "3.0.0",
  "info": {"title": "Pets", "version": "2"},
  "servers": [{"url": "https://api.example.com/v2"}],
  "paths": {
    "/pets/{id}": {
      "get": {
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
        ]
      }
    },
    "/pets": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}
            }
          }
        }
      }
    }
  }
}`

func TestOpenAPI3OperationsBecomeRequests(t *testing.T) {
	doc := parseAt(t, "https://www.example.com/openapi.json", openapi3)
	requests := requestsFor(t, doc)

	if _, ok := requests["GET https://api.example.com/v2/pets/1"]; !ok {
		t.Errorf("the path parameter was not filled with a value of its type: %v", requests)
	}
	body, ok := requests["POST https://api.example.com/v2/pets"]
	if !ok {
		t.Fatalf("the POST is missing: %v", requests)
	}
	if want := `{"name":"a"}`; body != want {
		t.Errorf("body = %s, want %s", body, want)
	}

	for _, request := range doc.Requests {
		if request.Method != "POST" {
			continue
		}
		if got := request.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json — the body is JSON", got)
		}
	}
}

// TestBaseFallsBackToTheDocumentsOwnAddress: a description that names no host is served
// from the place its operations live, with the file name dropped.
func TestBaseFallsBackToTheDocumentsOwnAddress(t *testing.T) {
	document := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /status:
    get: {}
`
	doc := parseAt(t, "https://app.example.com/api/openapi.json", document)
	requests := requestsFor(t, doc)
	if _, ok := requests["GET https://app.example.com/api/status"]; !ok {
		t.Errorf("the operations were not resolved against the document's own directory: %v", requests)
	}
}

func TestParseRejectsWhatIsNotADescription(t *testing.T) {
	location, _ := url.Parse("https://example.com/data.json")
	for _, body := range []string{
		``,
		`{"items":[1,2,3]}`,
		`{"openapi":"3.0.0"}`,
		`not json or yaml at all`,
	} {
		if _, ok := Parse([]byte(body), location); ok {
			t.Errorf("%q was taken for a description", body)
		}
	}
}

// TestOperationsAreBounded: a description can list thousands of operations, and a scan that
// spends its whole budget on one file has stopped being a scan.
func TestOperationsAreBounded(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("openapi: \"3.0.0\"\ninfo: {title: t, version: \"1\"}\npaths:\n")
	for i := 0; i < MaxOperations*2; i++ {
		builder.WriteString("  /p")
		builder.WriteString(strings.Repeat("x", 1))
		builder.WriteString(itoa(i))
		builder.WriteString(":\n    get: {}\n")
	}
	doc := parseAt(t, "https://example.com/openapi.json", builder.String())
	if len(doc.Requests) != MaxOperations {
		t.Errorf("got %d requests, want the cap of %d", len(doc.Requests), MaxOperations)
	}
}

func TestLooksLikeDocumentIsCheapAndNarrow(t *testing.T) {
	cases := map[string]bool{
		`{"swagger":"2.0","paths":{}}`:    true,
		`{"openapi":"3.0.0","paths":{}}`:  true,
		`openapi: "3.0.0"`:                true,
		`{"items":[1,2,3]}`:               false,
		`<html><body>hello</body></html>`: false,
		``:                                false,
	}
	for body, want := range cases {
		if got := LooksLikeDocument([]byte(body)); got != want {
			t.Errorf("LooksLikeDocument(%q) = %v, want %v", body, got, want)
		}
	}
}

func TestSampleValuesFollowTheDeclaration(t *testing.T) {
	cases := []struct {
		parameter rawParameter
		want      string
	}{
		{rawParameter{Example: "given"}, "given"},
		{rawParameter{Default: "fallback"}, "fallback"},
		{rawParameter{Enum: []any{"first", "second"}}, "first"},
		{rawParameter{Type: "integer"}, "1"},
		{rawParameter{Type: "boolean"}, "true"},
		{rawParameter{Type: "string"}, "a"},
		{rawParameter{Type: "string", Format: "date-time"}, "2020-01-01T00:00:00Z"},
		{rawParameter{Schema: map[string]any{"type": "integer"}}, "1"},
	}
	for _, tc := range cases {
		if got := sampleValue(tc.parameter); got != tc.want {
			t.Errorf("sampleValue(%+v) = %q, want %q", tc.parameter, got, tc.want)
		}
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
