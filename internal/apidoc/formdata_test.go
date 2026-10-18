package apidoc

import (
	"testing"
)

// TestSwaggerFormDataBecomesAFormBody: Swagger 2.0 puts form fields in `in: formdata`.
// They belong in the request body; a query string is not what the endpoint reads, and
// sending them there reaches the handler with every field empty.
func TestSwaggerFormDataBecomesAFormBody(t *testing.T) {
	source := `
swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.test
basePath: /api
schemes: [https]
paths:
  /login:
    post:
      parameters:
        - {name: user, in: formdata, type: string, default: alice}
        - {name: pass, in: formdata, type: string, default: secret}
      responses:
        "200": {description: ok}
`
	doc := parseAt(t, "https://example.test/swagger.json", source)
	if len(doc.Requests) != 1 {
		t.Fatalf("got %d requests, want one", len(doc.Requests))
	}
	request := doc.Requests[0]
	if request.Method != "POST" {
		t.Errorf("method = %q, want POST", request.Method)
	}
	if got := request.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got)
	}
	if got, want := string(request.Body), "pass=secret&user=alice"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if request.URL.RawQuery != "" {
		t.Errorf("form fields were put in the query: %q", request.URL.RawQuery)
	}
}

// TestSwaggerHeaderParameterIsSent: a header parameter is part of the operation's
// contract, and omitting it can make the target refuse the request before the code
// under test runs.
func TestSwaggerHeaderParameterIsSent(t *testing.T) {
	source := `
swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.test
paths:
  /thing:
    get:
      parameters:
        - {name: X-Tenant, in: header, type: string, default: acme}
      responses:
        "200": {description: ok}
`
	doc := parseAt(t, "https://example.test/swagger.json", source)
	if len(doc.Requests) != 1 {
		t.Fatalf("got %d requests, want one", len(doc.Requests))
	}
	if got := doc.Requests[0].Header.Get("X-Tenant"); got != "acme" {
		t.Errorf("X-Tenant = %q, want acme", got)
	}
}

// TestSwaggerCredentialHeaderIsLeftForTheOperator: a document that names an identity
// header is describing a header the caller must supply, not one with a sample value.
// Writing a placeholder would make ApplyCredentials decline the gap and turn an
// authenticated scan into an anonymous one.
func TestSwaggerCredentialHeaderIsLeftForTheOperator(t *testing.T) {
	source := `
swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: example.test
paths:
  /thing:
    get:
      parameters:
        - {name: Authorization, in: header, type: string, default: "Bearer placeholder"}
        - {name: X-Api-Key, in: header, type: string, default: placeholder}
        - {name: X-Auth-Token, in: header, type: string, default: placeholder}
        - {name: X-Access-Token, in: header, type: string, default: placeholder}
        - {name: Cookie, in: header, type: string, default: "sid=placeholder"}
      responses:
        "200": {description: ok}
`
	doc := parseAt(t, "https://example.test/swagger.json", source)
	if len(doc.Requests) != 1 {
		t.Fatalf("got %d requests, want one", len(doc.Requests))
	}
	for _, name := range []string{"Authorization", "X-Api-Key", "X-Auth-Token", "X-Access-Token", "Cookie"} {
		if got := doc.Requests[0].Header.Get(name); got != "" {
			t.Errorf("%s = %q, want it left for the configured credential", name, got)
		}
	}
}
