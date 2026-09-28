package passive

import (
	"context"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// target builds a Target around a request, with an empty response.
func target(t *testing.T, method, rawURL, body string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest(method, rawURL)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, rawURL, err)
	}
	if body != "" {
		request.Body = []byte(body)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return &checks.Target{Request: request}
}

func runCleartext(t *testing.T, tg *checks.Target) []*finding.Finding {
	t.Helper()
	bundle := i18n.New(i18n.EN)
	return cleartextPassword{}.Run(context.Background(), &checks.Context{Bundle: bundle}, tg)
}

// TestCleartextPasswordFiresOverHTTP: the case the check exists for.
func TestCleartextPasswordFiresOverHTTP(t *testing.T) {
	findings := runCleartext(t, target(t, "POST", "http://example.com/login", "username=alice&password=hunter2"))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

// TestCleartextPasswordNeverEchoesTheValue: the report travels — it gets
// attached to tickets and mailed around. Reproducing the credential there would
// turn a transport finding into a second disclosure.
func TestCleartextPasswordNeverEchoesTheValue(t *testing.T) {
	const secret = "Sup3rSecret-Pa55w0rd"
	findings := runCleartext(t, target(t, "POST", "http://example.com/login", "password="+secret))
	if len(findings) == 0 {
		t.Fatal("no finding")
	}
	f := findings[0]
	haystack := strings.Join([]string{
		f.Title, f.Description, f.Remediation, f.Payload, f.URL,
		strings.Join(f.Evidence.Matches, " "),
		string(f.Evidence.Request),
		string(f.Evidence.Response),
	}, " ")
	if strings.Contains(haystack, secret) {
		t.Errorf("the password value was reproduced in the finding:\n%s", haystack)
	}
	// The field name should still be there, or the report cannot be acted on.
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "password") {
		t.Error("the field name is missing from the evidence")
	}
}

// TestCleartextPasswordIgnoresHTTPS: over TLS there is nothing to report.
func TestCleartextPasswordIgnoresHTTPS(t *testing.T) {
	if findings := runCleartext(t, target(t, "POST", "https://example.com/login", "password=hunter2")); len(findings) != 0 {
		t.Errorf("a password over HTTPS was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCleartextPasswordIgnoresEmptyValue: an empty field is not a credential
// being transmitted, and every login page has one before it is filled in.
func TestCleartextPasswordIgnoresEmptyValue(t *testing.T) {
	if findings := runCleartext(t, target(t, "POST", "http://example.com/login", "username=alice&password=")); len(findings) != 0 {
		t.Errorf("an empty password field was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestCleartextPasswordFieldMatchingIsExact: `pass` must not match `passenger`
// or `bypass`, or the check fires on unrelated pages.
func TestCleartextPasswordFieldMatchingIsExact(t *testing.T) {
	for _, body := range []string{"passenger=alice", "bypass=true", "compass=north", "passages=12"} {
		if findings := runCleartext(t, target(t, "POST", "http://example.com/x", body)); len(findings) != 0 {
			t.Errorf("%q was mistaken for a password field: %v", body, findings[0].Evidence.Matches)
		}
	}
}

// TestCleartextPasswordFindsQueryParameters: credentials turn up in URLs too,
// where they are even more exposed — in logs, in Referer headers, in history.
func TestCleartextPasswordFindsQueryParameters(t *testing.T) {
	findings := runCleartext(t, target(t, "GET", "http://example.com/login?user=alice&pwd=secret1", ""))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "query") {
		t.Errorf("the location was not reported as the query string: %v", findings[0].Evidence.Matches)
	}
}

// TestCleartextPasswordReportsEachFieldOnce: a form with two password fields
// (new and confirmation) is one problem per field, not per request.
func TestCleartextPasswordReportsEachFieldOnce(t *testing.T) {
	findings := runCleartext(t, target(t, "POST", "http://example.com/signup",
		"new_password=abc123&confirm_password=abc123"))
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per field)", len(findings))
	}
}

// jsonTarget builds a Target with a JSON body.
func jsonTarget(t *testing.T, rawURL, body string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("POST", rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Body = []byte(body)
	request.Header.Set("Content-Type", "application/json")
	return &checks.Target{Request: request}
}

// TestCleartextPasswordFindsJSONBody: a login endpoint taking application/json
// is not a set of form parameters, so the parameter parser never sees it.
func TestCleartextPasswordFindsJSONBody(t *testing.T) {
	findings := runCleartext(t, jsonTarget(t, "http://api.example.com/session",
		`{"username":"alice","password":"hunter2"}`))
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "json") {
		t.Errorf("the location was not reported as the JSON body: %v", findings[0].Evidence.Matches)
	}
}

// TestCleartextPasswordNeverEchoesAJSONValue: the same promise as for form
// fields — a report is a document that travels.
func TestCleartextPasswordNeverEchoesAJSONValue(t *testing.T) {
	const secret = "JsonSecret-98765"
	findings := runCleartext(t, jsonTarget(t, "http://api.example.com/session",
		`{"user":"alice","password":"`+secret+`"}`))
	if len(findings) == 0 {
		t.Fatal("no finding")
	}
	f := findings[0]
	haystack := strings.Join([]string{
		f.Title, f.Description, f.Remediation, f.Payload, f.URL,
		strings.Join(f.Evidence.Matches, " "),
		string(f.Evidence.Request), string(f.Evidence.Response),
	}, " ")
	if strings.Contains(haystack, secret) {
		t.Errorf("the JSON password value reached the finding:\n%s", haystack)
	}
}

// TestCleartextPasswordIgnoresNonCredentialJSON: unrelated JSON must not trip it.
func TestCleartextPasswordIgnoresNonCredentialJSON(t *testing.T) {
	for _, body := range []string{
		`{"title":"hello","body":"world"}`,
		`{"password":""}`,
		`{"passenger":{"name":"alice"}}`,
		`not json at all`,
	} {
		if findings := runCleartext(t, jsonTarget(t, "http://api.example.com/x", body)); len(findings) != 0 {
			t.Errorf("%s was reported: %v", body, findings[0].Evidence.Matches)
		}
	}
}

// TestCleartextPasswordIgnoresJSONOverHTTPS: the transport is still what matters.
func TestCleartextPasswordIgnoresJSONOverHTTPS(t *testing.T) {
	if findings := runCleartext(t, jsonTarget(t, "https://api.example.com/session",
		`{"password":"hunter2"}`)); len(findings) != 0 {
		t.Errorf("JSON over HTTPS was reported: %v", findings[0].Evidence.Matches)
	}
}
