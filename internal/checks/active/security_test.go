package active

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// runRequestLevel runs a check that works on the request as a whole.
func runRequestLevel(t *testing.T, h *harness, check checks.Check, target *checks.Target) []*finding.Finding {
	t.Helper()
	return check.Run(context.Background(), h.ctx, target)
}

// targetWithBody builds a POST request carrying a body.
func targetWithBody(t *testing.T, rawURL, body string) (*httpmsg.Request, error) {
	t.Helper()
	request, err := httpmsg.NewRequest("POST", rawURL)
	if err != nil {
		return nil, err
	}
	request.Body = []byte(body)
	request.Header.Set("Content-Type", "application/xml")
	request.Header.Set("Content-Length", fmt.Sprint(len(body)))
	return request, nil
}

// withFormParameter posts a form body and runs the check against its first field.
func withFormParameter(t *testing.T, h *harness, check checks.Check, rawURL, body string) []*finding.Finding {
	t.Helper()

	request, err := httpmsg.NewRequest("POST", rawURL)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Body = []byte(body)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Length", fmt.Sprint(len(body)))

	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	if len(params) == 0 {
		t.Fatal("the form body has no parameters")
	}
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}
	return check.Run(context.Background(), h.ctx, target)
}

// targetWithHeader builds a GET request to be given a credential.
func targetWithHeader(t *testing.T, rawURL string) (*httpmsg.Request, error) {
	t.Helper()
	return httpmsg.NewRequest("GET", rawURL)
}

// TestHostHeaderFiresOnReflection covers the mechanism behind reset-link and
// cache poisoning: the value the client supplied comes back in the response.
func TestHostHeaderFiresOnReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The bug: absolute links are built from whatever Host arrived.
		fmt.Fprintf(w, `<html><body><a href="http://%s/login">login</a></body></html>`, r.Host)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := h.run(t, hostHeader{}, server.URL+"/")

	if len(findings) == 0 {
		t.Fatal("a reflected Host header was not reported")
	}
	if findings[0].CWE != "CWE-644" {
		t.Errorf("CWE = %q, want CWE-644", findings[0].CWE)
	}
}

// TestHostHeaderStaysQuietOnAWellBuiltApp keeps the check from firing on every
// site: an application that builds its links from configuration reflects
// nothing.
func TestHostHeaderStaysQuietOnAWellBuiltApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="https://example.com/login">login</a></body></html>`)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := h.run(t, hostHeader{}, server.URL+"/"); len(findings) != 0 {
		t.Errorf("a fixed-host application was reported: %+v", findings)
	}
}

// TestXXEFiresOnFileRead covers the non-blind case: the parser expands an entity
// that reads a local file and the contents land in the response.
func TestXXEFiresOnFileRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		// A parser that resolves file:// entities, which is the whole bug.
		if strings.Contains(string(body), "file:///etc/passwd") {
			fmt.Fprint(w, "<result>root:x:0:0:root:/root:/bin/bash</result>")
			return
		}
		fmt.Fprint(w, "<result>parsed ok</result>")
	}))
	defer server.Close()

	request, _ := targetWithBody(t, server.URL+"/parse", "<root><name>test</name></root>")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	target := &checks.Target{Request: request, Response: baseline}
	findings := runRequestLevel(t, h, xxe{}, target)
	if len(findings) == 0 {
		t.Fatal("an entity that read a local file was not reported")
	}
	if findings[0].CWE != "CWE-611" {
		t.Errorf("CWE = %q, want CWE-611", findings[0].CWE)
	}
}

// TestXXESkipsNonXMLRequests documents the guard: a JSON endpoint is not an XML
// parser and must not be sent XML payloads.
func TestXXESkipsNonXMLRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	request, _ := targetWithBody(t, server.URL+"/api", `{"name":"test","type":"json"}`)
	request.Header.Set("Content-Type", "application/json")

	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)
	findings := runRequestLevel(t, h, xxe{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) != 0 {
		t.Errorf("a JSON request was sent XML payloads: %+v", findings)
	}
}

// TestCSRFFiresWhenTheTokenIsNotEnforced is the direct experiment: send the
// request with the token, then with nonsense, and compare.
func TestCSRFFiresWhenTheTokenIsNotEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// The bug: the token is read but never checked.
		fmt.Fprint(w, "<html><body>Profile updated for "+strings.Repeat("lorem ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withFormParameter(t, h, csrf{}, server.URL+"/profile", "csrf_token=abc123&email=a%40b.c")
	if len(findings) == 0 {
		t.Fatal("an unenforced CSRF token was not reported")
	}
	if findings[0].CWE != "CWE-352" {
		t.Errorf("CWE = %q, want CWE-352", findings[0].CWE)
	}
	// The forged value must never equal the original.
	if findings[0].Payload == "abc123" {
		t.Error("the forged token is the original value")
	}
}

// TestCSRFStaysQuietWhenTheTokenIsChecked is the other half: a request rejected
// with a forged token is evidence the protection works.
func TestCSRFStaysQuietWhenTheTokenIsChecked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("csrf_token") != "abc123" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body>Invalid CSRF token</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>Profile updated "+strings.Repeat("lorem ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withFormParameter(t, h, csrf{}, server.URL+"/profile", "csrf_token=abc123&email=a%40b.c"); len(findings) != 0 {
		t.Errorf("a correctly verified token was reported: %+v", findings)
	}
}

// TestCSRFIgnoresSafeMethods: a GET is not a state change and needs no token.
func TestCSRFIgnoresSafeMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>page "+strings.Repeat("lorem ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, csrf{}, server.URL+"/search?csrf_token=abc&q=x"); len(findings) != 0 {
		t.Errorf("a GET was checked for CSRF: %+v", findings)
	}
}

// TestJWTFiresOnAlgNone covers the classic confusion: a token that declares it
// needs no signature is accepted.
func TestJWTFiresOnAlgNone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authorization, "Bearer ")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		header, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[0], "="))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var parsed map[string]any
		_ = json.Unmarshal(header, &parsed)
		// The bug: the algorithm comes from the token, so "none" is honoured.
		if alg, _ := parsed["alg"].(string); strings.EqualFold(alg, "none") {
			fmt.Fprint(w, `{"user":"admin","secret":"`+strings.Repeat("data", 30)+`"}`)
			return
		}
		fmt.Fprint(w, `{"user":"admin","secret":"`+strings.Repeat("data", 30)+`"}`)
	}))
	defer server.Close()

	// A token issued with a real algorithm, plus a signature we do not need to
	// forge: the check replaces the header and drops the signature.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user":"admin"}`))
	token := header + "." + payload + ".signature"

	request, err := targetWithHeader(t, server.URL+"/api/me")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if baseline.Status != 200 {
		t.Fatalf("baseline status = %d, want 200", baseline.Status)
	}

	findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("a token accepted with alg=none was not reported")
	}
	if findings[0].CWE != "CWE-347" {
		t.Errorf("CWE = %q, want CWE-347", findings[0].CWE)
	}
}

// TestJWTStaysQuietWhenSignatureIsVerified: the same server, but checking the
// signature, must produce nothing.
func TestJWTStaysQuietWhenSignatureIsVerified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authorization, "Bearer ")
		if !strings.HasSuffix(token, ".signature") {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		fmt.Fprint(w, `{"user":"admin","secret":"`+strings.Repeat("data", 30)+`"}`)
	}))
	defer server.Close()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user":"admin"}`))
	token := header + "." + payload + ".signature"

	request, _ := targetWithHeader(t, server.URL+"/api/me")
	request.Header.Set("Authorization", "Bearer "+token)

	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)
	findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) != 0 {
		t.Errorf("a verified signature was reported as missing: %+v", findings)
	}
}

func TestExtractJWT(t *testing.T) {
	valid := "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYSJ9.sig"
	cases := map[string]string{
		"Bearer " + valid:                valid,
		"session=" + valid + "; other=1": valid,
		"Basic dXNlcjpwYXNz":             "",
		"":                               "",
		"no-dots-here":                   "",
		"eyJhbGciOiJIUzI1NiJ9.notbase64.sig.more": "",
	}
	for input, want := range cases {
		if got := extractJWT(input); got != want {
			t.Errorf("extractJWT(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestForgeTokenChangesEveryCharacter(t *testing.T) {
	original := "abc123XYZ"
	forged := forgeToken(original)
	if forged == original {
		t.Fatal("the forged token equals the original")
	}
	if len(forged) != len(original) {
		t.Errorf("length changed: %d → %d", len(original), len(forged))
	}
	for i := 0; i < len(original); i++ {
		if forged[i] == original[i] {
			t.Errorf("character %d was left unchanged: %q", i, forged[i])
		}
	}
}

func TestNewChecksAreRegistered(t *testing.T) {
	for _, id := range []string{"xxe", "jwt", "csrf", "host-header"} {
		if checks.ByID(id) == nil {
			t.Errorf("check %q is not registered", id)
		}
	}
}
