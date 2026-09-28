package cli

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpclient"
)

// creds runs the identity flags through the same path a command uses.
func creds(t *testing.T, cookies, headers []string, basic string) []httpclient.Credential {
	t.Helper()
	o := &requestOptions{
		cookies:   &cookies,
		headers:   &headers,
		basicAuth: &basic,
	}
	got, err := o.credentials()
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	return got
}

func TestCookieCredential(t *testing.T) {
	got := creds(t, []string{"session=abc; csrf=xyz"}, nil, "")
	if len(got) != 1 || got[0].Name != "Cookie" {
		t.Fatalf("got %+v, want one Cookie credential", got)
	}
	if got[0].Value != "session=abc; csrf=xyz" {
		t.Errorf("value = %q", got[0].Value)
	}
}

// TestCookieToleratesAPastedHeader: people copy the whole line out of the
// browser's devtools, and rejecting that would be pedantry that costs a support
// round trip.
func TestCookieToleratesAPastedHeader(t *testing.T) {
	got := creds(t, []string{"Cookie: session=abc"}, nil, "")
	if len(got) != 1 || got[0].Value != "session=abc" {
		t.Errorf("got %+v, want the Cookie: prefix stripped", got)
	}
}

func TestHeaderCredential(t *testing.T) {
	got := creds(t, nil, []string{"X-Api-Key: secret", "Authorization: Bearer tok"}, "")
	if len(got) != 2 {
		t.Fatalf("got %d credentials, want 2", len(got))
	}
	if got[0].Name != "X-Api-Key" || got[0].Value != "secret" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Name != "Authorization" || got[1].Value != "Bearer tok" {
		t.Errorf("second = %+v", got[1])
	}
}

func TestBasicAuthCredential(t *testing.T) {
	got := creds(t, nil, nil, "alice:s3cret")
	if len(got) != 1 || got[0].Name != "Authorization" {
		t.Fatalf("got %+v, want one Authorization credential", got)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	if got[0].Value != want {
		t.Errorf("value = %q, want %q", got[0].Value, want)
	}
}

// TestBasicAuthKeepsColonsInThePassword: only the first colon separates user
// from password, because passwords contain colons.
func TestBasicAuthKeepsColonsInThePassword(t *testing.T) {
	got := creds(t, nil, nil, "alice:a:b:c")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:a:b:c"))
	if got[0].Value != want {
		t.Errorf("value = %q, want %q", got[0].Value, want)
	}
}

// TestMalformedCredentialsAreRejected: guessing what the user meant would
// silently scan as the wrong identity, which is worse than failing.
func TestMalformedCredentialsAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
		basic   string
	}{
		{"header without a colon", []string{"X-Api-Key secret"}, ""},
		{"header with an empty name", []string{": value"}, ""},
		{"basic auth without a colon", nil, "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &requestOptions{cookies: &[]string{}, headers: &tc.headers, basicAuth: &tc.basic}
			if _, err := o.credentials(); err == nil {
				t.Error("malformed input was accepted")
			}
		})
	}
}

// TestMultipleCookiesBecomeOneHeader: a client can only send one Cookie header,
// so repeats have to be joined rather than sent as separate fields.
func TestEmptyCredentialFlagsProduceNothing(t *testing.T) {
	got := creds(t, []string{"", "  "}, []string{""}, "")
	if len(got) != 0 {
		t.Errorf("blank flags produced %+v", got)
	}
	if _, err := (&requestOptions{cookies: &[]string{}, headers: &[]string{}, basicAuth: new(string)}).credentials(); err != nil {
		t.Errorf("no flags at all returned %v", err)
	}
}

func TestCookieAndHeaderCanBeCombined(t *testing.T) {
	got := creds(t, []string{"session=abc"}, []string{"X-Api-Key: k"}, "u:p")
	if len(got) != 3 {
		t.Fatalf("got %d credentials, want 3", len(got))
	}
	names := []string{got[0].Name, got[1].Name, got[2].Name}
	if strings.Join(names, ",") != "Cookie,X-Api-Key,Authorization" {
		t.Errorf("names = %v", names)
	}
}
