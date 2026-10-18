package active

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
)

// leakedKeySecret is the key the fixtures sign with. It is long enough to be read as key
// material — the probe ignores a value shorter than six characters — and made of nothing but the
// bytes a message prints a key with, so a refusal that carries it yields it as one run.
const leakedKeySecret = "s3cr3t-hmac-key-2024"

// hs256JWTSite verifies an HS256 signature with secret. A token it accepts is answered with
// acceptBody; a token it refuses gets refuseStatus and refuseBody, which is where a service that
// prints its key puts it.
func hs256JWTSite(t *testing.T, secret, acceptBody, refuseBody string, refuseStatus int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			w.WriteHeader(refuseStatus)
			fmt.Fprint(w, refuseBody)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(parts[2])) {
			w.WriteHeader(refuseStatus)
			fmt.Fprint(w, refuseBody)
			return
		}
		fmt.Fprint(w, acceptBody)
	}))
	t.Cleanup(server.Close)
	return server
}

// leakedKeyTarget fetches the baseline for a request carrying token, which is the pair the probe
// is handed.
func leakedKeyTarget(t *testing.T, h *harness, serverURL, token string) *checks.Target {
	t.Helper()
	request, err := targetWithHeader(t, serverURL+"/api/profile")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return &checks.Target{Request: request, Response: baseline}
}

// leakedKeyProbe runs the disclosed-key probe the way jwt.Run reaches it, on the token the
// fixture issued.
//
// It goes to the probe rather than to jwt.Run because most of these tests are controls: a
// fixture that answers a tampered token with a 200 is reported by the alg=none attempts first,
// and the finding under test would never be the one returned.
func leakedKeyProbe(t *testing.T, h *harness, target *checks.Target) *finding.Finding {
	t.Helper()
	field, original := findJWT(target.Request)
	if original == "" {
		t.Fatal("the fixture's request carries no token")
	}
	parts := strings.Split(original, ".")
	if len(parts) != 3 {
		t.Fatalf("the fixture's token has %d parts", len(parts))
	}
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	return jwtLeakedSigningKey(context.Background(), h.ctx, target, field, original, parts, header)
}

// TestJWTLeakedKeyFiresOnAKeyTheRefusalProves is the decisive form: the refusal prints a value
// whose keyed hash is the signature of the token the service accepted, so the value is the key
// whatever the sentence around it says, and every identity the application recognises is
// forgeable by whoever read that error.
func TestJWTLeakedKeyFiresOnAKeyTheRefusalProves(t *testing.T) {
	server := hs256JWTSite(t, leakedKeySecret,
		`{"user_id":34,"ok":true}`,
		`{"error":"bad signature","expected_key":"`+leakedKeySecret+`"}`,
		http.StatusUnauthorized)

	h := newHarness(t)
	token := tokenSignedWith(t, leakedKeySecret)
	f := leakedKeyProbe(t, h, leakedKeyTarget(t, h, server.URL, token))

	if f == nil {
		t.Fatal("a refusal that printed the key behind the accepted token was not reported")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical: the key is proved to be the one in use", f.Severity)
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", f.Confidence)
	}
	if f.CWE != "CWE-209" {
		t.Errorf("CWE = %q, want CWE-209 (the disclosure, not the forgery)", f.CWE)
	}
	if f.Param != "Authorization" {
		t.Errorf("param = %q, want the field the token travelled in", f.Param)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), leakedKeySecret) {
		t.Errorf("evidence does not carry the disclosed key: %v", f.Evidence.Matches)
	}
	if !strings.Contains(f.Evidence.Diff, leakedKeySecret) {
		t.Errorf("the evidence prose does not name the key: %q", f.Evidence.Diff)
	}
	// What a reader replays is the token that earned the refusal, not the one that worked.
	if f.Payload == token || strings.Count(f.Payload, ".") != 2 {
		t.Errorf("payload = %q, want the tampered token the refusal was about", f.Payload)
	}
	if !strings.Contains(string(f.Evidence.Request), f.Payload) {
		t.Errorf("the evidence request does not carry the payload it names:\n%s", f.Evidence.Request)
	}
}

// TestJWTLeakedKeyIsReachedFromTheCheck keeps the probe wired into the check: the same fixture,
// run through jwt.Run, has to report the disclosure rather than stop at one of the forgeries
// that come before it.
func TestJWTLeakedKeyIsReachedFromTheCheck(t *testing.T) {
	server := hs256JWTSite(t, leakedKeySecret,
		`{"user_id":34,"ok":true}`,
		`{"error":"bad signature","expected_key":"`+leakedKeySecret+`"}`,
		http.StatusUnauthorized)

	h := newHarness(t)
	target := leakedKeyTarget(t, h, server.URL, tokenSignedWith(t, leakedKeySecret))

	findings := runRequestLevel(t, h, jwt{}, target)
	if len(findings) == 0 {
		t.Fatal("the disclosure is not reached by the check itself")
	}
	if findings[0].CWE != "CWE-209" {
		t.Fatalf("CWE = %q, want CWE-209: a different finding stood in for the disclosure", findings[0].CWE)
	}
	checkEvidenceCarriesPayload(t, findings)
}

// TestJWTLeakedKeyStaysQuietOnALabelledButUnverifiedKey covers the form nothing can prove: a
// refusal names a value as a signing key, but that value does not sign the accepted token. A label
// alone is not key material, so this is not reported.
func TestJWTLeakedKeyStaysQuietOnALabelledButUnverifiedKey(t *testing.T) {
	const rotated = "rotated-key-abc123"
	server := hs256JWTSite(t, leakedKeySecret,
		`{"user_id":34,"ok":true}`,
		`{"error":"bad signature","signing_key":"`+rotated+`"}`,
		http.StatusUnauthorized)

	h := newHarness(t)
	if f := leakedKeyProbe(t, h, leakedKeyTarget(t, h, server.URL, tokenSignedWith(t, leakedKeySecret))); f != nil {
		t.Fatalf("a label without proof was reported as a leak: %v", f.Evidence.Matches)
	}
}

// TestJWTLeakedKeyStaysQuietWhenTheLabelNamesNoKey is the sentence this must not read as a leak:
// a message says the key is missing by putting the word where the key would go.
func TestJWTLeakedKeyStaysQuietWhenTheLabelNamesNoKey(t *testing.T) {
	server := hs256JWTSite(t, leakedKeySecret,
		`{"user_id":34,"ok":true}`,
		`{"error":"bad signature","signing_key":"required"}`,
		http.StatusUnauthorized)

	h := newHarness(t)
	if f := leakedKeyProbe(t, h, leakedKeyTarget(t, h, server.URL, tokenSignedWith(t, leakedKeySecret))); f != nil {
		t.Errorf("a message saying the key is missing was reported as a leak: %v", f.Evidence.Matches)
	}
}

// TestJWTLeakedKeyStaysQuietWhenTheAcceptedPageAlreadyPrintsIt: a page that publishes its key is
// a different finding. Calling it a leak by the refusal would put the wrong sentence in the
// report, so material the accepted answer already carried is not a disclosure.
func TestJWTLeakedKeyStaysQuietWhenTheAcceptedPageAlreadyPrintsIt(t *testing.T) {
	server := hs256JWTSite(t, leakedKeySecret,
		`{"user_id":34,"signing_key":"`+leakedKeySecret+`","ok":true}`,
		`{"error":"bad signature","signing_key":"`+leakedKeySecret+`"}`,
		http.StatusUnauthorized)

	h := newHarness(t)
	if f := leakedKeyProbe(t, h, leakedKeyTarget(t, h, server.URL, tokenSignedWith(t, leakedKeySecret))); f != nil {
		t.Errorf("a page that prints its own key was reported as a disclosure by the refusal: %v",
			f.Evidence.Matches)
	}
}

// TestJWTLeakedKeyStaysQuietWhenTheForgedTokenIsAnsweredLikeTheGoodOne: the probe has to read a
// refusal, and "accepted" is decided by comparing with the answer the service gave the token it
// issued — not by the words in a body. A service that answers the tampered token the way it
// answered the good one said nothing about this token, whatever the body holds.
func TestJWTLeakedKeyStaysQuietWhenTheForgedTokenIsAnsweredLikeTheGoodOne(t *testing.T) {
	// Both answers are 200 and close in size, which is what jwtAccepted compares: the second is
	// the same answer with an error object in it, which is what a careless API returns.
	server := hs256JWTSite(t, leakedKeySecret,
		`{"user_id":34,"ok":true,"issued":"2024-05-01T00:00:00Z"}`,
		`{"error":"bad signature","expected_key":"`+leakedKeySecret+`"}`,
		http.StatusOK)

	h := newHarness(t)
	if f := leakedKeyProbe(t, h, leakedKeyTarget(t, h, server.URL, tokenSignedWith(t, leakedKeySecret))); f != nil {
		t.Errorf("an answer the service also gave the token it issued was read as a refusal: %v",
			f.Evidence.Matches)
	}
}

// TestJWTLeakedKeyIsSkippedForAsymmetricTokens: a keyed hash can be proved to have been disclosed
// because the signature is a function of the key. An asymmetric token has no such proof to offer,
// so the probe does not even send a request.
func TestJWTLeakedKeyIsSkippedForAsymmetricTokens(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"bad signature","signing_key":"`+leakedKeySecret+`"}`)
	}))
	t.Cleanup(server.Close)

	h := newHarness(t)
	target := leakedKeyTarget(t, h, server.URL, rs256TestToken(t))
	if got := requests.Load(); got != 1 {
		t.Fatalf("the baseline took %d request(s), want 1", got)
	}
	if f := leakedKeyProbe(t, h, target); f != nil {
		t.Errorf("an asymmetric token was treated as a candidate for a disclosed key: %v", f.Evidence.Matches)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("the probe sent %d request(s) against an asymmetric token, want none", got-1)
	}
}

// rs256TestToken is an asymmetric-shaped token. Nothing verifies its signature: what is under
// test is whether the probe reads the header's algorithm before it sends anything.
func rs256TestToken(t *testing.T) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	return b64([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." +
		b64([]byte(`{"sub":"alice"}`)) + "." + b64([]byte("not-an-rsa-signature"))
}

// TestJWTLeakedKeyLabelParsingSeparatesFieldNamesFromValues pins the reading of a message that
// names its key: the label is the name the message used, and the value is what came after the
// separator — never the field glued to its value, and never a bare "key" from ordinary prose.
func TestJWTLeakedKeyLabelParsingSeparatesFieldNamesFromValues(t *testing.T) {
	cases := []struct {
		name string
		text string
		want []jwtKeyMention
	}{
		{
			name: "json field",
			text: `{"error":"bad signature","signing_key":"abc123"}`,
			want: []jwtKeyMention{{label: "signing_key", value: "abc123"}},
		},
		{
			name: "camel case field",
			text: `{"signingKey":"abc123"}`,
			want: []jwtKeyMention{{label: "signingKey", value: "abc123"}},
		},
		{
			name: "two words in prose",
			text: `the signing key: abc123`,
			want: []jwtKeyMention{{label: "signing key", value: "abc123"}},
		},
		{
			name: "query spelling",
			text: `jwt_secret=abc123`,
			want: []jwtKeyMention{{label: "jwt_secret", value: "abc123"}},
		},
		{
			name: "unquoted value after a colon and a space",
			text: `jwt secret : abc123`,
			want: []jwtKeyMention{{label: "jwt secret", value: "abc123"}},
		},
		{
			name: "a bare key or secret names nothing",
			text: `the key: abc123 and the secret: abc123`,
			want: nil,
		},
		{
			name: "an error field is not a signing key",
			text: `{"error":"bad signature"}`,
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := jwtKeyMentions(c.text)
			if len(got) != len(c.want) {
				t.Fatalf("jwtKeyMentions(%q) = %v, want %v", c.text, got, c.want)
			}
			for index := range got {
				if got[index] != c.want[index] {
					t.Errorf("mention %d of %q = %+v, want %+v", index, c.text, got[index], c.want[index])
				}
			}
		})
	}
}
