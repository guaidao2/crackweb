package active

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

// jwtService builds a server that verifies an HS256 signature with the given secret, the way a
// service that has done the ordinary thing does.
func jwtService(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(parts[2])) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"bad signature"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"user_id":34,"ok":true}`)
	}))
}

// tokenSignedWith mints a token a service using this secret would accept.
func tokenSignedWith(t *testing.T, secret string) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"user_id": float64(34), "role": "employee", "exp": float64(4102444800)})
	signingInput := b64(header) + "." + b64(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil))
}

func runJWTWithSecrets(t *testing.T, serviceURL, token string, secrets []string) []*finding.Finding {
	t.Helper()
	h := newHarness(t)
	h.ctx.JWTSecrets = secrets
	request, err := httpmsg.NewRequest("GET", serviceURL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline}
	if len(params) > 0 {
		target.Param = &params[0]
	}
	return runRequestLevel(t, h, jwt{}, target)
}

// TestJWTAKnownSecretIsReportedWhenTheServiceAcceptsIt is the online half of an offline
// discovery: the secret was found in a config file, and the question is whether the service
// still signs with it.
func TestJWTAKnownSecretIsReportedWhenTheServiceAcceptsIt(t *testing.T) {
	server := jwtService(t, "secret")
	t.Cleanup(server.Close)

	findings := runJWTWithSecrets(t, server.URL+"/api/profile", tokenSignedWith(t, "secret"), []string{"secret"})
	if len(findings) == 0 {
		t.Fatal("a service that accepts a token signed with the supplied key was not reported")
	}
	if findings[0].Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %v, want certain: the exchange is proof", findings[0].Confidence)
	}
}

// TestJWTAKnownSecretStaysQuietForTheWrongKey is the control that keeps this from being "a key
// was supplied, so report something".
func TestJWTAKnownSecretStaysQuietForTheWrongKey(t *testing.T) {
	server := jwtService(t, "secret")
	t.Cleanup(server.Close)

	findings := runJWTWithSecrets(t, server.URL+"/api/profile", tokenSignedWith(t, "secret"), []string{"wrong-key", "another-wrong-one"})
	if len(findings) != 0 {
		t.Errorf("a key that does not sign the token was reported: %v", findings[0].Evidence)
	}
}

// TestJWTAKnownSecretNeedsNoFlagToBehaveAsBefore: with no key supplied the check must do exactly
// what it did before this existed.
func TestJWTAKnownSecretNeedsNoFlagToBehaveAsBefore(t *testing.T) {
	server := jwtService(t, "secret")
	t.Cleanup(server.Close)

	if findings := runJWTWithSecrets(t, server.URL+"/api/profile", tokenSignedWith(t, "secret"), nil); len(findings) != 0 {
		t.Errorf("the check reported without --jwt-secret: %v", findings[0].Evidence)
	}
}
