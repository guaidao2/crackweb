package active

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
)

// rsaJWTSite signs with a private key and verifies with the public one it publishes — the
// arrangement the confusion attack needs. With `confused` it also accepts an HMAC token
// whose secret is that same public key, which is the flaw the check is for.
func rsaJWTSite(t *testing.T, confused bool) (*httptest.Server, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/jwks.json") {
			fmt.Fprintf(w, `{"kty":"RSA","pem":%q}`, string(publicPEM))
			return
		}
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid token"}`)
			return
		}
		header, err := decodeJWTPart(parts[0])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid token"}`)
			return
		}
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		signingInput := []byte(parts[0] + "." + parts[1])
		digest := sha256.Sum256(signingInput)

		ok := false
		switch alg, _ := header["alg"].(string); strings.ToLower(alg) {
		case "rs256":
			ok = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) == nil
		case "hs256":
			if confused {
				ok = hmacEqual(publicPEM, signingInput, signature)
			}
		}
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid token"}`)
			return
		}
		fmt.Fprint(w, `{"user":"admin","ok":true}`)
	}))
	t.Cleanup(server.Close)
	return server, key, publicPEM
}

// hmacEqual reports whether signature is the HMAC of signingInput under key.
func hmacEqual(key, signingInput, signature []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(signingInput)
	return hmac.Equal(mac.Sum(nil), signature)
}

// signRS256 builds a token the way the site above issues them.
func signRS256(t *testing.T, key *rsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(payload)
	body := base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(header + "." + body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return header + "." + body + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// TestJWTFiresOnAlgorithmConfusion: the token is signed with the key the service published,
// relabelled HS256, and accepted.
func TestJWTFiresOnAlgorithmConfusion(t *testing.T) {
	server, key, _ := rsaJWTSite(t, true)
	request, _ := targetWithHeader(t, server.URL+"/me")
	request.Header.Set("Authorization", "Bearer "+signRS256(t, key, map[string]any{"sub": "alice"}))

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil || baseline.Status != 200 {
		t.Fatalf("baseline: %v status=%v", err, baseline)
	}
	findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("a service verifying with its published public key was not reported")
	}
	if findings[0].CWE != "CWE-347" {
		t.Errorf("CWE = %q, want CWE-347", findings[0].CWE)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "public key") {
		t.Errorf("evidence does not explain the confusion: %v", findings[0].Evidence.Matches)
	}
}

// TestJWTStaysQuietWhenAlgorithmsAreSeparated: the same service, refusing the HMAC token.
func TestJWTStaysQuietWhenAlgorithmsAreSeparated(t *testing.T) {
	server, key, _ := rsaJWTSite(t, false)
	request, _ := targetWithHeader(t, server.URL+"/me")
	request.Header.Set("Authorization", "Bearer "+signRS256(t, key, map[string]any{"sub": "alice"}))

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil || baseline.Status != 200 {
		t.Fatalf("baseline: %v status=%v", err, baseline)
	}
	if findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a service that separates the algorithms was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestJWTConfusionIsSkippedForSymmetricTokens: the attack is about a public key, so a token
// that already uses HMAC is not a candidate.
func TestJWTConfusionIsSkippedForSymmetricTokens(t *testing.T) {
	header := map[string]any{"alg": "HS256"}
	parts := strings.Split(signedToken(t, "/dev/null", nil), ".")
	if f := jwtAlgorithmConfusion(context.Background(), nil, nil, "", "", parts, header); f != nil {
		t.Error("a symmetric token was treated as a candidate for confusion")
	}
}

// symmetricTestJWT is an HS256-shaped token. The signature is not checked by the fixtures here:
// what is under test is whether the endpoint verifies it at all, not whether this one is valid.
func symmetricTestJWT() string {
	b64 := base64.RawURLEncoding.EncodeToString
	return b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		b64([]byte(`{"sub":"crackweb"}`)) + ".not-a-real-signature"
}

// TestJWTStaysQuietWhenTheEndpointIgnoresTheHeader is the false positive this check used to
// report. An endpoint that never reads Authorization answers 200 to a token nobody signed —
// which is exactly what accepting an unsigned token looks like from the outside. Removing the
// credential is what separates them: if that succeeds too, the endpoint needs no credential and
// the forged token proved nothing.
func TestJWTStaysQuietWhenTheEndpointIgnoresTheHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never looks at the header.
		fmt.Fprint(w, "<html><body>welcome, stranger</body></html>")
	}))
	defer server.Close()

	request, _ := targetWithHeader(t, server.URL+"/anything")
	request.Header.Set("Authorization", "Bearer "+symmetricTestJWT())

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("an endpoint that ignores Authorization was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestJWTFiresWhenTheCredentialIsRequiredAndUnsignedIsAccepted is what the check exists for, and
// it has to survive that control: this endpoint refuses to answer without a credential, and
// accepts one whose algorithm is "none".
func TestJWTFiresWhenTheCredentialIsRequiredAndUnsignedIsAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		header := map[string]any{}
		if len(parts) > 0 {
			if decoded, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
				_ = json.Unmarshal(decoded, &header)
			}
		}
		// Accepts HS256 without checking the signature, and accepts "none" — the misconfiguration
		// under test. What it does do is refuse to answer without a credential at all.
		switch alg, _ := header["alg"].(string); {
		case strings.EqualFold(alg, "none"), alg == "HS256":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"user":"crackweb"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
	}))
	defer server.Close()

	request, _ := targetWithHeader(t, server.URL+"/api/me")
	request.Header.Set("Authorization", "Bearer "+symmetricTestJWT())

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil || baseline.Status != 200 {
		t.Fatalf("baseline: %v status=%v", err, baseline)
	}
	if findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline}); len(findings) == 0 {
		t.Error("an endpoint that requires a credential accepted an unsigned token, and it was not reported")
	}
}
