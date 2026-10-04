package local

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// sign builds a token the way any implementation would.
func sign(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := b64(header) + "." + b64(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil))
}

func TestParseReadsAWellFormedToken(t *testing.T) {
	raw := sign(t, "secret", map[string]any{"iss": "NeuraTech-OA", "user_id": float64(34)})
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if token.Algorithm() != "HS256" {
		t.Errorf("algorithm = %q", token.Algorithm())
	}
	if !token.Symmetric() {
		t.Error("HS256 was not treated as a keyed-hash algorithm")
	}
	if token.Claims["iss"] != "NeuraTech-OA" {
		t.Errorf("iss = %v", token.Claims["iss"])
	}
	// A token pasted from a browser arrives with the scheme attached more often than not.
	if _, err := Parse("Bearer " + raw); err != nil {
		t.Errorf("a token prefixed with Bearer was rejected: %v", err)
	}
}

func TestParseRejectsWhatIsNotAToken(t *testing.T) {
	for _, raw := range []string{"", "not-a-jwt", "only.two", "a.b.c.d"} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%q was accepted as a token", raw)
		}
	}
}

func TestCrackFindsTheSecretThatSignedTheToken(t *testing.T) {
	raw := sign(t, "secret", map[string]any{"iss": "example"})
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	candidates := SecretCandidates(token, nil)
	result, found := Crack(token, candidates)
	if !found {
		t.Fatalf("a token signed with %q was not cracked", "secret")
	}
	if result.Secret != "secret" {
		t.Errorf("secret = %q", result.Secret)
	}
	if !strings.HasSuffix(token.SignHMAC([]byte(result.Secret)), token.Signature) {
		t.Error("the secret found does not reproduce the signature")
	}
}

// TestCrackDerivesFromTheTokensOwnClaims covers the case a general wordlist cannot: the key is
// built from the issuer the token itself publishes.
func TestCrackDerivesFromTheTokensOwnClaims(t *testing.T) {
	raw := sign(t, "NeuraTech2024", map[string]any{"iss": "NeuraTech-OA"})
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	result, found := Crack(token, SecretCandidates(token, nil))
	if !found {
		t.Fatal("a key derived from the issuer was not found")
	}
	if result.Secret != "NeuraTech2024" {
		t.Errorf("secret = %q, want the derived one", result.Secret)
	}
}

func TestCrackStaysQuietOnAStrongSecret(t *testing.T) {
	raw := sign(t, "a-very-long-random-key-Xq7mK9vB2", map[string]any{"iss": "example"})
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, found := Crack(token, SecretCandidates(token, nil)); found {
		t.Error("a random secret was reported as cracked")
	}
}

// TestCrackRefusesAsymmetricTokens keeps the distinction the whole command rests on: an
// asymmetric signature is not a function of a guessable secret.
func TestCrackRefusesAsymmetricTokens(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"iss": "example"})
	raw := b64(header) + "." + b64(payload) + ".c2lnbmF0dXJl"
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if token.Symmetric() {
		t.Error("RS256 was treated as a keyed-hash algorithm")
	}
	if _, found := Crack(token, SecretCandidates(token, nil)); found {
		t.Error("an RS256 token was reported as cracked")
	}
}

func TestWordlistFromFileIsTriedFirst(t *testing.T) {
	raw := sign(t, "from-the-file", map[string]any{"iss": "example"})
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	result, found := Crack(token, SecretCandidates(token, []string{"nope", "from-the-file"}))
	if !found {
		t.Fatal("a secret from the supplied wordlist was not found")
	}
	if result.Index != 1 {
		t.Errorf("index = %d, want the position in the supplied list", result.Index)
	}
}

func TestExpiryIsReadFromTheClaims(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	raw := sign(t, "secret", map[string]any{"exp": float64(past)})
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	expiry, ok := token.Expiry()
	if !ok {
		t.Fatal("exp was not read")
	}
	if !expiry.Before(time.Now()) {
		t.Errorf("expiry %v is not in the past", expiry)
	}
}
