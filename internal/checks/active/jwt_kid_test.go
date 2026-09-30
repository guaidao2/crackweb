package active

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
)

// bearerJWTSite verifies a token and looks its key up by `kid`, reading the file
// the identifier names — the weakness itself. It insists on the `Bearer ` scheme,
// which is what makes the header rebuild visible: a forged token that arrives
// without its scheme is refused for its shape, and the finding would then never
// appear on any target that uses one.
func bearerJWTSite(t *testing.T) *httptest.Server {
	t.Helper()
	reject := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid token"}`)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			reject(w)
			return
		}
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			reject(w)
			return
		}
		header, err := decodeJWTPart(parts[0])
		if err != nil {
			reject(w)
			return
		}
		kid, _ := header["kid"].(string)
		// `/dev/null` reads as an empty file; anything else is the real key.
		key := []byte("real-secret-for-jwt")
		if strings.Contains(kid, "null") {
			key = nil
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || !hmac.Equal(mac.Sum(nil), signature) {
			reject(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(server.Close)
	return server
}

// signedToken builds a token the way the site above expects it.
func signedToken(t *testing.T, kid string, key []byte) string {
	t.Helper()
	return signJWT(map[string]any{"alg": "HS256", "kid": kid}, map[string]any{"sub": "alice"}, key)
}

// TestJWTFiresOnAKidThatNamesAnEmptyFile: the key lookup follows the caller's
// identifier to `/dev/null`, and the token signed with the empty key is accepted.
func TestJWTFiresOnAKidThatNamesAnEmptyFile(t *testing.T) {
	server := bearerJWTSite(t)
	request, _ := targetWithHeader(t, server.URL+"/me")
	request.Header.Set("Authorization", "Bearer "+signedToken(t, "/root/range/jwtkey", []byte("real-secret-for-jwt")))

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil || baseline.Status != 200 {
		t.Fatalf("baseline: %v status=%v", err, baseline)
	}

	findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("a key lookup that follows the identifier was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "dev/null") {
		t.Errorf("evidence does not name the identifier: %v", findings[0].Evidence.Matches)
	}
}

// TestJWTForgeryKeepsTheBearerScheme is the regression for the header rebuild: a
// forged token that arrives without its scheme is refused for its shape, so the
// finding would never appear on a target that uses one.
func TestJWTForgeryKeepsTheBearerScheme(t *testing.T) {
	value := replaceToken("Bearer eyJhbGciOiJIUzI1NiJ9.abc.def", "eyJhbGciOiJIUzI1NiJ9.abc.def", "forged")
	if !strings.HasPrefix(value, "Bearer ") {
		t.Errorf("replaceToken dropped the scheme: %q", value)
	}
	if !strings.HasSuffix(value, "forged") {
		t.Errorf("replaceToken did not substitute the token: %q", value)
	}
	// A token that is not in the value is still delivered on its own, which is
	// what a Cookie header holding nothing else needs.
	if got := replaceToken("", "a.b.c", "forged"); got != "forged" {
		t.Errorf("replaceToken on an empty value = %q, want the token alone", got)
	}
}

// TestJWTStaysQuietWhenTheKeyIsFixed: the identifier is ignored, so no forgery
// succeeds and nothing is reported.
func TestJWTStaysQuietWhenTheKeyIsFixed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid token"}`)
			return
		}
		parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid token"}`)
			return
		}
		mac := hmac.New(sha256.New, []byte("real-secret-for-jwt"))
		mac.Write([]byte(parts[0] + "." + parts[1]))
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if !hmac.Equal(mac.Sum(nil), signature) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid token"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	// The token the application itself would issue: signed with the real key, so
	// it is accepted, and the identifier it carries cannot change that.
	request, _ := targetWithHeader(t, server.URL+"/me")
	request.Header.Set("Authorization", "Bearer "+signedToken(t, "/dev/null", []byte("real-secret-for-jwt")))

	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil || baseline.Status != 200 {
		t.Fatalf("baseline: %v status=%v", err, baseline)
	}
	if findings := runRequestLevel(t, h, jwt{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a site with a fixed key was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestTamperSignatureChangesTheBytes is the bug this used to have. A signature is 32 bytes, its
// base64 is 43 characters, and the last character carries only two padding bits — so a signature
// ending in `A` becomes one ending in `B` that decodes to exactly the same bytes. The "forged"
// control token was therefore valid, the verifier accepted it, and the check concluded that
// signatures were not verified and abandoned the target.
func TestTamperSignatureChangesTheBytes(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	// A trailing byte whose low two bits are zero puts `A` at the end of the encoding.
	raw[len(raw)-1] = 0x00
	signature := base64.RawURLEncoding.EncodeToString(raw)
	if !strings.HasSuffix(signature, "A") {
		t.Fatalf("the fixture does not end in A as intended: %q", signature[len(signature)-4:])
	}

	forged := tamperSignature(signature)
	decoded, err := base64.RawURLEncoding.DecodeString(forged)
	if err != nil {
		t.Fatalf("the forgery is not decodable: %q (%v)", forged, err)
	}
	if bytes.Equal(decoded, raw) {
		t.Errorf("the forgery decodes to the original signature: %q", forged)
	}
	if len(decoded) != len(raw) {
		t.Errorf("the forgery has length %d, want %d", len(decoded), len(raw))
	}
	// And an empty signature still gets something.
	if tamperSignature("") == "" {
		t.Error("an empty signature was left empty")
	}
}
