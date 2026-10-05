// Package local holds the work crackweb does without a target: an artifact the operator
// already has is examined here, and nothing is sent anywhere.
//
// It is a separate package from checks for the same reason it is a separate command. A check
// exists to ask a target a question, and is written against the request/response pair it is
// handed; what this package does has no target and no exchange — a token is a string, and
// whether its signature can be forged from a guess is arithmetic.
package local

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Token is a decoded JSON Web Token.
type Token struct {
	// Raw is the token as it was given.
	Raw string
	// Header and Payload are the decoded JSON objects.
	Header map[string]any
	// Payload as well, under the name the specification uses.
	Claims map[string]any
	// Signature is the third part, still base64.
	Signature string
	// SigningInput is the first two parts, which is what a signature covers.
	SigningInput string
}

// Algorithm is the "alg" the token declares.
func (t *Token) Algorithm() string {
	if v, ok := t.Header["alg"].(string); ok {
		return v
	}
	return ""
}

// Parse decodes a token without verifying it.
//
// Nothing here is trusted: a token is attacker-controlled input until a signature proves
// otherwise, and the whole point of the rest of this package is to be the thing that decides
// whether it is.
func Parse(raw string) (*Token, error) {
	raw = strings.TrimSpace(raw)
	// A token pasted from a browser console or a log often arrives quoted or prefixed.
	raw = strings.TrimPrefix(raw, "Bearer ")
	raw = strings.Trim(raw, "\"'")
	raw = strings.TrimSpace(raw)

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("a JSON Web Token has three dot-separated parts; this one has %d", len(parts))
	}

	header, err := decodePart(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	claims, err := decodePart(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return &Token{
		Raw:          raw,
		Header:       header,
		Claims:       claims,
		Signature:    parts[2],
		SigningInput: parts[0] + "." + parts[1],
	}, nil
}

// decodePart base64-decodes one part and reads it as JSON.
func decodePart(part string) (map[string]any, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		// Tokens written with padding are common enough that a strict failure would be a
		// needless complaint.
		decoded, err = base64.URLEncoding.DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("not base64url: %w", err)
		}
	}
	out := map[string]any{}
	if err := json.Unmarshal(decoded, &out); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	return out, nil
}

// Signed reports whether the token carries a signature at all.
func (t *Token) Signed() bool { return strings.TrimSpace(t.Signature) != "" }

// HMACAlgorithms are the algorithms whose signature is a keyed hash: a guessable secret is the
// whole of their security.
var HMACAlgorithms = []string{"HS256", "HS384", "HS512"}

// Symmetric reports whether the token is signed with the kind of algorithm a guessed secret can
// forge.
func (t *Token) Symmetric() bool {
	alg := strings.ToUpper(t.Algorithm())
	for _, name := range HMACAlgorithms {
		if alg == name {
			return true
		}
	}
	return false
}

// Expiry reports the "exp" claim, if the token carries one.
func (t *Token) Expiry() (time.Time, bool) {
	value, ok := t.Claims["exp"]
	if !ok {
		return time.Time{}, false
	}
	seconds, ok := number(value)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0), true
}

// number reads a JSON number, which encoding/json gives as float64 but a token may carry as a
// string when whatever minted it was careless.
func number(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case string:
		var f float64
		if _, err := fmt.Sscanf(v, "%g", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

// VerifyHMAC reports whether the token's signature is the one this secret produces.
//
// The comparison is constant-time: a token is not a place to leak how many bytes of a guess
// were right.
func (t *Token) VerifyHMAC(secret []byte) bool {
	if !t.Symmetric() {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(t.Signature)
	if err != nil {
		if expected, err = base64.URLEncoding.DecodeString(t.Signature); err != nil {
			return false
		}
	}
	return hmac.Equal(expected, signHMAC(t.Algorithm(), t.SigningInput, secret))
}

// SignHMAC returns the token header and payload signed with this secret, as the algorithm the
// token declares produces it.
func (t *Token) SignHMAC(secret []byte) string {
	signature := base64.RawURLEncoding.EncodeToString(signHMAC(t.Algorithm(), t.SigningInput, secret))
	return t.SigningInput + "." + signature
}

// signHMAC computes the signature for an algorithm.
func signHMAC(algorithm, signingInput string, secret []byte) []byte {
	// HS384 and HS512 are the same construction with a wider digest.
	var hash func() hash.Hash = sha256.New
	switch strings.ToUpper(algorithm) {
	case "HS384":
		hash = sha512.New384
	case "HS512":
		hash = sha512.New
	}
	mac := hmac.New(hash, secret)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// SymmetricAlgorithm reports whether a declared algorithm is one a guessable secret can forge.
func SymmetricAlgorithm(algorithm string) bool {
	upper := strings.ToUpper(algorithm)
	for _, name := range HMACAlgorithms {
		if upper == name {
			return true
		}
	}
	return false
}

// SignWith returns the signing input signed under a secret with the named algorithm.
func SignWith(algorithm, signingInput string, secret []byte) string {
	signature := base64.RawURLEncoding.EncodeToString(signHMAC(algorithm, signingInput, secret))
	return signingInput + "." + signature
}

// Forge returns a token this secret signs, with the named claims replaced.
//
// This is the last step of a discovery that started with a token in hand: once the secret is
// known, the question stops being "can it be recovered" and becomes "what can be issued with
// it". Overwriting a claim and signing the result answers that without the operator having to
// reassemble a token by hand.
//
// The header is carried over rather than rebuilt, so the algorithm stays what the target
// actually uses; replacing claims never touches it.
func (t *Token) Forge(secret []byte, claims map[string]any) (string, error) {
	header := make(map[string]any, len(t.Header))
	for key, value := range t.Header {
		header[key] = value
	}
	payload := make(map[string]any, len(t.Claims)+len(claims))
	for key, value := range t.Claims {
		payload[key] = value
	}
	for key, value := range claims {
		if value == nil {
			delete(payload, key)
			continue
		}
		payload[key] = value
	}

	headerPart, err := encodeJWTPart(header)
	if err != nil {
		return "", err
	}
	payloadPart, err := encodeJWTPart(payload)
	if err != nil {
		return "", err
	}
	return SignWith(t.Algorithm(), headerPart+"."+payloadPart, secret), nil
}

// encodeJWTPart marshals one part the way the specification wants it: compact JSON, base64url,
// no padding.
func encodeJWTPart(object map[string]any) (string, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ClaimFromValue reads a command-line claim the way a person writes one: a bare value is a
// string, "true"/"false" and numbers are the types they look like, and a JSON document is
// parsed as one. `role=admin` and `is_admin=true` both have to mean what they say.
func ClaimFromValue(value string) any {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var parsed any
		if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
			return parsed
		}
	}
	var number float64
	if _, err := fmt.Sscanf(trimmed, "%g", &number); err == nil && fmt.Sprintf("%g", number) == trimmed {
		return number
	}
	return value
}
