package local

import (
	"bufio"
	"os"
	"strings"
)

// DefaultSecrets are the secrets that keep turning up: a word the framework's own
// documentation uses, a placeholder nobody replaced, the name of the product. They are not
// meant to be exhaustive — a real engagement uses a real wordlist — but a target protecting
// itself with `secret` is common enough that shipping nothing would miss it.
//
// Deliberately small. A guess costs no request, but it costs the operator's time to read a
// finding, and a dictionary of a million entries belongs in a file the operator chose.
var DefaultSecrets = []string{
	// The framework defaults, which are what a hurried deployment leaves in place.
	"secret", "secretkey", "secret_key", "jwtsecret", "jwt_secret", "jwt-secret",
	"supersecret", "super_secret", "mysecret", "my-secret", "topsecret",
	"private", "privatekey", "private_key", "key", "appkey", "app_key",
	"changeme", "change_me", "change-me", "replace_me", "replaceme", "placeholder",
	"your-256-bit-secret", "your_secret_key", "your-secret-key", "yourkey",

	// Passwords people reach for when the field is called "secret".
	"password", "passwd", "pass", "admin", "administrator", "root", "toor", "letmein",
	"123456", "12345678", "123456789", "1234567890", "12345", "1234", "123",
	"qwerty", "abc123", "password123", "admin123", "test", "test1", "testing",
	"demo", "dev", "development", "staging", "prod", "production",
	"default", "none", "null", "true", "false", "1234abcd",

	// The three-letter abbreviation of the technology itself.
	"jwt", "jwtkey", "jwt_key", "jsonwebtoken", "jws", "jose", "token", "tokenkey",
	"auth", "authkey", "auth_key", "apikey", "api_key", "access", "accesskey",
	"session", "sessionkey", "cookie", "csrf", "oauth", "sso",
	"hmac", "hmac256", "hs256", "sha256", "symmetric", "shared", "sharedsecret",

	// Words that describe the thing they are protecting badly enough to be used as its key.
	"crackme", "hackme", "insecure", "unsafe", "notsosecret", "not-secret", "nosecret",
	"iloveyou", "love", "god", "trustno1", "monkey", "dragon", "master", "sunshine",
	"welcome", "shadow", "football", "baseball", "whatever", "letmein123",
}

// SecretCandidates returns the dictionary to try: the built-in list, anything the token itself
// suggests, and — when the operator named one — the contents of their file.
//
// Deriving from the token is worth the few lines: an issuer of "NeuraTech-OA" is very often
// signing with something built from that word, and no general wordlist carries it.
func SecretCandidates(t *Token, wordlist []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}

	for _, secret := range wordlist {
		add(secret)
	}
	for _, secret := range DefaultSecrets {
		add(secret)
	}
	for _, derived := range derivedSecrets(t) {
		add(derived)
	}
	return out
}

// derivedSecrets builds candidates out of the claims a token carries.
func derivedSecrets(t *Token) []string {
	var words []string
	for _, claim := range []string{"iss", "aud", "sub", "azp", "client_id"} {
		value, ok := t.Claims[claim].(string)
		if !ok || value == "" || len(value) > 64 {
			continue
		}
		words = append(words, value)
		if base, _, found := strings.Cut(value, "-"); found && base != "" {
			words = append(words, base)
		}
		if base, _, found := strings.Cut(value, "_"); found && base != "" {
			words = append(words, base)
		}
	}

	var out []string
	for _, word := range words {
		lower := strings.ToLower(word)
		upper := strings.ToUpper(word)
		out = append(out, word, lower, upper)
		// The spellings a developer reaches for without thinking.
		for _, suffix := range []string{"secret", "-secret", "_secret", "Secret", "key", "-key", "_key", "Key", "2024", "2025", "123"} {
			out = append(out, word+suffix, lower+suffix)
		}
	}
	return out
}

// ReadWordlist reads one secret per line, ignoring blanks and comments.
//
// A wordlist is written by hand or copied from somewhere and will have both.
func ReadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var out []string
	scanner := bufio.NewScanner(file)
	// Secrets can be long; the default token limit would truncate them silently.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// CrackResult is a secret that reproduces the token's signature.
type CrackResult struct {
	// Secret is the value that signed the token.
	Secret string
	// Index is its position in the candidate list, the built-in ones first.
	Index int
	// Tried is how many candidates were tested before this one.
	Tried int
}

// Crack finds the secret that signed an HMAC token, or reports that none of the candidates is
// it.
//
// Every guess is arithmetic. No request is made and nothing is sent to anyone: the token is
// already in hand, and a signature is a function of the header, the payload and the secret.
// That is also why this can be exhaustive where an online guess would have to be cautious —
// there is no target to lock out and no log to fill.
func Crack(t *Token, candidates []string) (*CrackResult, bool) {
	if !t.Symmetric() || !t.Signed() {
		return nil, false
	}
	for index, candidate := range candidates {
		if t.VerifyHMAC([]byte(candidate)) {
			return &CrackResult{Secret: candidate, Index: index, Tried: index + 1}, true
		}
	}
	return nil, false
}
