package local

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// HashKind is what a string looks like it is.
type HashKind struct {
	// Name is the algorithm, as people write it.
	Name string
	// Note says what identifies it, which is what the reader wants when two algorithms
	// share the shape.
	Note string
	// Salted records that the value carries its own salt, so a plain digest table cannot be
	// compared against it.
	Salted bool
	// Crackable records that a word can be hashed and compared locally, with the standard
	// library alone. bcrypt and the argon family are deliberately not: they are designed to
	// be slow, they need a parameterised implementation, and guessing at them is not what
	// this is for.
	Crackable bool
	// new hasher builds the digest for a Crackable kind.
	new func() hash.Hash
}

// hashKinds are the shapes worth recognising, longest prefix first so that the specific
// formats win over the generic ones.
var hashKinds = []struct {
	prefix string
	kind   HashKind
}{
	{"$2y$", HashKind{Name: "bcrypt", Note: "the $2y$ variant, as PHP writes it", Salted: true}},
	{"$2a$", HashKind{Name: "bcrypt", Note: "the $2a$ variant", Salted: true}},
	{"$2b$", HashKind{Name: "bcrypt", Note: "the $2b$ variant", Salted: true}},
	{"$argon2id$", HashKind{Name: "argon2id", Note: "memory-hard, salted", Salted: true}},
	{"$argon2i$", HashKind{Name: "argon2i", Salted: true}},
	{"$argon2d$", HashKind{Name: "argon2d", Salted: true}},
	{"$scrypt$", HashKind{Name: "scrypt", Salted: true}},
	{"$pbkdf2-sha256$", HashKind{Name: "PBKDF2-SHA256", Salted: true}},
	{"$pbkdf2-sha512$", HashKind{Name: "PBKDF2-SHA512", Salted: true}},
	{"$6$", HashKind{Name: "sha512crypt", Note: "crypt(3) with SHA-512", Salted: true}},
	{"$5$", HashKind{Name: "sha256crypt", Note: "crypt(3) with SHA-256", Salted: true}},
	{"$1$", HashKind{Name: "md5crypt", Note: "crypt(3) with MD5, still seen in old /etc/shadow", Salted: true}},
	{"{SSHA}", HashKind{Name: "SSHA", Note: "an LDAP RFC 2307 hash, base64", Salted: true}},
	{"{SHA}", HashKind{Name: "SHA-1", Note: "an LDAP RFC 2307 hash, base64", Crackable: true, new: sha1.New}},
	{"*", HashKind{Name: "MySQL 4.1+ password", Note: "a leading * then 40 hex; the inner value is an unsalted SHA-1 of a SHA-1", Crackable: true, new: sha1.New}},
}

// Identify says what a string looks like. The answer is a list: the length of a hex digest
// does not tell MD5 from NTLM from MD4, and pretending otherwise would be worse than saying so.
func Identify(value string) []HashKind {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	var out []HashKind
	seen := map[string]bool{}
	add := func(kind HashKind) {
		if seen[kind.Name] {
			return
		}
		seen[kind.Name] = true
		out = append(out, kind)
	}

	for _, candidate := range hashKinds {
		if strings.HasPrefix(value, candidate.prefix) {
			add(candidate.kind)
		}
	}
	if len(out) > 0 {
		return out
	}

	// No prefix and no marker: all that is left is the length and the alphabet.
	if isHex(value) {
		if kind, ok := hexShapes[len(value)]; ok {
			for _, k := range kind {
				add(k)
			}
			return out
		}
	}
	// Base64 is the LDAP and pass-the-hash spelling.
	if isBase64(value) && len(value)%4 == 0 {
		add(HashKind{Name: "base64 digest", Note: "28 or 32 characters usually mean a SHA-1 or MD5 family hash in base64"})
	}
	return out
}

// hexShapes maps a digest length to everything that produces one.
var hexShapes = map[int][]HashKind{
	16: {{Name: "CRC-64", Note: "or a truncated digest; 16 hex digits alone identify nothing"}},
	32: {
		{Name: "MD5", Crackable: true, new: md5.New},
		{Name: "NTLM", Note: "same shape as MD5; told apart only by context"},
		{Name: "MD4", Note: "same shape as MD5"},
	},
	40:  {{Name: "SHA-1", Crackable: true, new: sha1.New}},
	56:  {{Name: "SHA-224", Crackable: true, new: sha256.New224}},
	64:  {{Name: "SHA-256", Crackable: true, new: sha256.New}},
	96:  {{Name: "SHA-384", Crackable: true, new: sha512.New384}},
	128: {{Name: "SHA-512", Crackable: true, new: sha512.New}},
}

// isHex reports whether every character is a hex digit.
func isHex(value string) bool {
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// isBase64 reports whether the value uses only the base64 alphabet, padding aside.
func isBase64(value string) bool {
	for _, r := range strings.TrimRight(value, "=") {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", r) {
			return false
		}
	}
	return true
}

// CrackResult is a plaintext whose digest equals the value.
type HashCrackResult struct {
	// Plaintext is the word that produced the digest.
	Plaintext string
	// Kind is the algorithm it was hashed with.
	Kind string
	// Tried is how many candidates were tested.
	Tried int
}

// CommonPasswords is the short list worth trying before asking for a real wordlist. It is the
// same shape as the JWT secrets and for the same reason: the words people reach for are few
// and they are the whole of what these hashes protect.
var CommonPasswords = []string{
	"", "password", "Password", "PASSWORD", "password1", "Password1", "password123",
	"passw0rd", "pa$$word", "p@ssw0rd", "P@ssw0rd", "P@ssw0rd!", "password!", "pass",
	"123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234", "123",
	"111111", "000000", "666666", "888888", "121212", "123123", "654321", "qwerty",
	"qwerty123", "qwertyuiop", "abc123", "abcd1234", "a1b2c3", "1q2w3e4r", "qazwsx",
	"letmein", "welcome", "welcome1", "monkey", "dragon", "master", "shadow", "sunshine",
	"iloveyou", "trustno1", "football", "baseball", "superman", "batman", "starwars",
	"admin", "admin123", "administrator", "root", "toor", "test", "test123", "guest",
	"user", "default", "changeme", "secret", "mysql", "postgres", "oracle", "sa",
	"azerty", "motdepasse", "passwort", "contraseña", "пароль",
}

// Crack tries candidates against a hash that Identify said is crackable.
//
// The work is a digest per candidate, locally. Nothing is sent and nothing is looked up: a
// digest is a function, and a word that reproduces it is proof.
func CrackHash(value string, kinds []HashKind, candidates []string) (*HashCrackResult, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	// The MySQL spelling wraps the digest in an asterisk; strip it for comparison.
	inner := strings.TrimPrefix(value, "*")

	for _, kind := range kinds {
		if !kind.Crackable || kind.new == nil {
			continue
		}
		for index, candidate := range candidates {
			digest := kind.new()
			digest.Write([]byte(candidate))
			sum := hex.EncodeToString(digest.Sum(nil))
			if kind.Name == "MySQL 4.1+ password" {
				// The stored value is SHA-1(SHA-1(word)), upper case, behind an asterisk.
				sum = strings.ToUpper(hex.EncodeToString(sha1Sum(mustHex(sum))))
			}
			if sum == inner || strings.EqualFold(sum, inner) {
				return &HashCrackResult{Plaintext: candidate, Kind: kind.Name, Tried: index + 1}, true
			}
		}
	}
	return nil, false
}

// sha1Sum returns the SHA-1 of the bytes a hex string names.
func sha1Sum(raw []byte) []byte {
	sum := sha1.Sum(raw)
	return sum[:]
}

// mustHex decodes a hex string, which the caller has already produced.
func mustHex(value string) []byte {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil
	}
	return raw
}

// ReadCandidates builds the list to try: the operator's wordlist first, then the built-in one.
func ReadCandidates(wordlist []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{wordlist, CommonPasswords} {
		for _, word := range list {
			if seen[word] {
				continue
			}
			seen[word] = true
			out = append(out, word)
		}
	}
	return out
}

// Describe renders a kind for the operator.
func (k HashKind) Describe() string {
	parts := []string{k.Name}
	if k.Note != "" {
		parts = append(parts, k.Note)
	}
	if k.Salted {
		parts = append(parts, "salted: the salt is inside the value")
	}
	if k.Crackable {
		parts = append(parts, "can be tried against a wordlist")
	}
	return strings.Join(parts, " — ")
}

// String makes a kind printable in an error or a report.
func (k HashKind) String() string { return fmt.Sprintf("%s", k.Name) }
