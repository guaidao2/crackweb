package local

import "testing"

// TestIdentifyNamesTheHashesPeopleActuallyMeet: recognition is the half of this that runs
// without a wordlist, and it has to be right about the shapes that turn up.
func TestIdentifyNamesTheHashesPeopleActuallyMeet(t *testing.T) {
	cases := []struct{ value, want string }{
		{"$2y$10$abcdefghijklmnopqrstuv", "bcrypt"},
		{"$argon2id$v=19$m=65536,t=3,p=4$abc$def", "argon2id"},
		{"$6$rounds=5000$abcdef$xyz", "sha512crypt"},
		{"5f4dcc3b5aa765d61d8327deb882cf99", "MD5"},
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1"},
		{"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "SHA-256"},
		{"8846f7eaee8fb117ad06bdd830b7586c", "NTLM"},
		{"*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9", "MySQL 4.1+ password"},
	}
	for _, c := range cases {
		kinds := Identify(c.value)
		found := false
		for _, k := range kinds {
			if k.Name == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("Identify(%q) = %v, want %s among them", c.value, kinds, c.want)
		}
	}
}

// TestCrackHashRecoversACommonPassword is the whole point: a digest of a word from the built-in
// list comes back. Everything is local arithmetic.
func TestCrackHashRecoversACommonPassword(t *testing.T) {
	// MD5("password"), which is in every dump.
	const stored = "5f4dcc3b5aa765d61d8327deb882cf99"
	result, ok := CrackHash(stored, Identify(stored), ReadCandidates(nil))
	if !ok {
		t.Fatal("the MD5 of a well-known password was not recovered")
	}
	if result.Plaintext != "password" {
		t.Errorf("plaintext = %q, want password", result.Plaintext)
	}
	if result.Kind != "MD5" {
		t.Errorf("kind = %q, want MD5", result.Kind)
	}
}

// TestCrackHashRefusesWhatItCannotDo keeps the honest line: bcrypt is recognised and not
// attacked, because the standard library cannot reproduce it and guessing at it is not this.
func TestCrackHashRefusesWhatItCannotDo(t *testing.T) {
	const bcrypt = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	kinds := Identify(bcrypt)
	if len(kinds) == 0 || kinds[0].Name != "bcrypt" {
		t.Fatalf("a bcrypt value was not recognised: %v", kinds)
	}
	if _, ok := CrackHash(bcrypt, kinds, ReadCandidates(nil)); ok {
		t.Error("bcrypt was reported as cracked, and it cannot be")
	}
}

// TestCrackHashStaysQuietOnAnUnknownDigest: not everything crackable-looking is weak.
func TestCrackHashStaysQuietOnAnUnknownDigest(t *testing.T) {
	// A digest of a phrase no list carries.
	const stored = "0c3d7f2b9e4a1c5d8f6b3e2a9c7d4f1b"
	if _, ok := CrackHash(stored, Identify(stored), ReadCandidates(nil)); ok {
		t.Error("a digest nothing in the list produces was reported as cracked")
	}
}
