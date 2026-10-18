package local

import (
	"crypto/sha1"
	"encoding/base64"
	"testing"
)

// TestIdentifyDoesNotCallAnOrdinaryWordBase64: every lowercase word uses a subset of the
// base64 alphabet, and a length test alone reported "password" as a digest.
func TestIdentifyDoesNotCallAnOrdinaryWordBase64(t *testing.T) {
	for _, value := range []string{"password", "abcdefghijklmnop", "correcthorsebattery"} {
		if kinds := Identify(value); len(kinds) != 0 {
			t.Errorf("Identify(%q) = %v, want no hash kinds", value, kinds)
		}
	}
}

// TestCrackHashRecoversAnLdapShaValue: an LDAP {SHA} value is a base64 digest, not a hex
// one. It was labelled crackable and then never matched anything.
func TestCrackHashRecoversAnLdapShaValue(t *testing.T) {
	sum := sha1.Sum([]byte("password"))
	stored := "{SHA}" + base64.StdEncoding.EncodeToString(sum[:])

	kinds := Identify(stored)
	if len(kinds) == 0 || kinds[0].Name != "SHA-1" {
		t.Fatalf("the LDAP value was not recognised: %v", kinds)
	}
	result, ok := CrackHash(stored, kinds, ReadCandidates(nil))
	if !ok {
		t.Fatal("the LDAP SHA value was not recovered")
	}
	if result.Plaintext != "password" || result.Kind != "SHA-1" {
		t.Errorf("got %+v, want password as SHA-1", result)
	}
}
