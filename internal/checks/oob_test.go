package checks

import "testing"

// TestAddressSpellingsCoverTheOtherWritings: each spelling is the same address to
// a resolver and a different string to a filter.
func TestAddressSpellingsCoverTheOtherWritings(t *testing.T) {
	spellings := addressSpellings("192.168.44.149:8081")
	if spellings == nil {
		t.Fatal("a dotted address has other spellings")
	}
	want := map[string]string{
		CallbackHostDecimal: "3232246933:8081",
		CallbackHostHex:     "0xc0a82c95:8081",
		CallbackHostOctal:   "0300.0250.054.0225:8081",
		CallbackHostMapped:  "[::ffff:192.168.44.149]:8081",
	}
	for placeholder, expected := range want {
		if got := spellings[placeholder]; got != expected {
			t.Errorf("%s = %q, want %q", placeholder, got, expected)
		}
	}
	// The octets between the first and the last are not zero here, so the short
	// form would name a different host and must not be offered at all.
	if got, ok := spellings[CallbackHostShort]; ok {
		t.Errorf("short form offered for 192.168.44.149: %q", got)
	}
}

// TestAddressSpellingsShortFormOnlyWhenItIsTheSameAddress: `127.1` is 127.0.0.1,
// and it is offered only when that is true.
func TestAddressSpellingsShortFormOnlyWhenItIsTheSameAddress(t *testing.T) {
	spellings := addressSpellings("127.0.0.1")
	if spellings == nil {
		t.Fatal("no spellings for a loopback address")
	}
	for placeholder, expected := range map[string]string{
		CallbackHostDecimal: "2130706433",
		CallbackHostOctal:   "0177.00.00.01",
		CallbackHostShort:   "127.1",
		CallbackHostMapped:  "[::ffff:127.0.0.1]",
	} {
		if got := spellings[placeholder]; got != expected {
			t.Errorf("%s = %q, want %q", placeholder, got, expected)
		}
	}
}

func TestAddressSpellingsRefuseWhatIsNotAnAddress(t *testing.T) {
	// A name has no address spelling, and inventing one would send a payload that
	// tests nothing.
	for _, host := range []string{"callback.example.com", "callback.example.com:8081", "::1"} {
		if addressSpellings(host) != nil {
			t.Errorf("%q was given an address spelling", host)
		}
	}
}

func TestSubstituteCallbackFillsTheNumericPlaceholders(t *testing.T) {
	got := substituteCallback(
		"http://"+CallbackHostDecimal+"/?url="+CallbackURL,
		"http://192.168.44.149:8081/ab12")
	want := "http://3232246933:8081/?url=http://192.168.44.149:8081/ab12"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSubstituteCallbackDropsWhatItCannotFill(t *testing.T) {
	// The callback is reached by name here, so there is no numeric spelling. An empty
	// result is what tells the caller to skip the payload rather than send a placeholder.
	if got := substituteCallback("http://"+CallbackHostDecimal+"/", "http://callback.example.com:8081/x"); got != "" {
		t.Errorf("got %q, want an empty result", got)
	}
}

func TestSubstituteCallbackLeavesOrdinarySeedsAlone(t *testing.T) {
	got := substituteCallback(CallbackURL+"/x", "http://192.168.44.149:8081/ab12")
	if want := "http://192.168.44.149:8081/ab12/x"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
