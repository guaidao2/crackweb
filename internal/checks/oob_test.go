package checks

import "testing"

func TestNumericHostForms(t *testing.T) {
	// 192.168.44.149 is 3232246933, and 0xC0A82C95.
	decimal, hexadecimal, ok := numericHostForms("192.168.44.149:8081")
	if !ok {
		t.Fatal("a dotted address has numeric forms")
	}
	if decimal != "3232246933:8081" {
		t.Errorf("decimal = %q, want %q", decimal, "3232246933:8081")
	}
	if hexadecimal != "0xc0a82c95:8081" {
		t.Errorf("hexadecimal = %q, want %q", hexadecimal, "0xc0a82c95:8081")
	}

	// Without a port.
	decimal, _, ok = numericHostForms("127.0.0.1")
	if !ok || decimal != "2130706433" {
		t.Errorf("numericHostForms(127.0.0.1) = %q, %v", decimal, ok)
	}
}

func TestNumericHostFormsRefusesWhatIsNotAnAddress(t *testing.T) {
	// A name has no numeric spelling, and inventing one would send a payload that tests
	// nothing.
	for _, host := range []string{"callback.example.com", "callback.example.com:8081", "::1"} {
		if _, _, ok := numericHostForms(host); ok {
			t.Errorf("%q was given a numeric form", host)
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
