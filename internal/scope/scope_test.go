package scope

import "testing"

func TestScopeMatching(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		host     string
		want     bool
	}{
		{"empty scope matches everything", nil, "anything.example", true},
		{"exact host", []string{"example.com"}, "example.com", true},
		{"port is ignored", []string{"example.com"}, "example.com:8443", true},
		{"bare domain covers subdomains", []string{"example.com"}, "www.example.com", true},
		{"wildcard subdomain", []string{"*.example.com"}, "api.example.com", true},
		{"wildcard also covers the apex", []string{"*.example.com"}, "example.com", true},
		{"leading dot form", []string{".example.com"}, "mail.example.com", true},
		{"different domain", []string{"example.com"}, "example.org", false},
		{"suffix confusion is not a match", []string{"example.com"}, "notexample.com", false},
		{"cidr range", []string{"10.0.0.0/8"}, "10.1.2.3", true},
		{"cidr outside range", []string{"10.0.0.0/8"}, "192.168.1.1", false},
		{"one of several patterns", []string{"a.example", "b.example"}, "b.example", true},
		{"case insensitive", []string{"Example.COM"}, "EXAMPLE.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewScope(tc.patterns).Contains(tc.host); got != tc.want {
				t.Errorf("Contains(%q) with %v = %v, want %v", tc.host, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestScopeIgnoresBlankPatterns(t *testing.T) {
	if !NewScope([]string{"", "   "}).Empty() {
		t.Error("blank patterns should leave the scope empty (match everything)")
	}
}

func TestStripPort(t *testing.T) {
	cases := map[string]string{
		"example.com:443": "example.com",
		"example.com":     "example.com",
		"[::1]:8080":      "::1",
		"[::1]":           "::1",
		"":                "",
	}
	for in, want := range cases {
		if got := StripPort(in); got != want {
			t.Errorf("StripPort(%q) = %q, want %q", in, got, want)
		}
	}
}
