package crawl

import (
	"net/url"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/apidoc"
)

// parseDocumentFor builds a parsed description whose operations point at one host.
func parseDocumentFor(t *testing.T, server string) *apidoc.Document {
	t.Helper()
	doc, ok := apidoc.Parse([]byte(`
openapi: "3.0.0"
info: {title: t, version: "1"}
servers: [{url: "`+server+`"}]
paths:
  /thing:
    get: {}
`), nil)
	if !ok {
		t.Fatal("the sample description did not parse")
	}
	return doc
}

func TestAPIDocReferencesAreFoundWhereTheyAreSpelled(t *testing.T) {
	base, err := url.Parse("https://app.example.com/ui/index.html")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	cases := map[string]string{
		// Swagger UI carries its own address this way, which is why asking the common paths
		// alone is not enough.
		`SwaggerUIBundle({ url: "/swagger.json", dom_id: "#ui" })`:     "https://app.example.com/swagger.json",
		"const spec = '/openapi.yaml';":                                "https://app.example.com/openapi.yaml",
		`{"servers":[{"url":"https://api.example.com/swagger.json"}]}`: "https://api.example.com/swagger.json",
		// Not descriptions.
		`<a href="/help.html">help</a>`:         "",
		`fetch('/api/items.json')`:              "",
		`<link rel="stylesheet" href="/a.css">`: "",
	}
	for body, want := range cases {
		got := apiDocReferences(body, base)
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%q produced %v, want nothing", body, got)
			}
			continue
		}
		found := false
		for _, reference := range got {
			if reference == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q produced %v, want %q among them", body, got, want)
		}
	}
}

func TestSeedAPIDocsAsksTheCommonAddressesOfTheSeedHost(t *testing.T) {
	c := newTestCrawler(t, "example.com")
	seed, err := url.Parse("https://example.com/app/page?q=1#frag")
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}

	got := c.seedAPIDocs(seed)
	if len(got) != len(apiDocPaths) {
		t.Fatalf("got %d addresses, want %d", len(got), len(apiDocPaths))
	}
	for _, address := range got {
		parsed, err := url.Parse(address)
		if err != nil {
			t.Fatalf("generated %q is not a URL: %v", address, err)
		}
		if parsed.Host != "example.com" {
			t.Errorf("%q walks off the seed host", address)
		}
		// The seed's own path, query and fragment have no business in a guess.
		if strings.Contains(address, "frag") || strings.Contains(address, "q=1") ||
			strings.Contains(address, "/app/") {
			t.Errorf("%q carries part of the seed's address", address)
		}
	}
}

func TestSeedAPIDocsStaysOutOfScope(t *testing.T) {
	c := newTestCrawler(t, "other.example.net")
	seed, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	if got := c.seedAPIDocs(seed); len(got) != 0 {
		t.Errorf("probed %v, which is outside the scope", got)
	}
}

func TestDeliverDocumentStaysOutOfScope(t *testing.T) {
	// A description is free to name any host. Following it off the engagement would be
	// exactly the mistake scope exists to prevent.
	c := newTestCrawler(t, "example.com")
	if got := c.deliverDocument(t.Context(), parseDocumentFor(t, "https://other.example.net/v1")); got != 0 {
		t.Errorf("delivered %d operations for a host outside the scope", got)
	}
}
