package crawl

import (
	"net/url"
	"testing"
)

func TestParseRobotsReadsDisallowsAndSitemaps(t *testing.T) {
	body := `# a robots file
User-agent: *
Disallow: /admin/
Disallow: /internal/api
Disallow: /
Disallow: /*.php$
Disallow:
Allow: /public

Sitemap: https://example.com/sitemap-main.xml
Sitemap: /sitemap-index.xml
`
	disallowed, sitemaps := parseRobots(body)

	want := []string{"/admin/", "/internal/api"}
	if len(disallowed) != len(want) {
		t.Fatalf("disallowed = %v, want %v", disallowed, want)
	}
	for i, path := range want {
		if disallowed[i] != path {
			t.Errorf("disallowed[%d] = %q, want %q", i, disallowed[i], path)
		}
	}

	if len(sitemaps) != 2 || sitemaps[0] != "https://example.com/sitemap-main.xml" {
		t.Errorf("sitemaps = %v", sitemaps)
	}
}

// TestRobotsEntriesThatNameNothingAreSkipped: an empty value allows everything, a bare "/"
// disallows everything, and a pattern is a rule rather than a path. None of them is an
// address, and turning one into a request would ask for the whole site or for a literal "*".
func TestRobotsEntriesThatNameNothingAreSkipped(t *testing.T) {
	for _, value := range []string{"", "/", "/*.php$", "/admin/*", "/index.html$", "admin/"} {
		if path, ok := usableRobotsPath(value); ok {
			t.Errorf("%q was turned into the address %q", value, path)
		}
	}
	for _, value := range []string{"/admin/", "/internal/api", "/backup.zip"} {
		if _, ok := usableRobotsPath(value); !ok {
			t.Errorf("%q names a path and was skipped", value)
		}
	}
}

func TestParseSitemapReadsLocations(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/a</loc></url>
  <url><loc> https://example.com/b </loc></url>
</urlset>`
	locations, indexes := parseSitemap([]byte(body))
	if len(indexes) != 0 {
		t.Errorf("a urlset produced indexes: %v", indexes)
	}
	if len(locations) != 2 || locations[0] != "https://example.com/a" || locations[1] != "https://example.com/b" {
		t.Errorf("locations = %v", locations)
	}
}

func TestParseSitemapReadsAnIndex(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
</sitemapindex>`
	locations, indexes := parseSitemap([]byte(body))
	if len(locations) != 0 {
		t.Errorf("an index produced locations: %v", locations)
	}
	if len(indexes) != 1 || indexes[0] != "https://example.com/sitemap-1.xml" {
		t.Errorf("indexes = %v", indexes)
	}
}

func TestSiteFileReferencesResolveAgainstTheHost(t *testing.T) {
	base, err := url.Parse("https://example.com/robots.txt")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	robots := `User-agent: *
Disallow: /admin/
Sitemap: /sitemap.xml
`
	references := siteFileReferences([]byte(robots), base)
	seen := map[string]bool{}
	for _, reference := range references {
		seen[reference] = true
	}
	// The sitemap comes first: it carries more addresses than a Disallow line does.
	if len(references) == 0 || references[0] != "https://example.com/sitemap.xml" {
		t.Errorf("the named sitemap is not first: %v", references)
	}
	if !seen["https://example.com/admin/"] {
		t.Errorf("the disallowed path was not resolved: %v", references)
	}

	sitemap := `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page</loc></url>
</urlset>`
	if got := siteFileReferences([]byte(sitemap), base); len(got) != 1 || got[0] != "https://example.com/page" {
		t.Errorf("sitemap references = %v", got)
	}
}

func TestSiteFileDetectionIgnoresPages(t *testing.T) {
	base, _ := url.Parse("https://example.com/")

	// A page is not a robots file however much it talks about one.
	page := []byte(`<html><body>Disallow: /admin/ is what a robots file says.</body></html>`)
	if got := siteFileReferences(page, base); len(got) != 0 {
		t.Errorf("a page was read as a robots file: %v", got)
	}
	// And an ordinary JSON response is neither.
	if got := siteFileReferences([]byte(`{"items":[1,2]}`), base); len(got) != 0 {
		t.Errorf("a JSON response was read as a site file: %v", got)
	}
	if got := siteFileReferences(nil, base); len(got) != 0 {
		t.Errorf("an empty body produced references: %v", got)
	}
}

func TestSitemapLocationsAreBounded(t *testing.T) {
	body := `<urlset>`
	for i := 0; i < maxSitemapLocations*2; i++ {
		body += `<url><loc>https://example.com/p</loc></url>`
	}
	body += `</urlset>`

	locations, _ := parseSitemap([]byte(body))
	if len(locations) != maxSitemapLocations {
		t.Errorf("got %d locations, want the cap of %d", len(locations), maxSitemapLocations)
	}
}
