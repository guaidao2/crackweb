package crawl

import (
	"encoding/xml"
	"net/url"
	"strings"
)

// A site describes itself in two files that are worth more than they look. A sitemap lists
// the addresses the site knows about, which is a page list nobody had to crawl for. A
// robots file lists the addresses the site would rather nobody looked at — and an entry
// there is a path somebody decided not to link to, which is where the interesting ones are.
//
// Reading a robots file is a deliberate choice, not an oversight. The convention exists for
// search engines, which are trying not to be a nuisance; a scan run against a system its
// operator authorised is asking a different question. Leaving the folder out would mean
// missing the administration interface precisely because nobody wanted it found, so the
// paths are fetched like any other address — and reported as coming from there, so a reader
// of the log knows why they were asked for.

// siteFilePaths are the two addresses a site publishes about itself.
var siteFilePaths = []string{
	"/robots.txt",
	"/sitemap.xml",
}

// maxSitemapBytes bounds what is read from a sitemap. A large site publishes megabytes of
// them, and a crawl that spends its budget on one file has stopped being a crawl.
const maxSitemapBytes = 2 << 20

// maxSitemapLocations bounds how many addresses one sitemap contributes.
const maxSitemapLocations = 500

// seedWellKnown returns the addresses a seed's host may publish one of a set of known files
// at.
//
// Only the host and the scheme come from the seed: its path, query and fragment describe one
// page, and a guess about where a description lives has no business carrying any of them.
func (c *Crawler) seedWellKnown(seed *url.URL, paths []string) []string {
	if seed == nil {
		return nil
	}
	var out []string
	for _, path := range paths {
		candidate := *seed
		candidate.Path = path
		candidate.RawPath = ""
		candidate.RawQuery = ""
		candidate.ForceQuery = false
		candidate.Fragment = ""
		candidate.RawFragment = ""
		if _, ok := c.accept(candidate.String(), 0); ok {
			out = append(out, candidate.String())
		}
	}
	return out
}

// seedSiteFiles returns the addresses a site's own files are published at, in scope.
func (c *Crawler) seedSiteFiles(seed *url.URL) []string {
	return c.seedWellKnown(seed, siteFilePaths)
}

// siteFileReferences returns the addresses a robots file or a sitemap points at.
//
// The files are not pages, so nothing is extracted from them the way a page is parsed; what
// they carry is a list of addresses, and that list is what comes back.
func siteFileReferences(body []byte, base *url.URL) []string {
	if len(body) == 0 {
		return nil
	}

	if looksLikeRobots(body) {
		text := string(body)
		if len(text) > maxSitemapBytes {
			text = text[:maxSitemapBytes]
		}
		disallowed, sitemaps := parseRobots(text)
		var out []string
		// The named sitemaps first: they carry more addresses each than a Disallow line does.
		for _, sitemap := range sitemaps {
			if resolved := resolve(base, sitemap); resolved != "" {
				out = append(out, resolved)
			}
		}
		for _, path := range disallowed {
			if resolved := resolve(base, path); resolved != "" {
				out = append(out, resolved)
			}
		}
		return out
	}

	if looksLikeSitemap(body) {
		locations, indexes := parseSitemap(body)
		var out []string
		for _, index := range indexes {
			if resolved := resolve(base, index); resolved != "" {
				out = append(out, resolved)
			}
		}
		for _, location := range locations {
			if resolved := resolve(base, location); resolved != "" {
				out = append(out, resolved)
			}
		}
		return out
	}
	return nil
}

// looksLikeRobots reports whether bytes are a robots file.
func looksLikeRobots(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	head := body
	if len(head) > 8192 {
		head = head[:8192]
	}
	text := strings.ToLower(string(head))
	// A robots file is a list of directives, and one of the two that matter is always there.
	return (strings.Contains(text, "user-agent:") || strings.Contains(text, "disallow:")) &&
		!strings.Contains(text, "<html")
}

// looksLikeSitemap reports whether bytes are a sitemap or an index of them.
func looksLikeSitemap(body []byte) bool {
	if len(body) == 0 || len(body) > maxSitemapBytes {
		return false
	}
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	text := strings.ToLower(string(head))
	return strings.Contains(text, "<urlset") || strings.Contains(text, "<sitemapindex")
}

// parseRobots returns what a robots file points at: the paths it disallows, and the sitemaps
// it names.
func parseRobots(body string) (disallowed []string, sitemaps []string) {
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A comment may follow a directive on the same line.
		if index := strings.Index(line, "#"); index > 0 {
			line = strings.TrimSpace(line[:index])
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "disallow":
			if path, ok := usableRobotsPath(value); ok && !seen[path] {
				seen[path] = true
				disallowed = append(disallowed, path)
			}
		case "sitemap":
			if value != "" && !seen[value] {
				seen[value] = true
				sitemaps = append(sitemaps, value)
			}
		}
	}
	return disallowed, sitemaps
}

// usableRobotsPath reports whether a Disallow value names something worth requesting.
//
// An empty value means everything is allowed, a bare "/" means nothing is, and a value with
// * or $ in it is a pattern rather than a path. None of the three names an address; the rest
// do.
func usableRobotsPath(value string) (string, bool) {
	if value == "" || value == "/" {
		return "", false
	}
	if strings.ContainsAny(value, "*$") {
		return "", false
	}
	if !strings.HasPrefix(value, "/") {
		return "", false
	}
	return value, true
}

// sitemapDocument covers a sitemap and the index that points at more of them: the two use
// different element names for the same idea.
type sitemapDocument struct {
	Locations []sitemapEntry `xml:"url"`
	Indexes   []sitemapEntry `xml:"sitemap"`
}

type sitemapEntry struct {
	Loc string `xml:"loc"`
}

// parseSitemap returns the addresses a sitemap lists and the sitemaps it points at.
func parseSitemap(body []byte) (locations []string, indexes []string) {
	var document sitemapDocument
	if err := xml.Unmarshal(body, &document); err != nil {
		return nil, nil
	}
	for _, entry := range document.Indexes {
		if len(indexes) >= maxSitemapLocations {
			break
		}
		if entry.Loc = strings.TrimSpace(entry.Loc); entry.Loc != "" {
			indexes = append(indexes, entry.Loc)
		}
	}
	for _, entry := range document.Locations {
		if len(locations) >= maxSitemapLocations {
			break
		}
		if entry.Loc = strings.TrimSpace(entry.Loc); entry.Loc != "" {
			locations = append(locations, entry.Loc)
		}
	}
	return locations, indexes
}
