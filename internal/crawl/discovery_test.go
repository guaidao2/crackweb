package crawl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/httpclient"
)

// discoveryCrawler builds a crawler that will actually fetch.
func discoveryCrawler(t *testing.T, opts Options) *Crawler {
	t.Helper()
	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	opts.Client = client
	opts.Engine = EngineHTTP
	return New(opts)
}

// discoveryServer answers a robots file and a description, and records what was asked for.
func discoveryServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		mu    sync.Mutex
		asked []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\n")
		case "/swagger.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{"/thing":{"get":{}}}}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html><body>a page</body></html>")
		}
	}))
	t.Cleanup(server.Close)

	return server, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func TestDiscoveryAsksForSiteFilesAndCountsWhatAnswered(t *testing.T) {
	server, asked := discoveryServer(t)

	c := discoveryCrawler(t, Options{MaxPages: 20})
	if err := c.Run(t.Context(), server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stats := c.Stats()
	if stats.SiteFiles != 1 {
		t.Errorf("SiteFiles = %d, want 1", stats.SiteFiles)
	}
	if stats.Descriptions != 1 || stats.Operations != 1 {
		t.Errorf("Descriptions/Operations = %d/%d, want 1/1", stats.Descriptions, stats.Operations)
	}

	seen := map[string]bool{}
	for _, path := range asked() {
		seen[path] = true
	}
	for _, want := range []string{"/robots.txt", "/swagger.json", "/admin/"} {
		if !seen[want] {
			t.Errorf("%s was never asked for, so the files it came from were not read: %v",
				want, asked())
		}
	}
}

// TestNoDiscoveryAsksForNothingElse is what the flag is for: a target where even one address
// the user did not name is one too many.
func TestNoDiscoveryAsksForNothingElse(t *testing.T) {
	server, asked := discoveryServer(t)

	c := discoveryCrawler(t, Options{MaxPages: 20, NoDiscovery: true})
	if err := c.Run(t.Context(), server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, path := range asked() {
		if path != "/" {
			t.Errorf("asked for %s with discovery turned off (everything asked for: %v)", path, asked())
		}
	}
	if stats := c.Stats(); stats.SiteFiles != 0 || stats.Descriptions != 0 {
		t.Errorf("discovery counts = %d/%d, want 0/0", stats.Descriptions, stats.SiteFiles)
	}
}

// TestDiscoveryDoesNotSpendThePageBudget: the guesses are not pages, and a crawl limited to
// a handful of them should still be allowed to ask whether the site publishes anything.
func TestDiscoveryDoesNotSpendThePageBudget(t *testing.T) {
	server, _ := discoveryServer(t)

	c := discoveryCrawler(t, Options{MaxPages: 2})
	if err := c.Run(t.Context(), server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if stats := c.Stats(); stats.SiteFiles != 1 || stats.Descriptions != 1 {
		t.Errorf("a two-page budget spent itself on the guesses: %d site file(s), %d description(s)",
			stats.SiteFiles, stats.Descriptions)
	}
}
