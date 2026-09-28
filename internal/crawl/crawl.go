// Package crawl discovers endpoints to test.
//
// crackweb's primary source of traffic is a human browsing through the proxy,
// but sometimes there is no human: a CI job, a fresh target, an API nobody has
// clicked through. The crawler fills that gap by driving the same scan engine
// that the proxy feeds.
//
// Two engines exist because neither is sufficient alone. The HTTP engine is
// fast and cheap but sees only what the server sends; a single-page application
// serves it an empty shell. The headless engine runs a real browser, so it sees
// what the user sees — at roughly five times the cost. Hybrid mode runs the
// browser first to find the application, then the HTTP engine to go deep.
package crawl

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/scope"
)

// Engines.
const (
	// EngineHTTP uses Go's HTTP client only.
	EngineHTTP = "http"
	// EngineHeadless drives a real Chromium.
	EngineHeadless = "headless"
	// EngineHybrid runs the headless engine for discovery and the HTTP engine
	// for depth.
	EngineHybrid = "hybrid"
)

// Defaults.
const (
	DefaultDepth       = 3
	DefaultMaxPages    = 500
	DefaultConcurrency = 6
)

// Options configures a crawl.
type Options struct {
	// Client fetches pages.
	Client *httpclient.Client
	// Engine selects the crawling strategy.
	Engine string
	// Depth bounds how far from the seed the crawl goes; 0 means unlimited.
	Depth int
	// MaxPages bounds how many pages are fetched.
	MaxPages int
	// Concurrency bounds simultaneous fetches.
	Concurrency int
	// Scope lists the hosts that may be crawled. Empty means "same host as the
	// seed".
	Scope []string
	// OnExchange receives every request the crawl made and the response it got,
	// which is how discovered endpoints reach the scanner.
	OnExchange func(req *httpmsg.Request, resp *httpmsg.Response)
	// OnURL is called for every URL discovered, whether or not it is fetched.
	OnURL func(rawURL string)
	// Logf receives progress messages.
	Logf func(format string, args ...any)
	// Headless configures the browser engine.
	Headless HeadlessOptions
}

// HeadlessOptions configures the browser engine.
type HeadlessOptions struct {
	// ExecPath is the Chromium binary. Empty means "find one".
	ExecPath string
	// Timeout bounds a single page load.
	Timeout time.Duration
	// Settle is how long to wait after load for late requests to fire.
	Settle time.Duration
	// NoSandbox disables the Chromium sandbox, which is needed in containers.
	NoSandbox bool
}

// Stats describes what a crawl did.
type Stats struct {
	// Pages is how many pages were fetched.
	Pages int
	// Discovered is how many URLs were found.
	Discovered int
	// Queued is how many requests were handed to the scanner.
	Queued int
	// Skipped counts URLs rejected as out of scope, duplicate or too deep.
	Skipped int
	// Elapsed is the wall-clock duration.
	Elapsed time.Duration
}

// Crawler walks a site.
type Crawler struct {
	opts  Options
	scope *scope.Scope

	mu    sync.Mutex
	seen  map[string]bool
	stats Stats
}

// New builds a crawler.
func New(opts Options) *Crawler {
	if opts.Engine == "" {
		opts.Engine = EngineHybrid
	}
	if opts.Depth == 0 {
		opts.Depth = DefaultDepth
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = DefaultMaxPages
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Headless.Settle <= 0 {
		opts.Headless.Settle = 1500 * time.Millisecond
	}
	if opts.Headless.Timeout <= 0 {
		opts.Headless.Timeout = 20 * time.Second
	}
	return &Crawler{opts: opts, seen: map[string]bool{}}
}

// Run crawls from a seed URL until the queue drains or a limit is hit.
func (c *Crawler) Run(ctx context.Context, seed string) error {
	start := time.Now()
	defer func() {
		c.mu.Lock()
		c.stats.Elapsed = time.Since(start)
		c.mu.Unlock()
	}()

	seedURL, err := url.Parse(seed)
	if err != nil {
		return fmt.Errorf("crawl: invalid seed URL %q: %w", seed, err)
	}
	if seedURL.Scheme == "" {
		seedURL.Scheme = "http"
	}

	// With no explicit scope, stay on the seed's host: wandering onto a
	// third-party domain mid-crawl is the classic way to end up testing
	// something nobody authorised.
	if c.opts.Scope == nil {
		c.scope = scope.NewScope([]string{seedURL.Hostname()})
	} else {
		c.scope = scope.NewScope(c.opts.Scope)
	}

	// The browser engine runs first in hybrid mode: it finds the endpoints a
	// static fetch cannot see, and hands them to the HTTP engine as extra seeds.
	seeds := []string{seed}
	if c.opts.Engine == EngineHeadless || c.opts.Engine == EngineHybrid {
		discovered, err := c.runHeadless(ctx, seed)
		if err != nil {
			c.opts.Logf("crawl: headless engine unavailable (%v); continuing with HTTP", err)
		} else {
			c.opts.Logf("crawl: the browser reported %d URL(s)", len(discovered))
		}
		seeds = append(seeds, discovered...)
	}

	// The browser is a discovery tool; the requests that matter are still made
	// by the HTTP engine, so that one code path produces everything the scanner
	// sees.
	depth := c.opts.Depth
	if c.opts.Engine == EngineHeadless {
		// Headless mode fetches what the browser found and stops there; asking
		// for depth is what hybrid mode is for.
		depth = 1
	}
	return c.runHTTP(ctx, seeds, depth)
}

// Stats returns a snapshot of the crawl counters.
func (c *Crawler) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// queueItem is one URL waiting to be fetched.
type queueItem struct {
	url   string
	depth int
}

// runHTTP breadth-first crawls from the given seeds, to the given depth.
func (c *Crawler) runHTTP(ctx context.Context, seeds []string, depth int) error {
	var (
		queue   []queueItem
		visited = map[string]bool{}
	)

	for _, seed := range seeds {
		if key, ok := c.accept(seed, 0); ok && !visited[key] {
			visited[key] = true
			queue = append(queue, queueItem{url: seed, depth: 0})
		}
	}

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Take a batch and fetch it concurrently.
		batch := queue
		if len(batch) > c.opts.Concurrency {
			batch = batch[:c.opts.Concurrency]
		}
		queue = queue[len(batch):]

		results := c.fetchBatch(ctx, batch)

		for _, result := range results {
			if result.err != nil {
				continue
			}
			for _, link := range result.links {
				key, ok := c.accept(link, result.depth+1)
				if !ok || visited[key] {
					continue
				}
				if depth > 0 && result.depth+1 > depth {
					continue
				}
				visited[key] = true
				queue = append(queue, queueItem{url: link, depth: result.depth + 1})
			}
		}

		if c.pageCount() >= c.opts.MaxPages {
			c.opts.Logf("crawl: reached the page limit (%d)", c.opts.MaxPages)
			break
		}
	}
	return nil
}

// fetchResult is one crawled page.
type fetchResult struct {
	depth int
	links []string
	err   error
}

// fetchBatch fetches a batch of URLs concurrently.
func (c *Crawler) fetchBatch(ctx context.Context, batch []queueItem) []fetchResult {
	results := make([]fetchResult, len(batch))
	var wg sync.WaitGroup

	for i, item := range batch {
		wg.Add(1)
		go func(index int, item queueItem) {
			defer wg.Done()
			results[index] = c.fetchOne(ctx, item)
		}(i, item)
	}
	wg.Wait()
	return results
}

// fetchOne fetches a single page and extracts what it points at.
func (c *Crawler) fetchOne(ctx context.Context, item queueItem) fetchResult {
	result := fetchResult{depth: item.depth}

	req, err := httpmsg.NewRequest("GET", item.url)
	if err != nil {
		result.err = err
		return result
	}
	req.Origin = httpmsg.OriginCrawler

	resp, err := c.opts.Client.Do(ctx, req)
	if err != nil {
		result.err = err
		return result
	}

	c.mu.Lock()
	c.stats.Pages++
	c.mu.Unlock()

	// Feed the exchange to the scanner before parsing: every page the crawl
	// touches is worth a passive look even if it yields no links.
	if c.opts.OnExchange != nil {
		c.opts.OnExchange(req, resp)
	}
	if c.opts.OnURL != nil {
		c.opts.OnURL(item.url)
	}

	base, err := url.Parse(item.url)
	if err != nil {
		return result
	}

	// Only parse HTML: there is nothing useful to extract from an image, and
	// pulling a 50MB archive into the parser would be worse than useless.
	contentType := resp.ContentType()
	if contentType != "text/html" && contentType != "application/xhtml+xml" && contentType != "" {
		return result
	}

	page, err := Parse(string(resp.Body), base)
	if err != nil {
		// A malformed page is not a crawl failure; skip it and carry on.
		return result
	}

	// Requests a form would produce are handed straight to the scanner: a form
	// is where injectable parameters live, and the crawler already knows how to
	// fill it in.
	for _, form := range page.Forms {
		c.submitForm(ctx, form, base)
	}

	result.links = append(result.links, page.Links...)
	return result
}

// submitForm turns a discovered form into the requests a user would generate.
//
// Both a GET and a POST request are produced when the page allows it: real
// applications often accept either, and the parameter is what matters for
// scanning, not the verb.
func (c *Crawler) submitForm(ctx context.Context, form Form, base *url.URL) {
	target := form.URL(base)
	if target == "" {
		return
	}
	if _, ok := c.accept(target, 0); !ok {
		return
	}

	switch strings.ToUpper(form.Method) {
	case "POST":
		req, err := httpmsg.NewRequest("POST", target)
		if err != nil {
			return
		}
		req.Origin = httpmsg.OriginCrawler
		req.Body = []byte(form.EncodeBody())
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", fmt.Sprint(len(req.Body)))
		c.deliver(ctx, req)
	default:
		req, err := httpmsg.NewRequest("GET", target+"?"+form.EncodeBody())
		if err != nil {
			return
		}
		req.Origin = httpmsg.OriginCrawler
		c.deliver(ctx, req)
	}
}

// deliver sends a synthesised request and passes the exchange on.
func (c *Crawler) deliver(ctx context.Context, req *httpmsg.Request) {
	resp, err := c.opts.Client.Do(ctx, req)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.stats.Queued++
	c.mu.Unlock()
	if c.opts.OnExchange != nil {
		c.opts.OnExchange(req, resp)
	}
}

// accept decides whether a URL is worth following, and returns its
// canonical form.
func (c *Crawler) accept(rawURL string, _ int) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	// Only http(s): mailto:, javascript: and data: are dead ends.
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if parsed.Host == "" {
		return "", false
	}
	if !c.scope.Contains(parsed.Host) {
		c.mu.Lock()
		c.stats.Skipped++
		c.mu.Unlock()
		return "", false
	}

	// Drop the fragment: /page and /page#section are the same resource, and
	// fetching both would double the crawl for nothing.
	parsed.Fragment = ""
	parsed.RawFragment = ""

	// Skip obvious non-pages; they are neither links to follow nor useful
	// responses to scan.
	lower := strings.ToLower(parsed.Path)
	for _, suffix := range []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3", ".zip", ".gz", ".pdf"} {
		if strings.HasSuffix(lower, suffix) {
			c.mu.Lock()
			c.stats.Skipped++
			c.mu.Unlock()
			return "", false
		}
	}

	key := parsed.String()
	c.mu.Lock()
	c.stats.Discovered++
	c.mu.Unlock()
	return key, true
}

// pageCount returns how many pages have been fetched.
func (c *Crawler) pageCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats.Pages
}
