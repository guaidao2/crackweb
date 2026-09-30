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
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/apidoc"
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
	// NoDiscovery turns off asking a site for the files it publishes about itself — an API
	// description, robots.txt, a sitemap. It exists for a target where even one address the
	// user did not name is one too many.
	NoDiscovery bool
	// APIDocPaths are extra addresses to ask for an API description at, on top of the
	// common ones. Plenty of sites publish a description under a name of their own, and
	// guessing it is not something a crawler can do.
	APIDocPaths []string
	// AllowStateChange lets the crawler queue the endpoints a page calls with POST, PUT,
	// PATCH or DELETE. They are left out by default: the crawler fetches addresses with
	// GET, and a request to an endpoint the page's own script only calls to delete
	// something is not obviously harmless to whatever is behind it.
	AllowStateChange bool
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
	// Descriptions is how many API descriptions were read, and Operations how many
	// operations they listed between them.
	Descriptions int
	Operations   int
	// SiteFiles is how many robots files and sitemaps answered.
	SiteFiles int
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

	// jar is the session the crawl builds as it goes: what the server hands out is
	// carried on later requests, the way a browser would carry it. Without it a site that
	// sets a cookie and then expects it back is only reachable on the very first request,
	// which is exactly the shape of an application whose parameters travel in a cookie.
	//
	// It lives here rather than in the HTTP client on purpose. The client is shared with
	// the checks, and a check that removes an identity to see what an anonymous visitor
	// gets must actually arrive anonymous — a cookie store underneath it would quietly
	// put the identity back.
	jar http.CookieJar

	mu    sync.Mutex
	seen  map[string]bool
	stats Stats
}

// applyCookies carries the session so far onto a request that does not already name its
// own cookies.
func (c *Crawler) applyCookies(req *httpmsg.Request) {
	if c.jar == nil || req == nil || req.URL == nil || req.Header.Has("Cookie") {
		return
	}
	cookies := c.jar.Cookies(req.URL)
	if len(cookies) == 0 {
		return
	}
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
}

// rememberCookies records what the server set, so later requests carry it.
func (c *Crawler) rememberCookies(req *httpmsg.Request, resp *httpmsg.Response) {
	if c.jar == nil || req == nil || req.URL == nil || resp == nil {
		return
	}
	values := resp.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	header := http.Header{}
	for _, value := range values {
		header.Add("Set-Cookie", value)
	}
	c.jar.SetCookies(req.URL, (&http.Response{Header: header}).Cookies())
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
	jar, _ := cookiejar.New(nil)
	return &Crawler{opts: opts, jar: jar, seen: map[string]bool{}}
}

// maxReplayBody bounds the body replayed from a browser request. Anything larger is an
// upload, and sending it again costs more than the endpoint is worth.
const maxReplayBody = 256 << 10

// replayObserved sends back the requests the browser made that the HTTP engine could not
// have produced on its own.
//
// The crawler's rule is that the HTTP engine makes every request the scanner sees, so that
// one code path produces them all. A request with a body is what the rule cannot cover: the
// page's own script chose the method, the bytes and the content type, and none of that can
// be reconstructed from the address it went to. Fetching that address as a GET misses the
// endpoint entirely, which is how a JSON API the browser talked to all along ends up
// untested. So the request is sent again exactly as it went out.
func (c *Crawler) replayObserved(ctx context.Context, observed []observedRequest) int {
	replayed := 0
	seen := map[string]bool{}

	for _, item := range observed {
		if !item.worthReplaying() {
			continue
		}
		key := item.Method + " " + item.URL + " " + string(item.Body)
		if seen[key] {
			continue
		}
		if _, ok := c.accept(item.URL, 0); !ok {
			continue
		}
		seen[key] = true

		req, err := httpmsg.NewRequest(item.Method, item.URL)
		if err != nil {
			continue
		}
		req.Origin = httpmsg.OriginCrawler
		req.Body = item.Body
		req.Header.Set("Content-Length", fmt.Sprint(len(item.Body)))
		if item.ContentType != "" {
			req.Header.Set("Content-Type", item.ContentType)
		}
		c.deliver(ctx, req)
		replayed++
	}
	return replayed
}

// worthReplaying reports whether a request the browser made is one the HTTP engine would
// not produce.
//
// Only a request that carries a body qualifies. A GET is something the HTTP engine fetches
// itself, and a bodyless POST — a logout, a "mark all as read" — has no parameter to test
// while sending it again does have an effect. Repeating a write is an unavoidable
// consequence of crawling a live application; the cost is best spent on requests that carry
// something worth testing.
func (o observedRequest) worthReplaying() bool {
	if len(o.Body) == 0 || len(o.Body) > maxReplayBody {
		return false
	}
	switch strings.ToUpper(o.Method) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
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

	// A site's own files are asked for first. They cost one request each, and they hand over
	// endpoints that no amount of following links would reach — and they are asked for
	// outside the page budget, so a small --max-pages does not spend itself on the guesses.
	seeds := []queueItem{{url: seed}}
	if !c.opts.NoDiscovery {
		for _, address := range c.seedAPIDocsAt(seedURL, c.opts.APIDocPaths) {
			seeds = append(seeds, queueItem{url: address, discovery: true})
		}
		for _, address := range c.seedSiteFiles(seedURL) {
			seeds = append(seeds, queueItem{url: address, discovery: true})
		}
	}
	if c.opts.Engine == EngineHeadless || c.opts.Engine == EngineHybrid {
		observed, err := c.runHeadless(ctx, seed)
		if err != nil {
			c.opts.Logf("crawl: headless engine unavailable (%v); continuing with HTTP", err)
		} else {
			replayed := c.replayObserved(ctx, observed)
			c.opts.Logf("crawl: the browser reported %d request(s), replayed %d",
				len(observed), replayed)
			for _, item := range observed {
				seeds = append(seeds, queueItem{url: item.URL})
			}
		}
	}

	// Everything the browser merely linked to is fetched by the HTTP engine, so one code
	// path still produces most of what the scanner sees. A request carrying a body is the
	// exception that path cannot cover — see replayObserved.
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
	// discovery marks a request that asks a site about itself rather than crawling one of
	// its pages: a description, a robots file, a sitemap. It is kept out of the page budget,
	// because a crawl limited to five pages should still be allowed to ask whether the site
	// publishes any of them.
	discovery bool
}

// runHTTP breadth-first crawls from the given seeds, to the given depth.
func (c *Crawler) runHTTP(ctx context.Context, seeds []queueItem, depth int) error {
	var (
		queue   []queueItem
		visited = map[string]bool{}
	)

	for _, seed := range seeds {
		if key, ok := c.accept(seed.url, 0); ok && !visited[key] {
			visited[key] = true
			queue = append(queue, seed)
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
	c.applyCookies(req)

	resp, err := c.opts.Client.Do(ctx, req)
	if err != nil {
		result.err = err
		return result
	}
	c.rememberCookies(req, resp)

	if !item.discovery {
		c.mu.Lock()
		c.stats.Pages++
		c.mu.Unlock()
	}

	// Feed the exchange to the scanner before parsing: every page the crawl touches is worth a
	// passive look even if it yields no links.
	//
	// A discovery request is the exception, and only when it came back empty. It asks the site
	// about itself — a description, a robots file, a sitemap — and the usual answer is that
	// there is no such file. Handing that 404 to the checks runs every probe in the tool
	// against the same absence, once per guessed address, which is where a crawl of four
	// endpoints spends most of its requests. A description that exists is a page, and is
	// scanned as one.
	worthScanning := !item.discovery || resp.Status < 400
	if worthScanning && c.opts.OnExchange != nil {
		c.opts.OnExchange(req, resp)
	}
	if worthScanning && c.opts.OnURL != nil {
		c.opts.OnURL(item.url)
	}

	base, err := url.Parse(item.url)
	if err != nil {
		return result
	}

	// A redirect target is a page worth following: that is how the crawl reaches what a
	// browser reaches, including a URL that only answers once the cookie the redirect set
	// comes back with it. Without this the crawl stops at the 302 and never sees the page
	// behind it.
	if resp.IsRedirect() {
		if location := resp.Header.Get("Location"); location != "" {
			if resolved := resolve(base, location); resolved != "" {
				result.links = append(result.links, resolved)
			}
		}
	}

	// Only parse HTML: there is nothing useful to extract from an image, and
	// pulling a 50MB archive into the parser would be worse than useless.
	// The files a site publishes about itself: a sitemap lists what it wants found, and a
	// robots file lists what it would rather nobody looked at — which is where the
	// interesting addresses usually turn out to be.
	if references := siteFileReferences(resp.Body, base); len(references) > 0 {
		c.mu.Lock()
		c.stats.SiteFiles++
		c.mu.Unlock()
		c.opts.Logf("crawl: %s points at %d address(es)", item.url, len(references))
		result.links = append(result.links, references...)
		return result
	}

	// A description is worth more than any page — it lists the operations nothing links to —
	// so it is parsed and its operations handed to the scanner instead of being looked
	// through for links.
	if apidoc.LooksLikeDocument(resp.Body) {
		if doc, ok := apidoc.Parse(resp.Body, base); ok {
			c.mu.Lock()
			c.stats.Descriptions++
			c.stats.Operations += len(doc.Requests)
			c.mu.Unlock()
			delivered := c.deliverDocument(ctx, doc)
			c.opts.Logf("crawl: %s describes %d operation(s), %d in scope",
				item.url, len(doc.Requests), delivered)
			return result
		}
	}

	contentType := resp.ContentType()
	if contentType != "text/html" && contentType != "application/xhtml+xml" && contentType != "" {
		return result
	}

	page, err := Parse(string(resp.Body), base, c.opts.AllowStateChange)
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
	// A page's script names endpoints that no link points at, and the browser issues none
	// of them while the page loads. They are worth queueing: this is how a search or delete
	// handler — the place an injectable parameter usually lives — becomes reachable.
	//
	// A read becomes a link. A write cannot: the crawler follows a link with GET, and an
	// upload endpoint reached with GET has nothing to say. Those are replayed with the
	// method and body the script uses, so the checks that care about the shape of the
	// request — the upload check above all — see the endpoint at all.
	for _, call := range scriptCalls(string(resp.Body), base, c.opts.AllowStateChange) {
		if safeMethods[call.Method] {
			result.links = append(result.links, call.URL)
			continue
		}
		c.replayScriptCall(ctx, call)
	}
	// A page that carries a Swagger UI names the description it reads, and that name is how a
	// description kept somewhere other than the common addresses is found.
	result.links = append(result.links, apiDocReferences(string(resp.Body), base)...)
	return result
}

// submitForm turns a discovered form into the requests a user would generate.
//
// Both a GET and a POST request are produced when the page allows it: real
// applications often accept either, and the parameter is what matters for
// scanning, not the verb.
func (c *Crawler) submitForm(ctx context.Context, form Form, base *url.URL) {
	for _, req := range FormRequests(form, base) {
		if _, ok := c.accept(req.URLString(), 0); !ok {
			continue
		}
		c.deliver(ctx, req)
	}
}

// FormRequests turns a discovered form into the requests a user would generate.
//
// The verb the form declares is the verb used, and the encoding it declares decides the body:
// a form carrying a file input has to be sent as multipart, because one sent as a urlencoded
// body is refused by the upload endpoint before it looks at a single field — which is how an
// upload form ends up looking like a form with nothing to test.
//
// This is exported because scanning a single URL needs exactly what crawling does: a page that
// declares a form is only testable through the request that form produces, and a one-shot scan
// never gets there by itself.
func FormRequests(form Form, base *url.URL) []*httpmsg.Request {
	target := form.URL(base)
	if target == "" {
		return nil
	}

	switch strings.ToUpper(form.Method) {
	case "POST":
		req, err := httpmsg.NewRequest("POST", target)
		if err != nil {
			return nil
		}
		req.Origin = httpmsg.OriginCrawler
		if form.IsMultipart() {
			body, contentType := form.EncodeMultipart()
			req.Body = body
			req.Header.Set("Content-Type", contentType)
		} else {
			req.Body = []byte(form.EncodeBody())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("Content-Length", fmt.Sprint(len(req.Body)))
		return []*httpmsg.Request{req}
	default:
		req, err := httpmsg.NewRequest("GET", target+"?"+form.EncodeBody())
		if err != nil {
			return nil
		}
		req.Origin = httpmsg.OriginCrawler
		return []*httpmsg.Request{req}
	}
}

// deliver sends a synthesised request and passes the exchange on. The crawl's session is
// applied here, so a request a form produced travels with the same cookies as the page
// the form was found on.
func (c *Crawler) deliver(ctx context.Context, req *httpmsg.Request) {
	c.applyCookies(req)
	resp, err := c.opts.Client.Do(ctx, req)
	if err != nil {
		return
	}
	c.rememberCookies(req, resp)
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
