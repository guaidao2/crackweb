package crawl

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ErrNoBrowser says the headless engine cannot run, so the caller can degrade
// to the HTTP engine and tell the user how to fix it.
var ErrNoBrowser = errors.New("no Chromium-based browser found")

// observedRequest is one request a page's own script made.
//
// The URL alone is not enough to reproduce it. A script decides the method, the bytes and
// the content type, and a JSON body is not something that can be reconstructed from the
// address it was posted to — which is how a JSON API the browser used all along ends up
// never being tested.
type observedRequest struct {
	URL         string
	Method      string
	Body        []byte
	ContentType string
}

// maxObservedBody bounds the body kept from a browser request. Anything larger is an
// upload, and replaying it would cost more than the endpoint is worth.
const maxObservedBody = 256 << 10

// requestBody reassembles the bytes a request carried.
//
// The protocol hands the body over as a list of entries, each base64-encoded, so the parts
// have to be decoded and put back together before the request can be sent again. A part
// that will not decode makes the whole body unusable: a half-reconstructed request would
// test something the browser never sent.
func requestBody(request *network.Request) []byte {
	if request == nil || !request.HasPostData || len(request.PostDataEntries) == 0 {
		return nil
	}
	var body []byte
	for _, entry := range request.PostDataEntries {
		if entry == nil || entry.Bytes == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(entry.Bytes)
		if err != nil {
			return nil
		}
		if len(body)+len(decoded) > maxObservedBody {
			return nil
		}
		body = append(body, decoded...)
	}
	return body
}

// requestContentType reads the content type a request was sent with, which decides how the
// scanner reads the body.
func requestContentType(request *network.Request) string {
	if request == nil || request.Headers == nil {
		return ""
	}
	for name, value := range request.Headers {
		if !strings.EqualFold(name, "Content-Type") {
			continue
		}
		if text, ok := value.(string); ok {
			return text
		}
	}
	return ""
}

// runHeadless drives a real browser and returns the requests it observed.
//
// What the browser saw comes back whole rather than as a list of URLs, because a page's own
// script decides the method and the body: the HTTP engine can fetch an address, but it
// cannot reconstruct a JSON document to post to one. Links the page pointed at are returned
// as ordinary GETs, so following them is still the HTTP engine's job.
func (c *Crawler) runHeadless(ctx context.Context, seed string) ([]observedRequest, error) {
	execPath := c.opts.Headless.ExecPath
	if execPath == "" {
		execPath = FindChromium()
	}
	if execPath == "" {
		return nil, ErrNoBrowser
	}

	allocatorOptions := append([]chromedp.ExecAllocatorOption{},
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.ExecPath(execPath),
		// The target is usually a staging box with a self-signed certificate,
		// and a crawl that refuses to load it discovers nothing.
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if c.opts.Headless.NoSandbox || runningInContainer() {
		allocatorOptions = append(allocatorOptions, chromedp.Flag("no-sandbox", true))
	}

	allocCtx, cancelAllocator := chromedp.NewExecAllocator(ctx, allocatorOptions...)
	defer cancelAllocator()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	var (
		mu       sync.Mutex
		observed = map[string]observedRequest{}
	)

	// Every request the page makes — XHR, fetch, script loads — is a request worth having,
	// and the browser is the only thing that saw what it carried. That is the whole reason
	// to pay for one.
	chromedp.ListenTarget(browserCtx, func(event any) {
		switch e := event.(type) {
		case *network.EventRequestWillBeSent:
			if e.Request == nil || e.Request.URL == "" {
				return
			}
			item := observedRequest{
				URL:         e.Request.URL,
				Method:      e.Request.Method,
				Body:        requestBody(e.Request),
				ContentType: requestContentType(e.Request),
			}
			mu.Lock()
			// One entry per address and method: a page that polls the same endpoint keeps
			// the last body it sent, which is the one most likely to carry real input.
			observed[item.Method+" "+item.URL] = item
			mu.Unlock()
		}
	})

	loadCtx, cancelLoad := context.WithTimeout(browserCtx, c.opts.Headless.Timeout)
	defer cancelLoad()

	var links []string
	err := chromedp.Run(loadCtx,
		network.Enable(),
		chromedp.Navigate(seed),
		// Wait for the page to settle: a SPA fires its data requests shortly
		// after load, and reading the DOM too early misses them.
		chromedp.Sleep(c.opts.Headless.Settle),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a[href]')).map(function (a) { return a.href; })`, &links),
	)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// A page that fails to load entirely is not fatal: the requests it did make
	// before failing are still worth testing.
	if err != nil {
		c.opts.Logf("crawl: headless load of %s reported %v; using what was observed", seed, err)
	}

	mu.Lock()
	for _, link := range links {
		key := "GET " + link
		if _, exists := observed[key]; !exists {
			observed[key] = observedRequest{URL: link, Method: "GET"}
		}
	}
	items := make([]observedRequest, 0, len(observed))
	for _, item := range observed {
		items = append(items, item)
	}
	mu.Unlock()

	// A stable order keeps a run reproducible, and keeps two runs' logs comparable.
	sort.Slice(items, func(i, j int) bool {
		if items[i].URL != items[j].URL {
			return items[i].URL < items[j].URL
		}
		return items[i].Method < items[j].Method
	})
	return items, nil
}

// runningInContainer reports whether the process is in a container, where the
// Chromium sandbox almost always fails to start.
func runningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		text := string(data)
		return strings.Contains(text, "docker") || strings.Contains(text, "kubepods") ||
			strings.Contains(text, "containerd")
	}
	return runtime.GOOS == "linux" && os.Geteuid() == 0
}
