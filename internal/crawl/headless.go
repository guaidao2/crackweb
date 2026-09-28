package crawl

import (
	"context"
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

// runHeadless drives a real browser and returns every URL it observed.
//
// The browser is used for discovery only: the endpoints it finds are handed to
// the HTTP engine, which fetches and scans them. That keeps one code path for
// the actual testing, and means the browser's own traffic never bypasses the
// scanner.
func (c *Crawler) runHeadless(ctx context.Context, seed string) ([]string, error) {
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
		mu         sync.Mutex
		discovered = map[string]bool{}
	)

	// Every request the page makes — XHR, fetch, script loads — is an endpoint
	// the HTTP engine can then test. This is the whole reason to pay for a
	// browser.
	chromedp.ListenTarget(browserCtx, func(event any) {
		switch e := event.(type) {
		case *network.EventRequestWillBeSent:
			if e.Request == nil {
				return
			}
			mu.Lock()
			discovered[e.Request.URL] = true
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
	for observed := range discovered {
		links = append(links, observed)
	}
	mu.Unlock()

	return dedupe(links), nil
}

// dedupe removes duplicates and sorts, so the URL list is reproducible.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
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
