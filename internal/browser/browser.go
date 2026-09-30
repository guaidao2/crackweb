// Package browser drives a real browser for the one question a response cannot answer:
// what a page's own script does with a value once it is in the document.
//
// Everything else crackweb decides can be decided from bytes on the wire. This cannot. A
// page that writes a URL value into the document as markup returns exactly the same
// response as one that escapes it first, and the difference appears only when a browser
// runs the script and acts on the result. So the check plants markup whose only effect is
// to exist under a name it chose, and then asks the browser whether that element is there.
package browser

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// Defaults for a probe. The settle is how long the page is given to finish with the value
// after load: a script that puts the fragment into the document usually does it on
// DOMContentLoaded, but a single-page application may take a moment longer.
const (
	DefaultTimeout = 25 * time.Second
	DefaultSettle  = 900 * time.Millisecond
)

// Probe is a browser kept alive across probes, so each one costs a tab rather than a
// process. It is safe for concurrent use, and serialises internally: one browser with one
// page at a time is what the concurrency limit exists to protect.
//
// The browser itself is started on the first probe rather than at construction. A scan
// that never asks a DOM question should not pay for a browser process, and loading a page
// in one is expensive enough that the caller wants that decision to cost nothing.
type Probe struct {
	parent   context.Context
	execPath string
	timeout  time.Duration
	settle   time.Duration

	mu       sync.Mutex
	allocCtx context.Context
	cancel   context.CancelFunc
}

// New describes the browser a probe will drive. The parent context bounds its lifetime:
// cancelling it, or calling Close, shuts the browser down.
func New(parent context.Context, execPath string, timeout, settle time.Duration) *Probe {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if settle <= 0 {
		settle = DefaultSettle
	}
	return &Probe{parent: parent, execPath: execPath, timeout: timeout, settle: settle}
}

// browser returns the allocator context, starting the browser on first use.
func (p *Probe) browser() (context.Context, error) {
	if p.allocCtx != nil {
		return p.allocCtx, nil
	}
	if p.parent == nil || p.parent.Err() != nil {
		return nil, errors.New("browser: the probe's context is done")
	}

	options := append([]chromedp.ExecAllocatorOption{},
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.ExecPath(p.execPath),
		// A target is routinely a staging box with a self-signed certificate, and a probe
		// that refuses to load it reports nothing.
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	if runningInContainer() {
		options = append(options, chromedp.Flag("no-sandbox", true))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(p.parent, options...)
	p.allocCtx, p.cancel = allocCtx, cancel
	return allocCtx, nil
}

// Close shuts the browser down.
func (p *Probe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
		p.allocCtx = nil
	}
	return nil
}

// Probe loads a target and reports whether an element named by the marker ended up in the
// document.
//
// The element is what the planted markup creates. Its presence means the page handed the
// value to something that parses markup — innerHTML, document.write, a framework's
// rendering — rather than displaying it as text, which is the whole of the flaw.
func (p *Probe) Probe(ctx context.Context, target, marker string) (bool, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if marker == "" {
		return false, "", errors.New("browser: probe needs a marker")
	}
	allocCtx, err := p.browser()
	if err != nil {
		return false, "", err
	}

	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	defer cancelTab()

	loadCtx, cancelLoad := context.WithTimeout(tabCtx, p.timeout)
	defer cancelLoad()

	// A load that reports an error may still have run the script that matters — a page
	// whose subresources failed is not a page that did nothing — so the element is looked
	// for either way.
	_ = chromedp.Run(loadCtx,
		chromedp.Navigate(target),
		chromedp.Sleep(p.settle),
	)

	var detail string
	err = chromedp.Run(loadCtx, chromedp.Evaluate(
		`(function () {
			var found = document.getElementById(`+jsString(marker)+`);
			if (!found) { return ""; }
			var parent = found.parentElement;
			return (parent ? "<" + parent.tagName.toLowerCase() + "> " : "") + found.outerHTML.slice(0, 200);
		})()`, &detail))
	if err != nil {
		return false, "", err
	}
	if detail == "" {
		return false, "", nil
	}
	return true, detail, nil
}

// jsString renders a value as a JavaScript string literal. The marker is generated, not
// received, but a probe that interpolates into script without quoting is the very mistake
// it is testing for.
// Eval loads a target and returns the value of a JavaScript expression in that page.
//
// Like Probe, a load that reports an error may still have run the script that matters, so
// the expression is evaluated either way. The result is rendered with fmt.Sprint because an
// expression is free to answer with a number, a boolean or nothing at all.
func (p *Probe) Eval(ctx context.Context, target, expression string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if expression == "" {
		return "", errors.New("browser: eval needs an expression")
	}
	allocCtx, err := p.browser()
	if err != nil {
		return "", err
	}

	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	defer cancelTab()

	loadCtx, cancelLoad := context.WithTimeout(tabCtx, p.timeout)
	defer cancelLoad()

	_ = chromedp.Run(loadCtx,
		chromedp.Navigate(target),
		chromedp.Sleep(p.settle),
	)

	var raw any
	if err := chromedp.Run(loadCtx, chromedp.Evaluate(expression, &raw)); err != nil {
		return "", err
	}
	if raw == nil {
		return "", nil
	}
	return fmt.Sprint(raw), nil
}

func jsString(value string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\'', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// runningInContainer reports whether the process is in a container, where the Chromium
// sandbox almost always fails to start.
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
