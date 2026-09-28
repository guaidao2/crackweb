// Package scan turns observed traffic into vulnerability tests.
//
// It is the join between the two halves of crackweb: whatever produced a
// request — the proxy, the crawler, a pasted capture — gets handed to the
// scanner, which decides what is worth testing there, fans the work out across
// a bounded pool, and collects what comes back.
//
// Two properties matter more than throughput. First, work is deduplicated: an
// endpoint is tested once, not once per visit, or a browsing session would
// re-scan the same page hundreds of times. Second, everything is bounded: a
// scan against a large application must not open unbounded connections or
// memory.
package scan

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/sitemap"
)

// DefaultConcurrency is how many checks run at once.
const DefaultConcurrency = 8

// DefaultMaxParamsPerRequest caps how many parameters of one request are
// tested. Forms with dozens of fields would otherwise dominate a scan's cost
// for very little additional coverage.
const DefaultMaxParamsPerRequest = 20

// defaultSkipParams are parameter names that are almost never worth injecting
// into, either because they are anti-CSRF tokens that will reject the request,
// or because they are framework plumbing.
var defaultSkipParams = []string{
	"csrf_token", "csrftoken", "_csrf", "csrfmiddlewaretoken", "authenticity_token",
	"__requestverificationtoken", "xsrf_token", "_token", "nonce",
	"submit", "commit", "reset", "button",
}

// Options configures a Scanner.
type Options struct {
	// Checks are the checks to run. Empty means every registered check.
	Checks []checks.Check
	// Concurrency bounds how many checks run at once.
	Concurrency int
	// MaxParamsPerRequest caps parameters tested per request.
	MaxParamsPerRequest int
	// SkipParams adds to the built-in list of parameters not worth testing.
	SkipParams []string
	// PassiveOnly runs only the checks that do not send traffic. It is what
	// makes a proxy session safe to point at production.
	PassiveOnly bool
	// Bundle renders messages in the user's language.
	Bundle *i18n.Bundle
	// OnFinding is called as each finding is confirmed, for live output.
	OnFinding func(*finding.Finding)
	// Logf receives progress messages.
	Logf func(format string, args ...any)
	// OOB is the out-of-band interaction server, if one is running.
	OOB checks.OOBProvider
}

// Stats summarises a scan.
type Stats struct {
	// Endpoints is how many unique endpoints were queued.
	Endpoints int
	// Tasks is how many (check, parameter) pairs ran.
	Tasks int
	// Skipped counts submissions rejected as duplicates or out of scope.
	Skipped int
	// Findings is how many findings were collected.
	Findings int
	// Requests is how many HTTP requests the checks sent.
	Requests int
	// Failures is how many of those never produced a response.
	Failures int
	// Elapsed is the wall-clock duration.
	Elapsed time.Duration
}

// Scanner runs checks over submitted requests.
type Scanner struct {
	opts Options

	passive     []checks.Check
	active      []checks.Check
	requestWide []checks.Check
	skip        map[string]bool

	ctx    context.Context
	cancel context.CancelFunc
	pool   chan struct{}
	wg     sync.WaitGroup

	mu           sync.Mutex
	seen         map[string]bool
	findings     []*finding.Finding
	stats        Stats
	checkCtx     *checks.Context
	started      time.Time
	interactions int
}

// New builds a scanner. The check context supplies the HTTP client, the
// normalizer and the out-of-band server to every check.
func New(opts Options, checkCtx *checks.Context) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.MaxParamsPerRequest <= 0 {
		opts.MaxParamsPerRequest = DefaultMaxParamsPerRequest
	}
	if opts.Bundle == nil {
		opts.Bundle = i18n.New(i18n.Default)
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}

	selected := opts.Checks
	if len(selected) == 0 {
		selected = checks.All()
	}

	s := &Scanner{
		opts:     opts,
		skip:     map[string]bool{},
		pool:     make(chan struct{}, opts.Concurrency),
		seen:     map[string]bool{},
		checkCtx: checkCtx,
		started:  time.Now(),
	}
	for _, name := range defaultSkipParams {
		s.skip[name] = true
	}
	for _, name := range opts.SkipParams {
		s.skip[strings.ToLower(strings.TrimSpace(name))] = true
	}
	for _, c := range selected {
		if c.Passive() {
			s.passive = append(s.passive, c)
			continue
		}
		if opts.PassiveOnly {
			continue
		}
		if checks.IsRequestLevel(c) {
			s.requestWide = append(s.requestWide, c)
			continue
		}
		s.active = append(s.active, c)
	}
	return s
}

// Start prepares the scanner for a run.
func (s *Scanner) Start(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = time.Now()
}

// Wait blocks until every dispatched check has finished, without cancelling
// anything. It is what a one-shot scan uses: dispatch the work, then wait.
func (s *Scanner) Wait() { s.wg.Wait() }

// Stop cancels in-flight work and then waits for it to finish.
func (s *Scanner) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

// Interactions reports how many out-of-band callbacks have been observed, for
// progress output.
func (s *Scanner) Interactions() int { return s.interactions }

// PassiveCount and ActiveCount report how many checks of each kind are loaded.
// ActiveCount includes request-level checks, since both send traffic.
func (s *Scanner) PassiveCount() int { return len(s.passive) }
func (s *Scanner) ActiveCount() int  { return len(s.active) + len(s.requestWide) }

// Submit queues an observed request for testing.
//
// A request with no parameters still gets the passive checks, which is why the
// proxy becomes useful the moment it starts: the user's own browsing is enough
// to produce findings.
func (s *Scanner) Submit(req *httpmsg.Request, resp *httpmsg.Response) {
	if req == nil || s.ctx == nil {
		return
	}

	key := sitemap.Key(req)
	s.mu.Lock()
	if s.seen[key] {
		s.stats.Skipped++
		s.mu.Unlock()
		return
	}
	s.seen[key] = true
	s.stats.Endpoints++
	s.mu.Unlock()

	target := &checks.Target{Request: req, Response: resp}
	for _, c := range s.passive {
		s.dispatch(c, target)
	}

	if resp == nil {
		return
	}

	// Request-level checks run once for the request itself — templates, and any
	// check whose subject is the URL rather than a parameter.
	for _, c := range s.requestWide {
		s.dispatch(c, target)
	}

	if len(s.active) == 0 {
		return
	}

	params := req.Params()
	if len(params) > s.opts.MaxParamsPerRequest {
		params = params[:s.opts.MaxParamsPerRequest]
	}
	for i := range params {
		param := params[i]
		if s.skip[strings.ToLower(param.Name)] {
			continue
		}
		specific := &checks.Target{Request: req, Response: resp, Param: &param}
		for _, c := range s.active {
			s.dispatch(c, specific)
		}
	}
}

// dispatch runs one check against one target, under the concurrency limit.
func (s *Scanner) dispatch(check checks.Check, target *checks.Target) {
	select {
	case <-s.ctx.Done():
		return
	default:
	}

	s.mu.Lock()
	s.stats.Tasks++
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		select {
		case s.pool <- struct{}{}:
			defer func() { <-s.pool }()
		case <-s.ctx.Done():
			return
		}

		results := s.safeRun(check, target)
		if len(results) == 0 {
			return
		}

		s.mu.Lock()
		for _, f := range results {
			f.FoundAt = time.Now()
			f.ComputeID()
			s.findings = append(s.findings, f)
		}
		s.mu.Unlock()

		if s.opts.OnFinding != nil {
			for _, f := range results {
				s.opts.OnFinding(f)
			}
		}
	}()
}

// safeRun calls a check, turning a panic into a skipped check rather than a
// crashed scan. A scanner that dies on one malformed response is worse than one
// that misses a check.
func (s *Scanner) safeRun(check checks.Check, target *checks.Target) (results []*finding.Finding) {
	defer func() {
		if r := recover(); r != nil {
			s.opts.Logf("check %s panicked on %s: %v", check.ID(), target.Request.URLString(), r)
			results = nil
		}
	}()
	return check.Run(s.ctx, s.checkCtx, target)
}

// Findings returns the deduplicated findings, most severe first.
func (s *Scanner) Findings() []*finding.Finding {
	s.mu.Lock()
	collected := make([]*finding.Finding, len(s.findings))
	copy(collected, s.findings)
	s.mu.Unlock()

	deduped := finding.Dedup(collected)
	finding.Sort(deduped)
	return deduped
}

// Stats returns a snapshot of the run's counters.
func (s *Scanner) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.stats
	stats.Findings = len(s.findings)
	stats.Elapsed = time.Since(s.started)
	if s.checkCtx != nil {
		stats.Requests = s.checkCtx.RequestCount()
		stats.Failures = s.checkCtx.FailureCount()
	}
	return stats
}

// Summary describes what a scan covered, for a report.
type Summary struct {
	// Hosts is the distinct hosts that were tested.
	Hosts []string
	// Endpoints is the number of unique endpoints queued.
	Endpoints int
	// Stats is the run's counters.
	Stats Stats
	// Started is when the scan began.
	Started time.Time
	// Finished is when it ended.
	Finished time.Time
}

// Summary builds a run summary from the store the scan drew from.
func (s *Scanner) Summary(store *sitemap.Store) Summary {
	summary := Summary{
		Started:   s.started,
		Finished:  time.Now(),
		Stats:     s.Stats(),
		Endpoints: s.Stats().Endpoints,
	}
	if store != nil {
		summary.Hosts = store.Hosts()
	}
	sort.Strings(summary.Hosts)
	return summary
}
