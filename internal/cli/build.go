package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/browser"
	"github.com/guaidao2/crackweb/internal/ca"
	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/crawl"
	// Importing the check packages for their side effect populates the
	// registry; without these the scan would run zero checks.
	_ "github.com/guaidao2/crackweb/internal/checks/active"
	_ "github.com/guaidao2/crackweb/internal/checks/passive"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/oob"
	"github.com/guaidao2/crackweb/internal/report"
	"github.com/guaidao2/crackweb/internal/scan"
	"github.com/guaidao2/crackweb/internal/sitemap"
	"github.com/guaidao2/crackweb/internal/template"
	"github.com/guaidao2/crackweb/internal/waf"
)

// requestOptions are the flags that control how crackweb talks to a target.
// They are shared by proxy, crawl and scan so that all three behave, and read,
// the same way.
type requestOptions struct {
	timeout      *time.Duration
	rate         *float64
	threads      *int
	insecure     *bool
	userAgent    *string
	proxy        *string
	sensitivity  *int
	skipParams   *[]string
	noNormalize  *bool
	verbose      *bool
	templates    *[]string
	sessions     *[]string
	noWAF        *bool
	noAssumeWAF  *bool
	unsafeChecks *bool
	cookies      *[]string
	headers      *[]string
	basicAuth    *string
	randomUA     *bool
}

// addRequestFlags registers the shared request options on a command.
func addRequestFlags(fs *FlagSet) *requestOptions {
	return &requestOptions{
		timeout:      fs.Duration("timeout", "", 10*time.Second, "<dur>", i18n.KeyFlagTimeout),
		rate:         fs.Float("rate", "", 0, "<n>", i18n.KeyFlagRate),
		threads:      fs.Int("threads", "t", 8, "<n>", i18n.KeyFlagThreads),
		insecure:     fs.Bool("insecure", "k", i18n.KeyFlagInsecure),
		userAgent:    fs.String("user-agent", "A", "", "<ua>", i18n.KeyFlagUserAgent),
		proxy:        fs.String("proxy", "", "", "<url>", i18n.KeyFlagProxy),
		sensitivity:  fs.Int("sensitivity", "s", 3, "<1-5>", i18n.KeyFlagSensitivity),
		skipParams:   fs.StringSlice("skip-param", "", "<name>", i18n.KeyFlagSkipParams),
		noNormalize:  fs.Bool("no-normalize", "", i18n.KeyFlagNoNormalize),
		verbose:      fs.Bool("verbose", "v", i18n.KeyFlagVerbose),
		templates:    fs.StringSlice("templates", "", "<dir>", i18n.KeyFlagTemplates),
		sessions:     fs.StringSlice("session", "", "<header>", i18n.KeyFlagSession),
		noWAF:        fs.Bool("no-waf", "", i18n.KeyFlagNoWAF),
		noAssumeWAF:  fs.Bool("no-assume-waf", "", i18n.KeyFlagNoAssumeWAF),
		cookies:      fs.StringSlice("cookie", "C", "<k=v; k2=v2>", i18n.KeyFlagCookie),
		headers:      fs.StringSlice("header", "H", "<name: value>", i18n.KeyFlagHeader),
		basicAuth:    fs.String("basic-auth", "", "", "<user:pass>", i18n.KeyFlagBasicAuth),
		randomUA:     fs.Bool("random-ua", "", i18n.KeyFlagRandomUA),
		unsafeChecks: fs.Bool("enable-unsafe-checks", "", i18n.KeyFlagUnsafeChecks),
	}
}

// thresholds turns the sensitivity flag into diff thresholds.
func (o *requestOptions) thresholds() (diff.Thresholds, error) {
	level := *o.sensitivity
	if level < 1 || level > 5 {
		return diff.Thresholds{}, errors.New("sensitivity out of range")
	}
	return diff.ThresholdsForSensitivity(level), nil
}

// client builds the HTTP client the checks will use.
func (o *requestOptions) client() (*httpclient.Client, error) {
	credentials, err := o.credentials()
	if err != nil {
		return nil, err
	}
	return httpclient.New(httpclient.Options{
		Timeout:      *o.timeout,
		Proxy:        *o.proxy,
		Insecure:     *o.insecure,
		UserAgent:    *o.userAgent,
		Rate:         *o.rate,
		MaxRedirects: 10,
		Credentials:  credentials,
		RandomUA:     *o.randomUA,
	})
}

// credentials turns the identity flags into the headers every request carries.
//
// Three spellings for one idea, because they are not interchangeable in
// practice: a cookie is what a browser session gives you, Basic is what a
// staging environment in front of the app asks for, and a bare header covers
// everything else — bearer tokens, API keys, an X-Forwarded-For the deployment
// expects. Requiring the user to hand-encode any of those into one of the others
// would just be a way to get it wrong.
func (o *requestOptions) credentials() ([]httpclient.Credential, error) {
	var creds []httpclient.Credential

	for _, raw := range *o.cookies {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		// A cookie value pasted from a browser may arrive with the header name
		// still attached, which is the single most common way to get this wrong.
		value = strings.TrimPrefix(value, "Cookie:")
		value = strings.TrimPrefix(value, "cookie:")
		creds = append(creds, httpclient.Credential{Name: "Cookie", Value: strings.TrimSpace(value)})
	}

	for _, raw := range *o.headers {
		// A blank value is skipped rather than rejected: an argument like
		// --header "$EXTRA" expands to nothing when the variable is unset, and
		// failing on that would break scripts for no reason. A non-empty value
		// that is not a header is still an error, because guessing there would
		// scan under the wrong identity.
		if strings.TrimSpace(raw) == "" {
			continue
		}
		name, value, found := strings.Cut(raw, ":")
		if !found {
			return nil, &UsageError{msg: fmt.Sprintf("malformed --header %q: expected %q", raw, "Name: value")}
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, &UsageError{msg: "malformed --header: the name is empty"}
		}
		creds = append(creds, httpclient.Credential{Name: name, Value: strings.TrimSpace(value)})
	}

	if raw := strings.TrimSpace(*o.basicAuth); raw != "" {
		user, pass, found := strings.Cut(raw, ":")
		if !found {
			return nil, &UsageError{msg: fmt.Sprintf("malformed --basic-auth: expected %q", "user:password")}
		}
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		creds = append(creds, httpclient.Credential{Name: "Authorization", Value: "Basic " + token})
	}

	return creds, nil
}

// normalizer builds the response normaliser.
func (o *requestOptions) normalizer() (*diff.Normalizer, error) {
	return diff.New(diff.Options{Off: *o.noNormalize})
}

// scanContext assembles everything a scan needs: the response normaliser, the
// difference engine and the scanner that drives the checks. The HTTP client is
// passed in so that the reference used to load templates and the one the checks
// use are the same object, sharing its connection pool and rate limiter.
func (o *requestOptions) scanContext(ctx context.Context, app *App, client *httpclient.Client, oobServer *oob.Server, selected []checks.Check, passiveOnly bool) (*checks.Context, *scan.Scanner, error) {
	thresholds, err := o.thresholds()
	if err != nil {
		return nil, nil, &UsageError{msg: app.T(i18n.KeyErrBadSensitivity)}
	}
	normalizer, err := o.normalizer()
	if err != nil {
		return nil, nil, err
	}

	var provider checks.OOBProvider
	if oobServer != nil {
		provider = oobServer
	}

	engine := diff.NewEngine(thresholds, diff.DefaultKeywords())
	checkCtx := checks.NewContext(client, app.Bundle, engine, normalizer)
	checkCtx.OOB = provider
	// A check that needs the page run in a browser is only a question away from one; the
	// process itself starts on the first probe, so a scan that never asks pays nothing.
	checkCtx.Browser = newBrowserProbe(ctx, app, selected)
	// WAF handling is on by default: it costs one probe per host and is what
	// makes the scanner work at all against a filtered target.
	checkCtx.WAF = waf.NewState(!*o.noWAF)
	// The mutations are the part that gets past a firewall, so they run whether or not one
	// was recognised — see Context.AssumeWAF. --no-waf turns the whole thing off, and
	// --no-assume-waf keeps the detection but drops the assumption.
	checkCtx.AssumeWAF = !*o.noAssumeWAF && !*o.noWAF
	checkCtx.Sessions = parseSessions(*o.sessions)

	// The access-control check is meaningless with fewer than two identities;
	// say so before the scan rather than letting it silently do nothing.
	if len(checkCtx.Sessions) < 2 {
		for _, check := range selected {
			if check.ID() == "idor" {
				app.Warn(i18n.KeyMsgIDORNeedsSessions)
				break
			}
		}
	} else {
		app.Note(i18n.KeyMsgSessionsLoaded, len(checkCtx.Sessions))
	}

	scanner := scan.New(scan.Options{
		Checks:      selected,
		Concurrency: *o.threads,
		SkipParams:  *o.skipParams,
		PassiveOnly: passiveOnly,
		Bundle:      app.Bundle,
		OOB:         provider,
		Logf:        func(string, ...any) {},
		OnFinding: func(f *finding.Finding) {
			app.printFinding(f)
		},
	}, checkCtx)
	return checkCtx, scanner, nil
}

// newBrowserProbe returns the browser the DOM check will drive, or nil when the machine has
// none. The check skips itself in that case, and a user who asked for it is told why: a
// scan that silently dropped a check it was asked to run would look like a clean result.
func newBrowserProbe(ctx context.Context, app *App, selected []checks.Check) checks.Browser {
	wanted := false
	for _, check := range selected {
		if check.ID() == "dom-xss" {
			wanted = true
			break
		}
	}
	if !wanted {
		return nil
	}
	execPath := crawl.FindChromium()
	if execPath == "" {
		app.Warn(i18n.KeyMsgNoBrowser)
		return nil
	}
	return browser.New(ctx, execPath, 0, 0)
}

// selectedChecks resolves the --checks flag and any --templates directories into
// the set of checks to run.
//
// Names that matched nothing are reported rather than ignored: a typo in
// --checks would otherwise turn into a scan that silently covers less than the
// user asked for.
func selectedChecks(app *App, spec string, templateDirs []string, client *httpclient.Client, includeUnsafe bool) ([]checks.Check, error) {
	// Templates are loaded first so that they are candidates for selection:
	// "--checks template" has to work before the user has seen the loaded set.
	candidates := checks.All()
	if len(templateDirs) > 0 {
		runner := template.NewRunner(client)
		loaded, unsupported, errs := template.LoadChecks(runner, templateDirs)
		for _, err := range errs {
			app.Warn(i18n.KeyMsgRequestError, err)
		}
		for id, reasons := range unsupported {
			app.Warn(i18n.KeyMsgTemplateUnsupported, id, strings.Join(reasons, ", "))
		}
		for _, check := range loaded {
			candidates = append(candidates, check)
		}
		if len(loaded) > 0 {
			app.Note(i18n.KeyMsgTemplateLoaded, len(loaded), strings.Join(templateDirs, ", "))
		}
	}

	names := splitList(spec)
	selected, unknown := checks.SelectFrom(candidates, names, includeUnsafe)
	if len(unknown) > 0 {
		return nil, &UsageError{msg: app.T(i18n.KeyMsgUnknownChecks, strings.Join(unknown, ", "))}
	}
	if len(selected) == 0 {
		selected = candidates
	}

	// A user who ticked the box is told which of the running checks can affect
	// the target, because that is the whole reason the switch exists.
	var unsafe []string
	for _, check := range selected {
		if checks.IsUnsafe(check) {
			unsafe = append(unsafe, check.ID())
		}
	}
	if len(unsafe) > 0 {
		app.Warn(i18n.KeyMsgUnsafeChecks, strings.Join(unsafe, ", "))
	}
	return selected, nil
}

// parseSessions turns --session values into identities.
//
// Two spellings are accepted, because both are natural to type: a full header
// line ("Cookie: sess=abc", "Authorization: Bearer x") when the identity lives
// in something other than a cookie, and a bare cookie string ("sess=abc;
// uid=1") when it does not.
func parseSessions(specs []string) []checks.Session {
	var sessions []checks.Session
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}

		header := httpmsg.KV{}
		if name, value, ok := strings.Cut(spec, ":"); ok {
			name = strings.TrimSpace(name)
			// A header name is a bare token: no spaces, no '='. That is what
			// tells "Cookie: a=b" from a cookie value that contains a colon.
			if name != "" && !strings.ContainsAny(name, "= \t") {
				header = httpmsg.KV{Name: name, Value: strings.TrimSpace(value)}
			}
		}
		if header.Name == "" {
			header = httpmsg.KV{Name: "Cookie", Value: spec}
		}

		sessions = append(sessions, checks.Session{
			Label:   fmt.Sprintf("session-%d", len(sessions)+1),
			Headers: []httpmsg.KV{header},
		})
	}
	return sessions
}

// splitList splits a comma-separated list, trimming blanks.
func splitList(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// trafficView adapts a sitemap to what checks expect, so that packages which
// know nothing about each other can still share the traffic record.
func trafficView(store *sitemap.Store) func() []checks.Exchange {
	return func() []checks.Exchange {
		if store == nil {
			return nil
		}
		entries := store.All()
		out := make([]checks.Exchange, 0, len(entries))
		for _, entry := range entries {
			if entry.Request == nil || entry.Response == nil {
				continue
			}
			out = append(out, checks.Exchange{Request: entry.Request, Response: entry.Response})
		}
		return out
	}
}

// loadCA loads the workspace CA, creating it on first use.
func loadCA(app *App, dir string) (*ca.CA, error) {
	if dir == "" {
		dir = ca.DefaultDir("")
	}
	authority, created, err := ca.LoadOrGenerate(dir)
	if err != nil {
		return nil, fmt.Errorf(app.T(i18n.KeyErrLoadCA), err)
	}
	if created {
		app.Note(i18n.KeyMsgCAGenerated, dir)
	} else {
		app.Note(i18n.KeyMsgCALoaded, dir)
	}
	return authority, nil
}

// newOOB builds the interaction server. The caller starts it, so that a failure
// to bind can be reported without having half-started a scan.
func newOOB(app *App, opts oob.Options) *oob.Server {
	return oob.New(oob.Options{
		HTTPAddr: opts.HTTPAddr,
		DNSAddr:  opts.DNSAddr,
		Domain:   opts.Domain,
		Logf: func(format string, args ...any) {
			if !app.Quiet {
				app.Printf(format, args...)
			}
		},
	})
}

// findingTitle renders a finding's title, preferring literal text so that a
// template's own wording is shown rather than an empty catalogue lookup.
func (a *App) findingTitle(f *finding.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return a.T(f.TitleKey)
}

// printFinding renders a finding as it is confirmed, so a scan shows progress
// rather than silence followed by a wall of text.
func (a *App) printFinding(f *finding.Finding) {
	severity := a.T(severityKey(f.Severity))
	a.Printf("%s %s  %s", a.paint(ansiRed, "["+severity+"]"), a.bold(a.findingTitle(f)), a.dim(f.CheckID))
	if f.Method != "" || f.URL != "" {
		a.Printf("    %s %s", f.Method, f.URL)
	}
	if f.Param != "" {
		a.Printf("    %s: %s", a.T(i18n.KeyReportFieldParam), f.Param)
	}
	if f.Payload != "" {
		a.Printf("    %s: %s", a.T(i18n.KeyReportFieldPayload), truncateForDisplay(f.Payload, 120))
	}
	a.Print("")
}

// severityKey maps a severity to its catalogue key.
func severityKey(s finding.Severity) i18n.Key {
	switch s {
	case finding.SeverityCritical:
		return i18n.KeySeverityCritical
	case finding.SeverityHigh:
		return i18n.KeySeverityHigh
	case finding.SeverityMedium:
		return i18n.KeySeverityMedium
	case finding.SeverityLow:
		return i18n.KeySeverityLow
	case finding.SeverityInfo:
		return i18n.KeySeverityInfo
	default:
		return i18n.KeySeverityUnknown
	}
}

// truncateForDisplay shortens a value for a terminal line.
func truncateForDisplay(s string, max int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", " ")
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// writeReport renders a report for a finished run and tells the user where it
// went. A failure to write is reported but not fatal: the findings were already
// printed to the terminal, and losing the run over a bad path would be worse.
func writeReport(app *App, path, target string, store *sitemap.Store, scanner *scan.Scanner, boundary report.Boundary) {
	if path == "" {
		return
	}
	bundle := app.Bundle
	data := &report.Data{
		Target:   target,
		Bundle:   bundle,
		Started:  time.Now(),
		Finished: time.Now(),
		Findings: scanner.Findings(),
	}
	if store != nil {
		data.Hosts = store.Hosts()
	}
	summary := scanner.Summary(store)
	data.Started = summary.Started
	data.Finished = summary.Finished
	data.Endpoints = summary.Endpoints
	data.Requests = summary.Stats.Requests

	if err := report.Write(path, data); err != nil {
		app.Warn(i18n.KeyMsgRequestError, err)
		return
	}
	app.Note(i18n.KeyMsgReportWritten, path)
}

// scanBoundary describes what stood between the scan and the target.
//
// Both facts are already being collected — a request that never came back is counted, and a
// firewall that answered is remembered with its vendor — and until now neither reached the
// output. That is the failure this exists to prevent: a defended target and a clean one
// produce the same report.
func scanBoundary(stats scan.Stats, checkCtx *checks.Context) report.Boundary {
	boundary := report.Boundary{Unanswered: stats.Failures}
	if checkCtx == nil || checkCtx.WAF == nil {
		return boundary
	}
	for _, summary := range checkCtx.WAF.Summaries() {
		if summary.Vendor == "" {
			// Probed and found to be unprotected: nothing to say.
			continue
		}
		boundary.Protected = append(boundary.Protected, report.ProtectedHost{
			Host:   summary.Host,
			Vendor: summary.Vendor,
		})
	}
	return boundary
}

// noteBoundary tells the user what stood between the scan and the target, on the terminal as
// well as in the report. It goes after the verdict, because "nothing found" is exactly the
// sentence a defended target also produces.
func (a *App) noteBoundary(boundary report.Boundary) {
	if a.Quiet {
		return
	}
	if boundary.Unanswered > 0 {
		a.Note(i18n.KeyMsgUnanswered, boundary.Unanswered)
	}
	for _, host := range boundary.Protected {
		if host.Vendor != "" {
			a.Note(i18n.KeyMsgProtectedWithVendor, host.Host, host.Vendor)
			continue
		}
		a.Note(i18n.KeyMsgProtectedHost, host.Host)
	}
}

// printChecks lists the available checks, grouped by kind.
func (a *App) printChecks() {
	a.Printf("%s:", a.T(i18n.KeyMsgChecksListed))
	for _, check := range checks.All() {
		kind := "active"
		if check.Passive() {
			kind = "passive"
		}
		// A check that is never selected by default has to say so here. This list is the
		// only place inside the tool that names them, and a user reading it has no other way
		// to learn one exists.
		optIn := ""
		if checks.IsUnsafe(check) {
			optIn = "[" + a.T(i18n.KeyMsgChecksOptIn) + "]"
		}
		a.Printf("  %-28s %-8s %-9s %-16s %s", check.ID(), kind, check.Severity(), optIn,
			strings.Join(check.Tags(), ","))
	}
}
