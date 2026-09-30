package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/crawl"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/scan"
	"github.com/guaidao2/crackweb/internal/sitemap"
)

// scanOptions is the parsed command line of "crackweb scan".
type scanOptions struct {
	*requestOptions
	url           *string
	raw           *string
	method        *string
	data          *string
	header        *[]string
	checks        *string
	output        *string
	listChecks    *bool
	forms         *bool
	oobHTTP       *string
	oobDNS        *string
	oobDomain     *string
	oobInteractsh *string
	oobToken      *string
	// fs is kept so the command can tell "not given" from "given the default".
	fs *FlagSet
}

// newScanCommand builds the one-shot scan command: a single target, or a single
// captured request, tested once.
func newScanCommand() *command {
	return newCommand("scan", i18n.KeyCmdScanSummary, i18n.KeyUsageScan,
		func(fs *FlagSet) *scanOptions {
			opts := &scanOptions{
				requestOptions: addRequestFlags(fs),
				url:            fs.String("url", "u", "", "<url>", i18n.KeyFlagScanURL),
				raw:            fs.String("raw", "r", "", "<file>", i18n.KeyFlagRaw),
				method:         fs.String("method", "X", "GET", "<method>", i18n.KeyFlagScanMethod),
				data:           fs.String("data", "d", "", "<body>", i18n.KeyFlagScanData),
				header:         fs.StringSlice("header", "H", "<header>", i18n.KeyFlagScanHeader),
				checks:         fs.String("checks", "", "all", "<list>", i18n.KeyFlagChecks),
				output:         fs.String("output", "o", "", "<file>", i18n.KeyFlagScanOutput),
				listChecks:     fs.Bool("list-checks", "", i18n.KeyFlagListChecks),
				forms:          fs.Bool("forms", "", i18n.KeyFlagScanForms),
				oobHTTP:        fs.String("oob-http", "", "", "<addr>", i18n.KeyFlagHTTPAddr),
				oobDNS:         fs.String("oob-dns", "", "", "<addr>", i18n.KeyFlagDNSAddr),
				oobDomain:      fs.String("oob-domain", "", "", "<host>", i18n.KeyFlagOOBDomain),
				oobInteractsh:  fs.String("oob-interactsh", "", "", "<server>", i18n.KeyFlagOOBInteractsh),
				oobToken:       fs.String("oob-token", "", "", "<token>", i18n.KeyFlagOOBToken),
			}
			opts.fs = fs
			return opts
		},
		runScan)
}

// runScan performs a one-shot scan.
func runScan(app *App, opts *scanOptions, _ []string) error {
	if *opts.listChecks {
		app.printChecks()
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	request, err := buildScanRequest(app, opts)
	if err != nil {
		return err
	}

	oobProvider := buildOOBProvider(ctx, app, *opts.oobHTTP, *opts.oobDNS,
		*opts.oobDomain, *opts.oobInteractsh, *opts.oobToken)

	client, err := opts.client()
	if err != nil {
		return err
	}

	selected, err := selectedChecks(app, *opts.checks, *opts.templates, client, *opts.unsafeChecks)
	if err != nil {
		return err
	}

	checkCtx, scanner, err := opts.scanContext(ctx, app, client, oobProvider, selected, false)
	if err != nil {
		return err
	}
	scanner.Start(ctx)

	if !app.Quiet {
		app.Note(i18n.KeyMsgChecksLoaded, len(selected), scanner.PassiveCount(), scanner.ActiveCount())
	}
	app.Note(i18n.KeyMsgScanStarted, request.URLString())

	// The scan needs a real response to compare against, so the baseline is
	// fetched first and handed to the checks as the target's own response.
	baselineStart := time.Now()
	resp, err := checkCtx.Do(ctx, request)
	if err != nil {
		return fmt.Errorf(app.T(i18n.KeyMsgRequestError), err)
	}

	store := sitemap.New(0)
	store.Add(request, resp)

	scanner.Submit(request, resp)

	// A page that declares a form is only testable through the request that form produces, and
	// a one-shot scan never gets there by itself: the form's action is a different URL, with a
	// body and an encoding the seed does not carry. --forms asks for that page's forms and
	// submits each one, exactly as the crawler would.
	if *opts.forms {
		submitForms(ctx, checkCtx, scanner, store, request, resp)
	}

	scanner.Wait()

	findings := scanner.Findings()
	stats := scanner.Stats()
	elapsed := time.Since(baselineStart)
	_ = elapsed

	if len(findings) == 0 {
		app.Note(i18n.KeyMsgNoFindings)
	} else {
		app.Note(i18n.KeyMsgScanFinished, len(findings), stats.Requests, humanDurationText(stats.Elapsed))
	}
	boundary := scanBoundary(stats, checkCtx)
	app.noteBoundary(boundary)
	writeReport(app, *opts.output, request.URLString(), store, scanner, boundary)
	return nil
}

// buildScanRequest turns the command line into the request to test.
func buildScanRequest(app *App, opts *scanOptions) (*httpmsg.Request, error) {
	if *opts.raw != "" {
		data, err := os.ReadFile(*opts.raw)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", *opts.raw, err)
		}
		request, err := httpmsg.ParseRequest(data, httpmsg.ParseOptions{})
		if err != nil {
			return nil, err
		}
		return request, nil
	}

	if *opts.url == "" {
		return nil, &UsageError{msg: app.T(i18n.KeyErrNeedTarget)}
	}

	request, err := httpmsg.NewRequest(*opts.method, *opts.url)
	if err != nil {
		return nil, err
	}
	// With a body the request is a form POST unless told otherwise.
	if *opts.data != "" {
		request.Body = []byte(*opts.data)
		request.Header.Set("Content-Length", fmt.Sprint(len(request.Body)))
		if request.ContentType() == "" {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if *opts.method == "GET" && !(opts.fs != nil && opts.fs.WasSet("method")) {
			request.Method = "POST"
		}
	}
	for _, raw := range *opts.header {
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		request.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return request, nil
}

// humanDurationText renders a duration for a status line.
func humanDurationText(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	return d.Round(time.Millisecond).String()
}

// submitForms submits every form the scanned page declares and hands each exchange to the
// scanner, so the checks see the parameters a user would actually send.
//
// Failing to parse the page is not an error: a response that carries no HTML has no forms, and
// the scan it was asked for has already happened.
func submitForms(ctx context.Context, checkCtx *checks.Context, scanner *scan.Scanner,
	store *sitemap.Store, request *httpmsg.Request, resp *httpmsg.Response) {
	if request.URL == nil || resp == nil || len(resp.Body) == 0 {
		return
	}
	var submitted []*httpmsg.Request

	if page, err := crawl.Parse(string(resp.Body), request.URL, false); err == nil {
		for _, form := range page.Forms {
			submitted = append(submitted, crawl.FormRequests(form, request.URL)...)
		}
	}
	// A modern page often declares no form at all: the search box and the upload widget are
	// script calls, carrying a JSON or multipart body that no GET reproduces. Those are read
	// out of the page's own script and sent the way it sends them, so the endpoints behind
	// them are testable from a single URL too.
	for _, call := range crawl.ScriptCalls(string(resp.Body), request.URL, true) {
		// --forms is an explicit request to send what the page sends, so a call the page
		// makes with POST is included: that is exactly what an HTML form does, and the two
		// should not differ. PUT, PATCH and DELETE stay out — no form submits with them, and
		// a scan that sends one is asking a target to change state in the hope of being
		// allowed to.
		if !formLikeMethod(call.Method) {
			continue
		}
		submitted = append(submitted, crawl.ScriptRequests(call)...)
	}

	for _, formReq := range submitted {
		formResp, err := checkCtx.Do(ctx, formReq)
		if err != nil || formResp == nil {
			continue
		}
		store.Add(formReq, formResp)
		scanner.Submit(formReq, formResp)
	}
}

// formLikeMethod reports whether a method is one a form can submit with.
func formLikeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "POST":
		return true
	}
	return false
}
