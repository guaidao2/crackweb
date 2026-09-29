package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/oob"
	"github.com/guaidao2/crackweb/internal/sitemap"
)

// scanOptions is the parsed command line of "crackweb scan".
type scanOptions struct {
	*requestOptions
	url        *string
	raw        *string
	method     *string
	data       *string
	header     *[]string
	checks     *string
	output     *string
	listChecks *bool
	oobHTTP    *string
	oobDNS     *string
	oobDomain  *string
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
				oobHTTP:        fs.String("oob-http", "", "", "<addr>", i18n.KeyFlagHTTPAddr),
				oobDNS:         fs.String("oob-dns", "", "", "<addr>", i18n.KeyFlagDNSAddr),
				oobDomain:      fs.String("oob-domain", "", "", "<host>", i18n.KeyFlagOOBDomain),
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

	var oobServer *oob.Server
	if *opts.oobHTTP != "" || *opts.oobDNS != "" {
		oobServer = newOOB(app, oob.Options{
			HTTPAddr: *opts.oobHTTP,
			DNSAddr:  *opts.oobDNS,
			Domain:   *opts.oobDomain,
		})
		if err := oobServer.Start(ctx); err != nil {
			app.Warn(i18n.KeyMsgRequestError, err)
			oobServer = nil
		} else {
			app.Note(i18n.KeyMsgOOBListening, oobServer.HTTPAddr(), oobServer.DNSAddr())
		}
	}

	client, err := opts.client()
	if err != nil {
		return err
	}

	selected, err := selectedChecks(app, *opts.checks, *opts.templates, client, *opts.unsafeChecks)
	if err != nil {
		return err
	}

	checkCtx, scanner, err := opts.scanContext(ctx, app, client, oobServer, selected, false)
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
