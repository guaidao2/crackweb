package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/guaidao2/crackweb/internal/crawl"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/sitemap"
)

// crawlOptions is the parsed command line of "crackweb crawl".
type crawlOptions struct {
	*requestOptions
	url           *string
	depth         *int
	engine        *string
	maxPages      *int
	scope         *[]string
	checks        *string
	report        *string
	listChecks    *bool
	noDiscovery   *bool
	allowState    *bool
	apiDoc        *[]string
	oobHTTP       *string
	oobDNS        *string
	oobDomain     *string
	oobInteractsh *string
	oobToken      *string
}

// newCrawlCommand builds the crawler command: discovery-driven scanning, for
// targets nobody is going to click through by hand.
func newCrawlCommand() *command {
	return newCommand("crawl", i18n.KeyCmdCrawlSummary, i18n.KeyUsageCrawl,
		func(fs *FlagSet) *crawlOptions {
			return &crawlOptions{
				requestOptions: addRequestFlags(fs),
				url:            fs.String("url", "u", "", "<url>", i18n.KeyFlagURL),
				depth:          fs.Int("depth", "", crawl.DefaultDepth, "<n>", i18n.KeyFlagDepth),
				engine:         fs.String("engine", "", crawl.EngineHybrid, "<name>", i18n.KeyFlagEngine),
				maxPages:       fs.Int("max-pages", "", crawl.DefaultMaxPages, "<n>", i18n.KeyFlagMaxPages),
				scope:          fs.StringSlice("scope", "", "<pattern>", i18n.KeyFlagScope),
				checks:         fs.String("checks", "", "all", "<list>", i18n.KeyFlagChecks),
				report:         fs.String("output", "o", "", "<file>", i18n.KeyFlagScanOutput),
				listChecks:     fs.Bool("list-checks", "", i18n.KeyFlagListChecks),
				noDiscovery:    fs.Bool("no-discovery", "", i18n.KeyFlagNoDiscovery),
				allowState:     fs.Bool("allow-state-change", "", i18n.KeyFlagAllowStateChange),
				apiDoc:         fs.StringSlice("api-doc", "", "<path>", i18n.KeyFlagAPIDoc),
				oobHTTP:        fs.String("oob-http", "", "", "<addr>", i18n.KeyFlagHTTPAddr),
				oobDNS:         fs.String("oob-dns", "", "", "<addr>", i18n.KeyFlagDNSAddr),
				oobDomain:      fs.String("oob-domain", "", "", "<host>", i18n.KeyFlagOOBDomain),
				oobInteractsh:  fs.String("oob-interactsh", "", "", "<server>", i18n.KeyFlagOOBInteractsh),
				oobToken:       fs.String("oob-token", "", "", "<token>", i18n.KeyFlagOOBToken),
			}
		},
		runCrawl)
}

// runCrawl crawls a target and scans everything it finds.
func runCrawl(app *App, opts *crawlOptions, _ []string) error {
	if *opts.listChecks {
		app.printChecks()
		return nil
	}
	if *opts.url == "" {
		return &UsageError{msg: app.T(i18n.KeyErrURLRequired)}
	}
	switch *opts.engine {
	case crawl.EngineHTTP, crawl.EngineHeadless, crawl.EngineHybrid:
	default:
		return &UsageError{msg: app.T(i18n.KeyMsgUnknownChecks, *opts.engine)}
	}

	// Warn before the crawl starts rather than after it finishes, so the user
	// knows why the browser-based discovery they asked for did not happen. The
	// crawl itself degrades quietly to the HTTP engine either way.
	if *opts.engine != crawl.EngineHTTP && crawl.FindChromium() == "" {
		app.Warn(i18n.KeyMsgNoBrowser)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
	app.Note(i18n.KeyMsgScanStarted, *opts.url)
	// Say it before it happens: the crawl asks for addresses the user did not name, and
	// finding that out from a target's logs is the wrong way round.
	if !*opts.noDiscovery {
		app.Note(i18n.KeyMsgProbing)
	}

	store := sitemap.New(0)
	// Cross-request checks need the traffic the crawl has collected so far.
	checkCtx.Exchanges = trafficView(store)

	crawler := crawl.New(crawl.Options{
		Client:           client,
		Engine:           *opts.engine,
		Depth:            *opts.depth,
		MaxPages:         *opts.maxPages,
		Concurrency:      *opts.threads,
		Scope:            *opts.scope,
		NoDiscovery:      *opts.noDiscovery,
		AllowStateChange: *opts.allowState,
		APIDocPaths:      *opts.apiDoc,
		OnExchange: func(req *httpmsg.Request, resp *httpmsg.Response) {
			store.Add(req, resp)
			scanner.Submit(req, resp)
		},
		Logf: func(format string, args ...any) {
			if *opts.verbose {
				app.Printf(format, args...)
			}
		},
	})
	crawlErr := crawler.Run(ctx, *opts.url)
	if crawlErr != nil && ctx.Err() == nil {
		app.Warn(i18n.KeyMsgRequestError, crawlErr)
	}

	// Let the checks finish what the crawl handed them before reporting.
	scanner.Wait()

	findings := scanner.Findings()
	stats := scanner.Stats()
	crawlStats := crawler.Stats()
	if len(findings) == 0 {
		app.Note(i18n.KeyMsgNoFindings)
	} else {
		app.Note(i18n.KeyMsgScanFinished, len(findings), stats.Requests, humanDurationText(stats.Elapsed))
	}
	if !app.Quiet {
		app.Note(i18n.KeyMsgCrawlStats, crawlStats.Pages, crawlStats.Discovered, stats.Requests)
		if crawlStats.Descriptions > 0 || crawlStats.SiteFiles > 0 {
			app.Note(i18n.KeyMsgSelfDescribed, crawlStats.Descriptions, crawlStats.SiteFiles)
		}
	}
	boundary := scanBoundary(stats, checkCtx)
	app.noteBoundary(boundary)
	writeReport(app, *opts.report, *opts.url, store, scanner, boundary)
	return nil
}
