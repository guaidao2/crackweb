package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/guaidao2/crackweb/internal/ca"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/oob"
	"github.com/guaidao2/crackweb/internal/proxy"
	"github.com/guaidao2/crackweb/internal/sitemap"
)

// proxyOptions is the parsed command line of "crackweb proxy".
type proxyOptions struct {
	*requestOptions
	listen      *string
	upstream    *string
	scope       *[]string
	passiveOnly *bool
	report      *string
	checks      *string
	listChecks  *bool
	exportCA    *string
	oobHTTP     *string
	oobDNS      *string
	oobDomain   *string
}

// newProxyCommand builds the intercepting proxy command — the traffic-driven
// half of crackweb, where what gets tested is decided by where the browser goes.
func newProxyCommand() *command {
	return newCommand("proxy", i18n.KeyCmdProxySummary, i18n.KeyUsageProxy,
		func(fs *FlagSet) *proxyOptions {
			return &proxyOptions{
				requestOptions: addRequestFlags(fs),
				listen:         fs.String("listen", "l", proxy.DefaultListen, "<addr>", i18n.KeyFlagListen),
				upstream:       fs.String("upstream", "", "", "<url>", i18n.KeyFlagUpstream),
				scope:          fs.StringSlice("scope", "", "<pattern>", i18n.KeyFlagScope),
				passiveOnly:    fs.Bool("passive-only", "", i18n.KeyFlagPassiveOnly),
				report:         fs.String("output", "o", "", "<file>", i18n.KeyFlagScanOutput),
				checks:         fs.String("checks", "", "all", "<list>", i18n.KeyFlagChecks),
				listChecks:     fs.Bool("list-checks", "", i18n.KeyFlagListChecks),
				exportCA:       fs.String("export-ca", "", "", "<file>", i18n.KeyFlagExportCA),
				oobHTTP:        fs.String("oob-http", "", "", "<addr>", i18n.KeyFlagHTTPAddr),
				oobDNS:         fs.String("oob-dns", "", "", "<addr>", i18n.KeyFlagDNSAddr),
				oobDomain:      fs.String("oob-domain", "", "", "<host>", i18n.KeyFlagOOBDomain),
			}
		},
		runProxy)
}

// runProxy starts the proxy, feeds everything it sees to the scanner, and writes
// a report once the user stops it.
func runProxy(app *App, opts *proxyOptions, _ []string) error {
	if *opts.listChecks {
		app.printChecks()
		return nil
	}

	// Ctrl-C is the normal way to end a proxy session, so it has to be a clean
	// shutdown that still produces a report.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authority, err := loadCA(app, "")
	if err != nil {
		return err
	}
	if *opts.exportCA != "" {
		if err := os.WriteFile(*opts.exportCA, authority.CertPEM(), 0o644); err != nil {
			return err
		}
	}
	app.Note(i18n.KeyMsgProxyCAHint, ca.DefaultDir(""))

	// Out-of-band testing is opt-in here: the callback listener has to be
	// reachable from the target, which is not true of a laptop behind NAT.
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

	checkCtx, scanner, err := opts.scanContext(app, client, oobServer, selected, *opts.passiveOnly)
	if err != nil {
		return err
	}
	scanner.Start(ctx)

	store := sitemap.New(0)
	// Cross-request checks, such as stored injection, need to see the traffic
	// that has gone through already. Without a store they skip themselves.
	checkCtx.Exchanges = trafficView(store)

	intercept, err := proxy.New(proxy.Options{
		Listen:   *opts.listen,
		Scope:    *opts.scope,
		Upstream: *opts.upstream,
		CA:       authority,
		Insecure: *opts.insecure,
		Timeout:  *opts.timeout,
		OnResponse: func(req *httpmsg.Request, resp *httpmsg.Response) {
			// Recording and scanning are deliberately not on the critical path
			// of the request: browsing must stay responsive while a scan runs.
			store.Add(req, resp)
			scanner.Submit(req, resp)
		},
		OnError: func(err error) {
			if *opts.verbose {
				app.Warn(i18n.KeyMsgRequestError, err)
			}
		},
		Logf: func(format string, args ...any) {
			if *opts.verbose {
				app.Printf(format, args...)
			}
		},
	})
	if err != nil {
		return err
	}

	app.Print(app.bold(app.T(i18n.KeyMsgProxyListening, intercept.Addr())))
	app.Print(app.dim(app.T(i18n.KeyAppTagline)))
	app.Print("")

	serveErr := intercept.Serve(ctx)

	// Give in-flight checks a moment and let the scanner drain before the
	// report is written, so the last findings are not lost.
	scanner.Stop()

	if len(scanner.Findings()) == 0 {
		app.Note(i18n.KeyMsgNoFindings)
	}
	writeReport(app, *opts.report, *opts.listen, store, scanner)

	if serveErr != nil {
		return serveErr
	}
	app.Note(i18n.KeyMsgProxyStopped)
	return nil
}
