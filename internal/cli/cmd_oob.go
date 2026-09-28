package cli

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/oob"
)

// oobOptions is the parsed command line of "crackweb oob".
type oobOptions struct {
	http   *string
	dns    *string
	token  *string
	domain *string
}

// newOobCommand builds the out-of-band interaction server command. Running it
// standalone is what lets a scan on one host receive callbacks from a target
// that cannot reach it — the common case when the scanning machine is behind
// NAT and the target is on the internet.
func newOobCommand() *command {
	return newCommand("oob", i18n.KeyCmdOobSummary, i18n.KeyUsageOob,
		func(fs *FlagSet) *oobOptions {
			return &oobOptions{
				http:   fs.String("http", "", oob.DefaultHTTPAddr, "<addr>", i18n.KeyFlagHTTPAddr),
				dns:    fs.String("dns", "", oob.DefaultDNSAddr, "<addr>", i18n.KeyFlagDNSAddr),
				token:  fs.String("token", "", "", "<secret>", i18n.KeyFlagOOBToken),
				domain: fs.String("domain", "", "", "<host>", i18n.KeyFlagOOBDomain),
			}
		},
		runOOB)
}

// runOOB starts the interaction server and reports callbacks as they arrive.
func runOOB(app *App, opts *oobOptions, _ []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := newOOB(app, oob.Options{
		HTTPAddr: *opts.http,
		DNSAddr:  *opts.dns,
		Domain:   *opts.domain,
		Token:    *opts.token,
	})

	go func() {
		if err := server.Start(ctx); err != nil && ctx.Err() == nil {
			app.Warn(i18n.KeyMsgRequestError, err)
		}
	}()

	// Give the listeners a moment so the addresses printed are the real ones.
	time.Sleep(50 * time.Millisecond)
	app.Note(i18n.KeyMsgOOBListening, server.HTTPAddr(), server.DNSAddr())

	exampleURL, _ := server.NewURL("example")
	app.Printf("")
	app.Printf("%s", app.T(i18n.KeyMsgOOBCallbackExample, exampleURL))
	app.Print("")

	// Report interactions as they land, rather than making the operator guess
	// whether anything is arriving.
	seen := 0
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = server.Close()
			app.Note(i18n.KeyMsgProxyStopped)
			return nil
		case <-ticker.C:
			events := server.Events()
			for _, event := range events[min(seen, len(events)):] {
				app.Printf("%s  %-4s  %-16s  %s",
					app.bold(event.At.Format("15:04:05")),
					strings.ToUpper(event.Protocol),
					event.RemoteAddr,
					event.Detail)
			}
			seen = len(events)
		}
	}
}
