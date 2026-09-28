// Package cli implements crackweb's command line: global option handling,
// subcommand dispatch, and help output in the user's language.
//
// English is the default. Chinese is switched on explicitly with --lang zh, or
// implicitly through CRACKWEB_LANG or a Chinese POSIX locale.
package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/guaidao2/crackweb/internal/i18n"
)

// Exit codes, following the usual convention so crackweb behaves in scripts.
const (
	// ExitOK means the command finished successfully.
	ExitOK = 0
	// ExitFailure means the command started but did not finish.
	ExitFailure = 1
	// ExitUsage means the command line itself was wrong.
	ExitUsage = 2
)

// ErrUnimplemented is returned by a command whose behaviour is not built yet.
// The command has already explained itself on stderr by the time it is returned.
var ErrUnimplemented = errors.New("not implemented")

// errLangNeedsValue is an internal sentinel: the caller localises it once a
// catalogue exists.
var errLangNeedsValue = errors.New("--lang needs a value")

// Main is the process entry point. It returns the exit code rather than calling
// os.Exit so that it stays testable.
func Main(args []string, stdout, stderr io.Writer) int {
	rest, global, err := extractGlobalOptions(args)

	lang := i18n.Default
	if err != nil {
		// The command line is already broken before we know which language to
		// speak, so report it in the default one.
		app := newApp(lang, stdout, stderr, global)
		app.Fail(i18n.KeyErrFlagNeedsValue, "--lang")
		return ExitUsage
	}

	if global.langExplicit {
		parsed, ok := i18n.ParseLang(global.lang)
		if !ok {
			// The requested language is unusable, so report that in the default
			// language rather than guessing.
			app := newApp(lang, stdout, stderr, global)
			app.Fail(i18n.KeyErrBadLang, global.lang)
			return ExitUsage
		}
		lang = parsed
	} else {
		lang = i18n.Detect("")
	}

	return newApp(lang, stdout, stderr, global).Run(rest)
}

// newApp assembles the output environment for a run.
func newApp(lang i18n.Lang, stdout, stderr io.Writer, global globalOptions) *App {
	return &App{
		Bundle: i18n.New(lang),
		Stdout: stdout,
		Stderr: stderr,
		Color:  ColorEnabled(stdout, global.noColor),
		Quiet:  global.quiet,
	}
}

// globalOptions holds the options that are accepted before, and independently
// of, any subcommand.
type globalOptions struct {
	lang         string
	langExplicit bool
	noColor      bool
	quiet        bool
}

// extractGlobalOptions pulls the global options out of the argument list,
// wherever they appear, and returns the remaining arguments untouched. Global
// options therefore work both as "crackweb --lang zh proxy" and as
// "crackweb proxy --lang zh".
//
// None of them has a short alias on purpose: the short names are the business of
// the subcommands, where -l already means --listen and -q would be ambiguous.
func extractGlobalOptions(args []string) ([]string, globalOptions, error) {
	var (
		global globalOptions
		rest   = make([]string, 0, len(args))
	)

	for i := 0; i < len(args); i++ {
		token := args[i]
		name, inline, hasInline := splitOption(token)

		switch name {
		case "lang":
			global.langExplicit = true
			if hasInline {
				global.lang = inline
				continue
			}
			if i+1 >= len(args) {
				return nil, global, errLangNeedsValue
			}
			i++
			global.lang = args[i]

		case "no-color":
			global.noColor = true

		case "quiet":
			global.quiet = true

		default:
			rest = append(rest, token)
		}
	}
	return rest, global, nil
}

// splitOption breaks "--name=value" into its parts. Anything that is not a long
// option comes back with an empty name, so it is passed through untouched.
func splitOption(token string) (name, inline string, hasInline bool) {
	if !strings.HasPrefix(token, "--") {
		return "", "", false
	}
	name, inline, hasInline = strings.Cut(strings.TrimPrefix(token, "--"), "=")
	return name, inline, hasInline
}

// Command is one subcommand: its identity, the options it accepts and the work
// it performs.
type command struct {
	name    string
	summary i18n.Key
	usage   i18n.Key

	// flagSet builds the option set for help rendering.
	flagSet func(*App) *FlagSet
	// execute parses the arguments and runs the command.
	execute func(*App, []string) error
}

// newCommand wires a typed option struct to the generic command plumbing, so
// each subcommand declares its options once and gets type-safe access to them
// in its run function.
func newCommand[O any](
	name string,
	summary, usage i18n.Key,
	setup func(*FlagSet) *O,
	run func(*App, *O, []string) error,
) *command {
	return &command{
		name:    name,
		summary: summary,
		usage:   usage,
		flagSet: func(app *App) *FlagSet {
			fs := NewFlagSet(app.Bundle)
			setup(fs)
			return fs
		},
		execute: func(app *App, args []string) error {
			fs := NewFlagSet(app.Bundle)
			opts := setup(fs)
			if err := fs.Parse(args); err != nil {
				return err
			}
			return run(app, opts, fs.Args())
		},
	}
}

// commands returns every subcommand, in the order they are listed in the help.
func (a *App) commands() []*command {
	return []*command{
		newProxyCommand(),
		newCrawlCommand(),
		newScanCommand(),
		newOobCommand(),
		newCaCommand(),
	}
}

// findCommand looks a subcommand up by name.
func (a *App) findCommand(name string) *command {
	for _, cmd := range a.commands() {
		if cmd.name == name {
			return cmd
		}
	}
	return nil
}

// Run dispatches a command line that has already had its global options
// stripped.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		a.Print(a.rootHelp())
		return ExitOK
	}

	switch args[0] {
	case "-h", "--help", "help":
		a.Print(a.rootHelp())
		return ExitOK
	case "-V", "--version", "version":
		a.Print(a.versionText())
		return ExitOK
	}

	if strings.HasPrefix(args[0], "-") {
		a.Fail(i18n.KeyErrUnknownFlag, args[0])
		fmt.Fprintln(a.Stderr, a.T(i18n.KeyHelpSubcommandHint))
		return ExitUsage
	}

	cmd := a.findCommand(args[0])
	if cmd == nil {
		a.Fail(i18n.KeyErrUnknownCommand, args[0])
		fmt.Fprintln(a.Stderr, a.T(i18n.KeyHelpSubcommandHint))
		return ExitUsage
	}
	return a.execute(cmd, args[1:])
}

// execute runs one subcommand and maps its outcome onto an exit code.
func (a *App) execute(cmd *command, args []string) int {
	err := cmd.execute(a, args)
	switch {
	case err == nil:
		return ExitOK

	case errors.Is(err, ErrHelp):
		a.Print(a.commandHelp(cmd))
		return ExitOK

	case errors.Is(err, ErrUnimplemented):
		// The command has already said what is missing; do not talk over it.
		return ExitFailure

	case IsUsageError(err):
		a.FailMessage(err.Error())
		fmt.Fprintln(a.Stderr, a.dim(a.commandUsageLine(cmd)))
		return ExitUsage

	default:
		a.FailMessage(err.Error())
		return ExitFailure
	}
}
