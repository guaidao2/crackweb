package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/guaidao2/crackweb/internal/i18n"
)

// ANSI escapes. crackweb does not depend on a colouring library: the handful of
// styles it needs are cheaper to write than to vendor.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
)

// App carries everything a command needs to talk to the user: the message
// catalogue, the two output streams and whether colour is welcome.
type App struct {
	Bundle *i18n.Bundle
	Stdout io.Writer
	Stderr io.Writer
	// Color enables ANSI styling on stdout.
	Color bool
	// Quiet suppresses progress and status chatter, leaving findings only.
	Quiet bool
}

// T looks a message up in the active catalogue.
func (a *App) T(key i18n.Key, args ...any) string { return a.Bundle.T(key, args...) }

// Print writes a line to stdout.
func (a *App) Print(line string) { fmt.Fprintln(a.Stdout, line) }

// Printf writes a formatted line to stdout.
func (a *App) Printf(format string, args ...any) { fmt.Fprintf(a.Stdout, format+"\n", args...) }

// Note writes an informational line to stderr. Status chatter goes to stderr so
// that a report piped to stdout stays clean.
func (a *App) Note(key i18n.Key, args ...any) {
	fmt.Fprintln(a.Stderr, a.T(key, args...))
}

// Warn writes a highlighted warning to stderr.
func (a *App) Warn(key i18n.Key, args ...any) {
	fmt.Fprintln(a.Stderr, a.paint(ansiYellow, a.T(key, args...)))
}

// Fail writes an error to stderr.
func (a *App) Fail(key i18n.Key, args ...any) {
	fmt.Fprintln(a.Stderr, a.paint(ansiRed, a.T(key, args...)))
}

// FailMessage writes an already-rendered error to stderr.
func (a *App) FailMessage(msg string) {
	fmt.Fprintln(a.Stderr, a.paint(ansiRed, msg))
}

// Text returns msg verbatim when colour is off.
func (a *App) Text(msg string) string { return msg }

func (a *App) paint(code, msg string) string {
	if !a.Color {
		return msg
	}
	return code + msg + ansiReset
}

// bold styles a heading, when colour is enabled.
func (a *App) bold(msg string) string { return a.paint(ansiBold, msg) }

// dim styles secondary text, when colour is enabled.
func (a *App) dim(msg string) string { return a.paint(ansiDim, msg) }

// isTerminal reports whether w is an interactive terminal, which is the cue to
// enable colour. Pipes and files get plain text.
func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled decides whether to use ANSI styles on stdout. NO_COLOR (any
// non-empty value) and a non-terminal stdout both turn colour off.
func ColorEnabled(stdout io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminal(stdout)
}
