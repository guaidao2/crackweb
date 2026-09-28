package cli

import (
	"fmt"
	"strings"

	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/version"
)

// section renders a bold heading with a blank line after it.
func (a *App) section(title i18n.Key) string {
	return a.bold(a.T(title)) + "\n"
}

// versionText is what "crackweb --version" prints.
func (a *App) versionText() string {
	var b strings.Builder
	b.WriteString(a.bold(version.Full()) + "\n\n")
	b.WriteString(a.T(i18n.KeyAppTagline) + "\n\n")
	fmt.Fprintf(&b, "%s %s\n\n", a.T(i18n.KeyRepoLabel), version.Repo)
	b.WriteString(a.T(i18n.KeyAppDisclaimer))
	return b.String()
}

// rootHelp is the top-level help: banner, usage, commands, global options and
// examples.
func (a *App) rootHelp() string {
	var b strings.Builder

	b.WriteString(a.bold(version.Full()) + "\n")
	b.WriteString(a.T(i18n.KeyAppTagline) + "\n\n")

	b.WriteString(a.section(i18n.KeyHelpUsage))
	fmt.Fprintf(&b, "  %s\n\n", a.T(i18n.KeyHelpUsageLine))

	b.WriteString(a.section(i18n.KeyHelpCommandsTitle))
	b.WriteString(a.commandList())

	b.WriteString(a.section(i18n.KeyHelpOptionsTitle))
	b.WriteString(a.globalFlagSet().Help())
	b.WriteByte('\n')

	b.WriteString(a.section(i18n.KeyHelpExamplesTitle))
	b.WriteString(a.T(i18n.KeyHelpExamples) + "\n\n")

	b.WriteString(a.dim(a.T(i18n.KeyHelpSubcommandHint)) + "\n\n")

	b.WriteString(a.section(i18n.KeyHelpMoreInfoTitle))
	fmt.Fprintf(&b, "  %s\n", version.Repo)

	return b.String()
}

// commandList renders the COMMANDS table, aligned on the longest name.
func (a *App) commandList() string {
	commands := a.commands()
	width := 0
	for _, cmd := range commands {
		if len(cmd.name) > width {
			width = len(cmd.name)
		}
	}

	var b strings.Builder
	for _, cmd := range commands {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, cmd.name, a.T(cmd.summary))
	}
	b.WriteByte('\n')
	return b.String()
}

// commandHelp is what "crackweb <command> --help" prints.
func (a *App) commandHelp(cmd *command) string {
	var b strings.Builder

	b.WriteString(a.section(i18n.KeyHelpUsage))
	fmt.Fprintf(&b, "  %s\n\n", a.commandUsageLine(cmd))

	if help := cmd.flagSet(a).Help(); help != "" {
		b.WriteString(a.section(i18n.KeyHelpCmdOptionsTitle))
		b.WriteString(help)
		b.WriteByte('\n')
	}

	b.WriteString(a.dim(a.T(i18n.KeyHelpGlobalHint)))
	return b.String()
}

// commandUsageLine renders the command's usage with the program name prefixed.
func (a *App) commandUsageLine(cmd *command) string {
	return a.T(i18n.KeyHelpCommandUsageFmt, a.T(cmd.usage))
}

// notImplemented reports that a command's behaviour arrives in a later
// milestone. It speaks for itself on stderr and returns ErrUnimplemented, which
// execute turns into a failing — but not usage — exit code.
func notImplemented(app *App, feature, milestone string) error {
	app.Note(i18n.KeyMsgNotImplemented, feature)
	app.Note(i18n.KeyMsgPlannedFor, milestone)
	return ErrUnimplemented
}

// globalFlagSet describes the options Main understands, for help rendering
// only — it is never used to parse anything, since these are handled before
// dispatch so that they work on either side of the subcommand name.
func (a *App) globalFlagSet() *FlagSet {
	fs := NewFlagSet(a.Bundle)
	fs.String("lang", "", string(i18n.Default), "<code>", i18n.KeyFlagLang)
	fs.Bool("no-color", "", i18n.KeyFlagNoColor)
	fs.Bool("quiet", "", i18n.KeyFlagQuiet)
	fs.Bool("help", "h", i18n.KeyFlagHelp)
	fs.Bool("version", "V", i18n.KeyFlagVersion)
	return fs
}
