package cli

import (
	"bytes"
	"strings"
	"testing"
)

// run executes crackweb's entry point with captured output and a neutral
// language environment, so the result does not depend on the host.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Setenv("CRACKWEB_LANG", "")

	var out, errOut bytes.Buffer
	code = Main(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestNoArgumentsPrintsRootHelpInEnglish(t *testing.T) {
	code, stdout, _ := run(t)

	if code != ExitOK {
		t.Errorf("exit code = %d, want %d", code, ExitOK)
	}
	for _, want := range []string{"USAGE", "COMMANDS", "GLOBAL OPTIONS", "EXAMPLES", "proxy"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help output is missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "用法") {
		t.Error("default output should be English, but it contains Chinese headings")
	}
}

// TestEveryLanguageSwitchWorks covers the three ways a user can ask for
// Chinese, including the position-independence of global options.
func TestEveryLanguageSwitchWorks(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  string
	}{
		{"--lang before the command", []string{"--lang", "zh", "proxy", "--help"}, ""},
		{"--lang after the command", []string{"proxy", "--help", "--lang", "zh"}, ""},
		{"--lang=value form", []string{"--lang=zh", "--help"}, ""},
		{"CRACKWEB_LANG", []string{"proxy", "--help"}, "zh"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CRACKWEB_LANG", tc.env)

			var out, errOut bytes.Buffer
			if code := Main(tc.args, &out, &errOut); code != ExitOK {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitOK, errOut.String())
			}
			if !strings.Contains(out.String(), "选项") && !strings.Contains(out.String(), "用法") {
				t.Errorf("output is not in Chinese:\n%s", out.String())
			}
		})
	}
}

// TestLocaleAloneDoesNotSwitchLanguage guards the documented default: English
// unless the user asks otherwise.
func TestLocaleAloneDoesNotSwitchLanguage(t *testing.T) {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("CRACKWEB_LANG", "")
			t.Setenv(key, "zh_CN.UTF-8")

			var out, errOut bytes.Buffer
			if code := Main([]string{"--help"}, &out, &errOut); code != ExitOK {
				t.Fatalf("exit code = %d, want %d", code, ExitOK)
			}
			if !strings.Contains(out.String(), "USAGE") {
				t.Errorf("%s=zh_CN.UTF-8 changed the language:\n%s", key, out.String())
			}
		})
	}
}

func TestVersionOutput(t *testing.T) {
	code, stdout, _ := run(t, "--version")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	for _, want := range []string{"crackweb v", "guaidao2 & coolmoon", "github.com/guaidao2/crackweb"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output is missing %q:\n%s", want, stdout)
		}
	}
}

func TestCommandHelpListsItsOptions(t *testing.T) {
	cases := []struct {
		command  string
		contains []string
	}{
		{"proxy", []string{"crackweb proxy", "--listen", "-l,", "--upstream", "--scope", "--passive-only"}},
		{"crawl", []string{"crackweb crawl", "-u,", "--url", "--depth", "--engine", "--max-pages"}},
		{"scan", []string{"crackweb scan", "-u,", "-r,", "--raw", "--checks", "-o,"}},
		{"oob", []string{"crackweb oob", "--dns", "--http", "--token", "--domain"}},
		{"ca", []string{"crackweb ca", "--out", "--force"}},
	}

	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			code, stdout, _ := run(t, tc.command, "--help")
			if code != ExitOK {
				t.Fatalf("exit code = %d, want %d", code, ExitOK)
			}
			for _, want := range tc.contains {
				if !strings.Contains(stdout, want) {
					t.Errorf("%s help is missing %q:\n%s", tc.command, want, stdout)
				}
			}
			// The command's own options must not be labelled as the global ones.
			if strings.Contains(stdout, "GLOBAL OPTIONS") {
				t.Errorf("%s help labels its own options as global:\n%s", tc.command, stdout)
			}
			if !strings.Contains(stdout, "OPTIONS") {
				t.Errorf("%s help has no options heading:\n%s", tc.command, stdout)
			}
		})
	}
}

func TestUnknownCommandFailsWithUsage(t *testing.T) {
	code, _, stderr := run(t, "frobnicate")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "frobnicate") {
		t.Errorf("stderr does not name the bad command:\n%s", stderr)
	}
}

func TestUnknownOptionFailsWithUsage(t *testing.T) {
	code, _, stderr := run(t, "proxy", "--nonsense")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "--nonsense") {
		t.Errorf("stderr does not name the bad option:\n%s", stderr)
	}
}

func TestOptionValueForms(t *testing.T) {
	// "--name value" and "--name=value" must both parse. An unknown check name
	// must be refused rather than quietly scanning nothing.
	code, _, stderr := run(t, "scan", "-u", "http://127.0.0.1:1", "--checks=no-such-check")
	if code != ExitUsage {
		t.Errorf("unknown check: exit code = %d, want %d (stderr: %s)", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, "no-such-check") {
		t.Errorf("stderr does not name the unknown check:\n%s", stderr)
	}

	code, _, stderr = run(t, "crawl", "-u", "http://127.0.0.1:1", "--depth", "notanumber")
	if code != ExitUsage {
		t.Errorf("bad integer: exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "--depth") {
		t.Errorf("stderr does not name the option:\n%s", stderr)
	}
}

func TestMissingOptionValueFails(t *testing.T) {
	code, _, stderr := run(t, "proxy", "--listen")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "--listen") {
		t.Errorf("stderr does not name the option:\n%s", stderr)
	}
}

func TestScanRequiresATarget(t *testing.T) {
	code, _, stderr := run(t, "scan")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "-u/--url") {
		t.Errorf("stderr does not explain what is missing:\n%s", stderr)
	}
}

func TestBadLanguageIsRejected(t *testing.T) {
	code, _, stderr := run(t, "--lang", "klingon", "--help")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "klingon") {
		t.Errorf("stderr does not name the bad language:\n%s", stderr)
	}
}

func TestLanguageNeedsAValue(t *testing.T) {
	code, _, stderr := run(t, "--lang")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "--lang") {
		t.Errorf("stderr does not name the option:\n%s", stderr)
	}
}

// TestListChecksDoesNotRunAScan covers the one command path that reaches the
// check registry without touching the network. The long-running commands
// (proxy, crawl, scan against a live target) are exercised end to end in their
// own packages, where a listener can be started and torn down in-process.
func TestListChecksDoesNotRunAScan(t *testing.T) {
	for _, command := range []string{"scan", "crawl", "proxy"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, _ := run(t, command, "--list-checks")
			if code != ExitOK {
				t.Fatalf("exit code = %d, want %d", code, ExitOK)
			}
			for _, want := range []string{"sqli-error", "xss-reflected", "passive-security-headers"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("%s --list-checks does not mention %s:\n%s", command, want, stdout)
				}
			}
		})
	}
}

// TestCommandsValidateBeforeStarting checks that the guard clauses fire before
// anything is bound or fetched: a bad invocation must fail fast, not hang.
func TestCommandsValidateBeforeStarting(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"crawl without a URL", []string{"crawl"}, "-u/--url"},
		{"crawl with a bad engine", []string{"crawl", "-u", "http://127.0.0.1:1", "--engine", "telepathy"}, "telepathy"},
		{"scan without a target", []string{"scan"}, "-u/--url"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := run(t, tc.args...)
			if code != ExitUsage {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, ExitUsage, stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr does not mention %q:\n%s", tc.want, stderr)
			}
		})
	}
}

// TestHelpIsTranslatedConsistently checks that both catalogues describe the same
// set of commands, so a command added to one language cannot go missing in the
// other.
func TestHelpIsTranslatedConsistently(t *testing.T) {
	commands := []string{"proxy", "crawl", "scan", "oob", "ca"}

	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			_, stdout, _ := run(t, "--lang", lang, "--help")
			for _, name := range commands {
				if !strings.Contains(stdout, name) {
					t.Errorf("%s help does not list the %q command:\n%s", lang, name, stdout)
				}
			}
		})
	}
}

// TestContainerCommandHelpListsItsSubjects covers the defect this test was added for: `local`
// carries its work in subcommands and has no options of its own, so its help rendered a usage
// line and nothing else — the one thing a reader needs was the one thing missing.
func TestContainerCommandHelpListsItsSubjects(t *testing.T) {
	for _, args := range [][]string{{"local", "--help"}, {"local"}} {
		_, stdout, _ := run(t, args...)

		for _, want := range []string{"jwt", "hash"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%v: the subject %q is not listed:\n%s", args, want, stdout)
			}
		}
		// A subject has to be described, not merely named.
		if !strings.Contains(stdout, "JSON Web Token") {
			t.Errorf("%v: the subjects carry no description:\n%s", args, stdout)
		}
	}
}

// TestSubjectHelpIsTheSubjectsOwn is the other half: asking a subject for help must show the
// options that subject takes, not the ones its parent has.
func TestSubjectHelpIsTheSubjectsOwn(t *testing.T) {
	_, jwtHelp, _ := run(t, "local", "jwt", "--help")
	if !strings.Contains(jwtHelp, "--forge") || !strings.Contains(jwtHelp, "--wordlist") {
		t.Errorf("local jwt --help does not list its own options:\n%s", jwtHelp)
	}

	_, hashHelp, _ := run(t, "local", "hash", "--help")
	if !strings.Contains(hashHelp, "--wordlist") {
		t.Errorf("local hash --help does not list its options:\n%s", hashHelp)
	}
	// The hash subject has no use for a signing key, so it must not advertise one.
	if strings.Contains(hashHelp, "--forge") {
		t.Errorf("local hash --help shows an option that belongs to jwt:\n%s", hashHelp)
	}
}
