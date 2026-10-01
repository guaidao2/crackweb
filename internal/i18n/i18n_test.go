package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// keysDeclaredInSource parses keys.go and returns every Key constant it
// declares. Deriving the list from the source instead of a hand-maintained
// slice means a newly added key can never silently escape the completeness
// checks below.
func keysDeclaredInSource(t *testing.T) []Key {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "keys.go", nil, 0)
	if err != nil {
		t.Fatalf("parse keys.go: %v", err)
	}

	var keys []Key
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			ident, ok := value.Type.(*ast.Ident)
			if !ok || ident.Name != "Key" {
				continue
			}
			if len(value.Values) != 1 {
				continue
			}
			lit, ok := value.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("unquote %s: %v", lit.Value, err)
			}
			keys = append(keys, Key(text))
		}
	}
	if len(keys) == 0 {
		t.Fatal("no Key constants found in keys.go")
	}
	return keys
}

// TestEveryKeyIsTranslated is the guard rail that keeps the two catalogues from
// drifting apart: every declared key must exist in English and in Chinese.
func TestEveryKeyIsTranslated(t *testing.T) {
	for _, key := range keysDeclaredInSource(t) {
		for _, lang := range []Lang{EN, ZH} {
			if _, ok := catalogueFor(lang)[key]; !ok {
				t.Errorf("key %q is missing from the %s catalogue", key, lang)
			}
		}
	}
}

// TestNoOrphanTranslations catches the opposite mistake: entries that stay
// behind after a key is renamed or removed.
func TestNoOrphanTranslations(t *testing.T) {
	declared := keysDeclaredInSource(t)
	known := make(map[Key]struct{}, len(declared))
	for _, key := range declared {
		known[key] = struct{}{}
	}

	for _, lang := range []Lang{EN, ZH} {
		for key := range catalogueFor(lang) {
			if _, ok := known[key]; !ok {
				t.Errorf("%s catalogue defines %q, which keys.go does not declare", lang, key)
			}
		}
	}
}

// TestFormatVerbsMatch ensures a translation uses the same printf verbs as the
// English original. Without this, a placeholder dropped while translating shows
// up as a stray "%!s(MISSING)" in the middle of a scan.
func TestFormatVerbsMatch(t *testing.T) {
	reference := catalogueFor(EN)
	for key, want := range reference {
		got, ok := catalogueFor(ZH)[key]
		if !ok {
			continue // reported by TestEveryKeyIsTranslated
		}
		if a, b := formatVerbs(want), formatVerbs(got); a != b {
			t.Errorf("key %q: verb mismatch\n  en: %s\n  zh: %s", key, a, b)
		}
	}
}

// formatVerbs renders the ordered printf verbs of a format string, e.g.
// "invalid value %q for %s: %s" -> "%q %s %s".
//
// Order matters and duplicates are kept: T fills its arguments positionally, so
// a translation that reorders or drops a verb would print the wrong value in
// the wrong slot. That is exactly the mistake this check exists to catch.
func formatVerbs(format string) string {
	var verbs []string
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		if i >= len(format) {
			break
		}
		if format[i] == '%' { // literal percent
			continue
		}
		verbs = append(verbs, "%"+string(format[i]))
	}
	return strings.Join(verbs, " ")
}

func TestParseLang(t *testing.T) {
	cases := []struct {
		in    string
		want  Lang
		match bool
	}{
		{"en", EN, true},
		{"EN", EN, true},
		{"english", EN, true},
		{"en_US.UTF-8", EN, true},
		{"en-GB", EN, true},
		{"zh", ZH, true},
		{"ZH", ZH, true},
		{"zh_CN.UTF-8", ZH, true},
		{"zh-CN", ZH, true},
		{"zh-Hans-CN", ZH, true},
		{"cn", ZH, true},
		{"chinese", ZH, true},
		{"", "", false},
		{"fr", "", false},
		{"C.UTF-8", "", false},
		{"POSIX", "", false},
	}

	for _, tc := range cases {
		got, ok := ParseLang(tc.in)
		if ok != tc.match || (ok && got != tc.want) {
			t.Errorf("ParseLang(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.match)
		}
	}
}

func TestDetect(t *testing.T) {
	// Neutralise the ambient locale so the test is deterministic on any host.
	clearLocale(t)

	cases := []struct {
		name     string
		explicit string
		env      map[string]string
		want     Lang
	}{
		{"default is English", "", nil, EN},
		{"explicit wins", "zh", map[string]string{"CRACKWEB_LANG": "en"}, ZH},
		{"CRACKWEB_LANG", "", map[string]string{"CRACKWEB_LANG": "zh"}, ZH},
		{"explicit junk falls through", "klingon", map[string]string{"CRACKWEB_LANG": "zh"}, ZH},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearLocale(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if got := Detect(tc.explicit); got != tc.want {
				t.Errorf("Detect(%q) with %v = %q, want %q", tc.explicit, tc.env, got, tc.want)
			}
		})
	}
}

// TestDetectIgnoresLocale pins the contract that matters to users: a Chinese
// LC_ALL or LANG does not change the output language on its own. Switching to
// Chinese is always an explicit act — --lang zh, or CRACKWEB_LANG=zh.
func TestDetectIgnoresLocale(t *testing.T) {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Run(key, func(t *testing.T) {
			clearLocale(t)
			t.Setenv(key, "zh_CN.UTF-8")

			if got := Detect(""); got != EN {
				t.Errorf("Detect(\"\") with %s=zh_CN.UTF-8 = %q, want %q", key, got, EN)
			}
		})
	}
}

// clearLocale blanks the environment variables Detect consults.
func clearLocale(t *testing.T) {
	t.Helper()
	for _, key := range []string{"CRACKWEB_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(key, "")
	}
}

func TestBundleFallsBackToEnglish(t *testing.T) {
	b := New(Lang("fr")) // unsupported: must degrade to the default catalogue
	if b.Lang() != EN {
		t.Fatalf("New(fr).Lang() = %q, want %q", b.Lang(), EN)
	}
	if got, want := b.T(KeyAppTagline), english[KeyAppTagline]; got != want {
		t.Errorf("fallback tagline = %q, want %q", got, want)
	}
}

func TestBundleMissingKeyReturnsKey(t *testing.T) {
	b := New(EN)
	const missing Key = "does.not.exist"
	if got := b.T(missing); got != string(missing) {
		t.Errorf("T(%q) = %q, want the key itself", missing, got)
	}
}

func TestBundleFormatsOnlyWithArguments(t *testing.T) {
	b := New(EN)

	// With no arguments the message is passed through verbatim, so a literal
	// percent in translated text can never be mangled.
	raw := "100% safe"
	b.msgs[KeyAppTagline] = raw
	if got := b.T(KeyAppTagline); got != raw {
		t.Errorf("T() with no args = %q, want %q", got, raw)
	}

	// With arguments it behaves as a format string.
	b.msgs[KeyAppTagline] = "hello %s"
	if got, want := b.T(KeyAppTagline, "world"), "hello world"; got != want {
		t.Errorf("T() with args = %q, want %q", got, want)
	}
}

func TestChineseCatalogueIsReachable(t *testing.T) {
	b := New(ZH)
	if b.Lang() != ZH {
		t.Fatalf("New(ZH).Lang() = %q, want %q", b.Lang(), ZH)
	}
	if !b.Has(KeyAppTagline) {
		t.Fatal("Chinese catalogue is missing the tagline")
	}
	if got := b.T(KeyAppTagline); got == english[KeyAppTagline] {
		t.Error("Chinese tagline is identical to the English one — is the translation wired up?")
	}
}

// TestMain guards against the test binary itself leaking a locale into Detect.
func TestMain(m *testing.M) {
	for _, key := range []string{"CRACKWEB_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		os.Unsetenv(key)
	}
	os.Exit(m.Run())
}

// TestFormattedTemplatesMatchWhatTheCallersPass catches the class of defect a reader sees as a
// raw format verb in the report: a template written `%.3f` while the caller passes a string that
// was already formatted, which renders as `%!f(string=0.9)`.
//
// The checks format similarities with strconv before handing them to the bundle, so any template
// that expects a float and receives that string is a bug in one of the two. This renders each
// template that names a float verb with the value a caller actually passes.
func TestFormattedTemplatesMatchWhatTheCallersPass(t *testing.T) {
	// What the callers pass for a similarity: strconv.FormatFloat(v, 'f', 3, 64).
	formatted := strconv.FormatFloat(0.9, 'f', 3, 64)

	for _, b := range []*Bundle{New(EN), New(ZH)} {
		got := b.T(KeyEvidenceBoolean, formatted, formatted, formatted)
		if strings.Contains(got, "%!") {
			t.Errorf("KeyEvidenceBoolean renders a format mismatch: %s", got)
		}
		if !strings.Contains(got, "0.900") {
			t.Errorf("KeyEvidenceBoolean lost the value it was given: %s", got)
		}
		// The CSRF evidence takes a percentage as a float, so it keeps its float verb.
		if cs := b.T(KeyEvidenceCSRF, "csrf", "x", 88.0); strings.Contains(cs, "%!") {
			t.Errorf("KeyEvidenceCSRF renders a format mismatch: %s", cs)
		}
	}
}
