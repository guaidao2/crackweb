// Package diff is crackweb's response-difference engine.
//
// The problem it solves: a web page that carries a timestamp, a CSRF token or a
// random session id looks "different" on every single request. A scanner that
// compares responses naively therefore either reports everything — burying the
// real findings — or reports nothing. This package normalises the dynamic noise
// away first, restores reflected parameter values to their baseline, and only
// then measures how much of the response actually changed.
package diff

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule is one normalisation rule: a pattern whose matches are replaced with a
// stable placeholder. A rule may use a function instead when deciding what to
// replace needs more than a regex.
type Rule struct {
	Name string
	Re   *regexp.Regexp
	Repl string
	Fn   func(string) string
}

// defaultRules removes content that changes on every response but carries no
// meaning. Each rule targets one class of noise seen in real traffic.
var defaultRules = []Rule{
	{Name: "uuid", Re: regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), Repl: "<UUID>"},
	{Name: "httpdate", Re: regexp.MustCompile(`(?i)\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+[A-Z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT\b`), Repl: "<HTTPDATE>"},
	{Name: "datetime", Re: regexp.MustCompile(`\b\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:[T ]\d{1,2}:\d{2}(?::\d{2})?)?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`), Repl: "<DATETIME>"},
	{Name: "time", Re: regexp.MustCompile(`\b\d{1,2}:\d{2}:\d{2}\b`), Repl: "<TIME>"},
	{Name: "epochms", Re: regexp.MustCompile(`\b1\d{12}\b`), Repl: "<TS>"},
	{Name: "token", Re: regexp.MustCompile(`(?i)(csrf[-_]?token|xsrf[-_]?token|authenticity[-_]?token|requestverificationtoken|csrfmiddlewaretoken|session[-_]?id|jsessionid|phpsessid|nonce|access[-_]?token|bearer)(["']?\s*[:=]{1,2}\s*["']?)[A-Za-z0-9._+/=%\-]{6,}`), Repl: "${1}${2}<TOKEN>"},
	{Name: "hex", Re: regexp.MustCompile(`\b[0-9a-fA-F]{20,}\b`), Repl: "<HEX>"},
	{Name: "base64", Re: regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`), Repl: "<B64>"},
	{Name: "random", Fn: maskRandomTokens},
	{Name: "longnum", Re: regexp.MustCompile(`\b\d{14,}\b`), Repl: "<NUM>"},
}

// numbersRule is opt-in: it masks every number, which suits pages full of
// counters and offsets but destroys real signal elsewhere.
var numbersRule = Rule{
	Name: "numbers",
	Re:   regexp.MustCompile(`\b\d+\b`),
	Repl: "<N>",
}

// Normalizer rewrites a response body into a comparison-stable form.
type Normalizer struct {
	rules []Rule
	off   bool
}

// DefaultRuleNames returns the names of the built-in rules.
func DefaultRuleNames() []string {
	out := make([]string, 0, len(defaultRules))
	for _, r := range defaultRules {
		out = append(out, r.Name)
	}
	return out
}

// ParseRule compiles a user rule written as "regex=>replacement".
func ParseRule(spec string) (Rule, error) {
	idx := strings.Index(spec, "=>")
	if idx < 0 {
		return Rule{}, fmt.Errorf("normalisation rule %q is malformed: want \"regex=>replacement\"", spec)
	}
	pattern := strings.TrimSpace(spec[:idx])
	repl := spec[idx+2:]
	if pattern == "" {
		return Rule{}, fmt.Errorf("normalisation rule %q has an empty pattern", spec)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("normalisation rule %q does not compile: %w", spec, err)
	}
	return Rule{Name: "custom:" + pattern, Re: re, Repl: repl}, nil
}

// Options configures a Normalizer.
type Options struct {
	// Custom rules, written as "regex=>replacement".
	Custom []string
	// Disable lists built-in rule names to skip.
	Disable []string
	// Numbers also masks plain numbers.
	Numbers bool
	// Off disables normalisation entirely, degenerating to a raw comparison.
	Off bool
}

// New builds a Normalizer from options.
func New(opts Options) (*Normalizer, error) {
	n := &Normalizer{off: opts.Off}
	if opts.Off {
		return n, nil
	}
	disabled := make(map[string]struct{}, len(opts.Disable))
	for _, d := range opts.Disable {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			disabled[d] = struct{}{}
		}
	}
	for _, r := range defaultRules {
		if _, skip := disabled[r.Name]; skip {
			continue
		}
		n.rules = append(n.rules, r)
	}
	if opts.Numbers {
		n.rules = append(n.rules, numbersRule)
	}
	for _, c := range opts.Custom {
		if strings.TrimSpace(c) == "" {
			continue
		}
		r, err := ParseRule(c)
		if err != nil {
			return nil, err
		}
		n.rules = append(n.rules, r)
	}
	return n, nil
}

// Off reports whether normalisation is disabled.
func (n *Normalizer) Off() bool { return n.off }

// MaxEchoBytes bounds the body scanned for reflected values. Larger responses
// are downloads, where a reflection cannot appear.
const MaxEchoBytes = 256 << 10

// Normalize rewrites a body into comparison-stable text.
func (n *Normalizer) Normalize(body []byte) string {
	s, _ := n.NormalizeEcho(body, nil, false)
	return s
}

// NormalizeEcho normalises a body and handles parameter reflection.
//
// Reflection is the second big source of false positives: many pages echo the
// parameter value straight back into the HTML, so every payload makes the page
// look different. Replacing the injected values with the baseline ones makes an
// echo look like the baseline again, so only a genuine structural change is
// reported. When detectOnly is set the values are recorded but not replaced,
// which is what a reflection-focused check wants.
//
// pairs is a flat list of pattern, replacement, pattern, replacement…, ordered
// longest-pattern-first by the caller so that a short pattern cannot pre-empt a
// longer one.
func (n *Normalizer) NormalizeEcho(body []byte, pairs []string, detectOnly bool) (string, []string) {
	s := string(body)
	if !n.off {
		for _, r := range n.rules {
			if r.Fn != nil {
				s = r.Fn(s)
				continue
			}
			s = r.Re.ReplaceAllString(s, r.Repl)
		}
	}
	var echoed []string
	if len(pairs) > 0 && len(s) <= MaxEchoBytes {
		for i := 0; i+1 < len(pairs); i += 2 {
			pat := pairs[i]
			if pat == "" {
				continue
			}
			if strings.Contains(s, pat) {
				echoed = append(echoed, pat)
			}
		}
		if !detectOnly {
			s = strings.NewReplacer(pairs...).Replace(s)
		}
	}
	return collapse(s), echoed
}

// collapse folds whitespace and drops blank lines, so that reflowed markup does
// not read as a content change.
func collapse(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	if !strings.ContainsAny(s, " \t\n") {
		return s
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		l := strings.TrimSpace(foldSpaces(line))
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// foldSpaces collapses runs of inline whitespace into one space.
func foldSpaces(s string) string {
	if !strings.ContainsAny(s, " \t") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		space = false
		b.WriteByte(c)
	}
	return b.String()
}

// randTokenRe matches "long words" that might be session identifiers.
var randTokenRe = regexp.MustCompile(`[A-Za-z0-9+/_=-]{16,}`)

// maskRandomTokens replaces session-identifier-shaped strings with a
// placeholder. The test is deliberately narrow — length alone is not enough —
// so that ordinary long words and URL path segments survive.
func maskRandomTokens(s string) string {
	if len(s) < 16 {
		return s
	}
	return randTokenRe.ReplaceAllStringFunc(s, func(tok string) string {
		if !looksRandom(tok) {
			return tok
		}
		return "<RAND>"
	})
}

// looksRandom reports whether a long token looks like an identifier: mixed
// character classes, and for tokens without digits, a substantial length.
func looksRandom(tok string) bool {
	var hasLower, hasUpper, hasDigit bool
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	kinds := 0
	for _, b := range []bool{hasLower, hasUpper, hasDigit} {
		if b {
			kinds++
		}
	}
	if hasDigit {
		return kinds >= 2
	}
	return len(tok) >= 24 && hasLower && hasUpper
}

// binaryTypes are content types that are never worth text comparison.
var binaryTypes = []string{
	"image/", "audio/", "video/", "font/",
	"application/octet-stream", "application/pdf", "application/zip",
	"application/x-gzip", "application/x-tar", "application/x-7z-compressed",
	"application/x-rar", "application/wasm", "application/x-font",
}

// IsBinaryContentType reports whether a Content-Type denotes binary content.
func IsBinaryContentType(ct string) bool {
	c := strings.ToLower(ct)
	if i := strings.Index(c, ";"); i >= 0 {
		c = c[:i]
	}
	c = strings.TrimSpace(c)
	for _, p := range binaryTypes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}
