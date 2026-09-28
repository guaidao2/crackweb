// Package payload turns a small set of hand-written attack strings into a large
// family of equivalent variations.
//
// The problem it solves: a scanner that ships fixed payloads —
// `' OR 1=1--`, `<script>alert(1)</script>`, `../../etc/passwd` — is detected by
// any signature-based WAF on the first request, and its coverage against a
// target that filters anything is close to zero. That is not a payload problem,
// it is an architecture problem: the payload has to be *derived* from what the
// target accepts, not looked up.
//
// So a payload here is a seed plus a set of mutators that preserve its meaning
// while changing its bytes. The mutators are grouped by what they exploit:
//
//   - encoding   — the request is decoded more than once on the way in
//   - syntax     — the parser accepts whitespace, comments and casing that a
//     signature does not anticipate
//   - structure  — the transport or the parameter itself can be reshaped
//
// Variants are ordered by "generation": generation 0 is the plain seed,
// generation 1 applies one mutator, generation 2 two, and so on. A check walks
// up the generations only when the target refuses what it is given, so an
// unprotected target costs one request per seed and a heavily filtered one gets
// the full grammar.
package payload

import (
	"strings"
)

// Kind is a class of vulnerability. Mutators declare which kinds they make
// sense for, so a SQLi variant never gets a JavaScript-only transformation.
type Kind string

// Vulnerability kinds.
const (
	SQLi      Kind = "sqli"
	XSS       Kind = "xss"
	Traversal Kind = "traversal"
	Command   Kind = "command"
	SSTI      Kind = "ssti"
	NoSQL     Kind = "nosql"
	XXE       Kind = "xxe"
	Redirect  Kind = "redirect"
	CRLF      Kind = "crlf"
	// HostHeader covers checks that attack a request header rather than a value.
	HostHeader Kind = "host-header"
	Generic    Kind = "generic"
)

// Mutator rewrites a payload without changing what it means to the target.
//
// Apply must be idempotent-safe and cheap: variants are generated on demand,
// and a mutator that returns the input unchanged is simply skipped.
type Mutator struct {
	// Name identifies the transformation in evidence and logs.
	Name string
	// Kinds are the vulnerability classes it applies to. An empty list means
	// every class.
	Kinds []Kind
	// Excludes names classes this mutator must not touch, even when Kinds would
	// allow them.
	//
	// It exists because "still equivalent" is class-specific. Turning `<` into
	// `&#60;` produces the same bytes a browser renders as text — which is
	// exactly what makes markup harmless. A transformation that neutralises a
	// payload is not an evasion, it is self-defeat, so entity and hex encoding
	// are excluded from XSS.
	Excludes []Kind
	// Family groups mutators that should not be combined with each other,
	// because they would fight: applying both "space to comment" and "space to
	// tab" produces nothing useful.
	Family string
	// Weight orders mutators within a generation. Lower runs first, so the
	// cheapest and most broadly useful transformations are attempted before
	// exotic ones.
	Weight int
	// ProducesEncoded marks a mutator whose output is already in transport form
	// — percent-encoded — and must therefore not be encoded again. Everything
	// else emits an ordinary string that still needs encoding before it can sit
	// in a URL or a form body.
	ProducesEncoded bool
	// Apply performs the rewrite.
	Apply func(string) string
}

// matches reports whether a mutator applies to a kind.
func (m Mutator) matches(kind Kind) bool {
	for _, k := range m.Excludes {
		if k == kind {
			return false
		}
	}
	if len(m.Kinds) == 0 {
		return true
	}
	for _, k := range m.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// replaceAll is a mutator body that rewrites substrings.
func replaceAll(from, to string) func(string) string {
	return func(s string) string { return strings.ReplaceAll(s, from, to) }
}

// mapChars rewrites each occurrence of a character, optionally only when it
// appears outside quotes, which is what keeps a transformation from corrupting
// the literal parts of a payload.
func mapChars(replacements map[byte]string) func(string) string {
	return func(s string) string {
		var b strings.Builder
		b.Grow(len(s) + 8)
		inQuote := byte(0)
		for i := 0; i < len(s); i++ {
			c := s[i]
			if inQuote != 0 {
				b.WriteByte(c)
				if c == inQuote {
					inQuote = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				inQuote = c
				b.WriteByte(c)
				continue
			}
			if replacement, ok := replacements[c]; ok {
				b.WriteString(replacement)
				continue
			}
			b.WriteByte(c)
		}
		return b.String()
	}
}

// alternateCase flips the case of alphabetic runs, which defeats a signature
// that matches a keyword literally while staying valid to a case-insensitive
// parser.
func alternateCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'a' || c > 'z' {
			if c < 'A' || c > 'Z' {
				b.WriteByte(c)
				continue
			}
		}
		if upper {
			b.WriteString(strings.ToUpper(string(c)))
		} else {
			b.WriteString(strings.ToLower(string(c)))
		}
		upper = !upper
	}
	return b.String()
}

// insertInKeyword splits a SQL keyword with a comment, which keeps it valid SQL
// while breaking a literal match. `SELECT` becomes `SEL/**/ECT`.
func insertInKeyword(keyword, insertion string) func(string) string {
	return func(s string) string {
		if len(keyword) < 3 {
			return s
		}
		split := len(keyword) / 2
		broken := keyword[:split] + insertion + keyword[split:]
		// Replace case-insensitively, preserving nothing: the target's parser
		// does not care, and a signature does.
		var b strings.Builder
		lower := strings.ToLower(s)
		needle := strings.ToLower(keyword)
		for {
			idx := strings.Index(lower, needle)
			if idx < 0 {
				b.WriteString(s)
				break
			}
			b.WriteString(s[:idx])
			b.WriteString(broken)
			s = s[idx+len(keyword):]
			lower = lower[idx+len(keyword):]
		}
		return b.String()
	}
}
