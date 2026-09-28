package diff

import (
	"strings"
)

// Keyword is one sensitive-pattern rule. A keyword hit means the response
// contains something it should not: a database error, a stack trace, the
// contents of a system file.
//
// Labels are kept in English on purpose. They name technical artefacts that
// read the same in every language, and they end up in reports next to the raw
// evidence, where a literal match is more useful than a translation.
type Keyword struct {
	// Text is the literal to search for, matched case-insensitively.
	Text string
	// Label names the pattern in reports.
	Label string
}

// defaultKeywords is the built-in sensitive-pattern table, grouped by the kind
// of leak it indicates.
var defaultKeywords = []Keyword{
	// Database errors: the classic proof of SQL injection.
	{"you have an error in your sql syntax", "MySQL syntax error"},
	{"sql syntax", "SQL syntax error"},
	{"mysql_fetch", "MySQL function error"},
	{"mysqli_", "MySQLi error"},
	{"warning: mysql", "MySQL warning"},
	{"unclosed quotation mark", "Unclosed SQL quotation"},
	{"quoted string not properly terminated", "Unterminated SQL string"},
	{"odbc sql server driver", "SQL Server ODBC error"},
	{"microsoft ole db provider", "OLE DB error"},
	{"sqlstate[", "SQLSTATE error"},
	{"postgresql query failed", "PostgreSQL error"},
	{"pg_query()", "PostgreSQL error"},
	{"sqlite3.operationalerror", "SQLite error"},
	{"ora-", "Oracle error"},
	{"syntax error", "Syntax error"},
	// Application errors: stack traces and interpreter warnings that leak
	// internals and often mark a successful injection.
	{"traceback (most recent call last)", "Python traceback"},
	{"system.nullreferenceexception", ".NET exception"},
	{"java.lang.", "Java exception"},
	{"exception in thread", "Java thread exception"},
	{"at org.apache.", "Java stack frame"},
	{"stack trace", "Stack trace"},
	{"undefined index", "PHP undefined index"},
	{"undefined offset", "PHP undefined offset"},
	{"undefined variable", "PHP undefined variable"},
	{"parse error", "Parse error"},
	{"fatal error", "Fatal error"},
	{"notice:", "PHP notice"},
	{"template syntax error", "Template syntax error"},
	{"freemarker", "FreeMarker error"},
	{"jinja2", "Jinja2 error"},
	{"velocity", "Velocity error"},
	// File disclosure: proof of path traversal or local file inclusion.
	{"root:x:0:0", "/etc/passwd content"},
	{"daemon:x:1:1", "/etc/passwd content"},
	{"[boot loader]", "win.ini content"},
	{"for 16-bit app support", "win.ini content"},
	{"no such file or directory", "File not found error"},
	// Command execution: proof that a shell ran our payload.
	{"command not found", "Command execution output"},
	{"uid=0(", "Command execution output"},
	{"gid=0(", "Command execution output"},
	// Configuration and resource leaks.
	{"web-inf/web.xml", "Java configuration leak"},
	{".git/config", "Exposed Git repository"},
	{"index of /", "Directory listing"},
	{"access denied for user", "Database access denied"},
	{"xml parsing error", "XML parsing error"},
	{"internal server error", "Internal server error"},
}

// DefaultKeywords returns a copy of the built-in table.
func DefaultKeywords() []Keyword {
	out := make([]Keyword, len(defaultKeywords))
	copy(out, defaultKeywords)
	return out
}

// ParseKeyword parses a user keyword written as "text" or "text=label".
func ParseKeyword(spec string) Keyword {
	s := strings.TrimSpace(spec)
	if i := strings.Index(s, "="); i > 0 {
		return Keyword{Text: strings.ToLower(strings.TrimSpace(s[:i])), Label: strings.TrimSpace(s[i+1:])}
	}
	return Keyword{Text: strings.ToLower(s), Label: s}
}
