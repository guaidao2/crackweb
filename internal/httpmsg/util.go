package httpmsg

import (
	"strconv"
	"strings"
)

// mediaType strips the parameters from a Content-Type value and lower-cases the
// result: "text/HTML; charset=utf-8" -> "text/html".
func mediaType(value string) string {
	if i := strings.IndexByte(value, ';'); i >= 0 {
		value = value[:i]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// parseInt parses a non-negative-ish integer field such as Content-Length,
// tolerating surrounding whitespace.
func parseInt(value string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(value))
}

// isInlineWhitespace reports whether b is a space or a horizontal tab.
func isInlineWhitespace(b byte) bool { return b == ' ' || b == '\t' }

// isHeaderFolded reports whether a header line is a continuation (obs-fold) of
// the previous field.
func isHeaderFolded(line string) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}
