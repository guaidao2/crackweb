package active

import (
	"strings"
	"testing"
)

// TestErrorSignaturesCoverTheEnginesOwnWords: the messages a database prints today, as opposed
// to the wrapper spellings above them in the list. Each is a sentence an ordinary page has no
// reason to contain, which is what makes it usable as evidence when it is new to the response.
func TestErrorSignaturesCoverTheEnginesOwnWords(t *testing.T) {
	cases := map[string]string{
		"PostgreSQL": `ERROR: syntax error at or near "'"`,
		"SQL Server": "Incorrect syntax near '1'.",
		"MySQL":      "Unknown column 'x' in 'where clause'",
		"SQLite":     "no such table: users",
	}
	for engine, body := range cases {
		lower := strings.ToLower(body)
		if firstNewSignature(lower, "rows: 0", sqlErrorSignatures) == "" {
			t.Errorf("%s: its own error message was not recognised: %q", engine, body)
		}
	}
}

// TestErrorSignaturesIgnoreAPageThatAlreadySaidIt: the message has to be new. A page that
// mentions one of these phrases in its ordinary text is not a page that was broken by a probe.
func TestErrorSignaturesIgnoreAPageThatAlreadySaidIt(t *testing.T) {
	body := strings.ToLower("Documentation: a query can fail with no such table: users")
	if got := firstNewSignature(body, body, sqlErrorSignatures); got != "" {
		t.Errorf("a phrase already in the baseline was counted as new: %q", got)
	}
}
