package active

import (
	"strings"
	"testing"
	"time"
)

// TestSQLiTimeCoversBothQuotingContexts pins the pair of shapes a delay payload
// needs, because only one of them used to exist.
//
// Measured on a real target: in a numeric parameter `1' AND SLEEP(5)-- -` is a
// syntax error the database answers in a millisecond, while `1 AND SLEEP(5)`
// pauses for the five seconds it asked for. A check whose every seed opens with a
// quote therefore could not see a numeric time-based injection at all — it
// reported the syntax error as "no delay" and moved on.
func TestSQLiTimeCoversBothQuotingContexts(t *testing.T) {
	const (
		quoted = iota
		bare
	)
	seen := map[int]string{}
	for _, item := range sqliTimingSuffixes {
		if !strings.Contains(item.suffix, "SLEEP(") &&
			!strings.Contains(item.suffix, "pg_sleep(") &&
			!strings.Contains(item.suffix, "BENCHMARK(") {
			continue
		}
		kind := bare
		if strings.HasPrefix(strings.TrimSpace(item.suffix), "'") {
			kind = quoted
		}
		seen[kind] = item.suffix
	}
	if _, ok := seen[quoted]; !ok {
		t.Error("no quoted delay payload: a string parameter would never be seen")
	}
	if _, ok := seen[bare]; !ok {
		t.Error("no unquoted delay payload: a numeric parameter would never be seen")
	}

	// SQLite has no sleep primitive at all, so work has to stand in for it.
	work := false
	for _, item := range sqliTimingSuffixes {
		if strings.Contains(item.suffix, "RANDOMBLOB(") {
			work = true
		}
	}
	if !work {
		t.Error("no work-based delay payload: a SQLite target would never be seen")
	}
}

// TestSQLiUnionCoversBothQuotingContexts is the same requirement for the union
// check: the arm without a leading quote is what a numeric parameter needs, and
// the quoted one is what a string parameter needs. Whichever is missing, half the
// targets are invisible.
func TestSQLiUnionCoversBothQuotingContexts(t *testing.T) {
	var quoted, bare bool
	for _, seed := range unionSeeds() {
		switch {
		case strings.HasPrefix(seed, "1' UNION SELECT "):
			quoted = true
		case strings.HasPrefix(seed, "1 UNION SELECT "):
			bare = true
		}
	}
	if !quoted {
		t.Error("no quoted UNION arm: a string parameter would never be seen")
	}
	if !bare {
		t.Error("no unquoted UNION arm: a numeric parameter would never be seen")
	}
}

// TestTimeSuffixesReachTheOrderByPosition: the sort parameter takes an expression but not a
// quoted string, so a suffix that opens with a quote is a syntax error there and an `AND` has
// nothing to attach to. Without a suffix built for that position the check was blind to a
// time-based injection it can otherwise measure perfectly well.
func TestTimeSuffixesReachTheOrderByPosition(t *testing.T) {
	var wanted string
	for _, item := range sqliTimingSuffixes {
		if strings.Contains(item.suffix, "(SELECT SLEEP(") && !strings.Contains(item.suffix, "'") {
			wanted = item.suffix
			break
		}
	}
	if wanted == "" {
		t.Fatal("no suffix is written for a position that takes an expression rather than a string")
	}
	// The parameter's own value is kept in front, which is what makes the term an addition to
	// the list the caller supplied rather than the whole of it.
	payloads := sqliTimePayloadsFor("desc")
	for _, p := range payloads {
		if p.payload == "desc"+wanted {
			if p.delay < time.Second {
				t.Errorf("the sort-position suffix asks for %v, which is not worth measuring", p.delay)
			}
			return
		}
	}
	t.Errorf("the suffix %q was not built with the parameter's own value in front", wanted)
}

// TestTimeSuffixesStillOpenWithAQuoteForStringPositions guards the other half: the sort-position
// spellings must not have replaced the ones a quoted parameter needs.
func TestTimeSuffixesStillOpenWithAQuoteForStringPositions(t *testing.T) {
	quoted := 0
	for _, item := range sqliTimingSuffixes {
		if strings.Contains(item.suffix, "SLEEP(") && strings.Contains(item.suffix, "'") {
			quoted++
		}
	}
	if quoted == 0 {
		t.Error("no suffix is written for a quoted string position")
	}
}
