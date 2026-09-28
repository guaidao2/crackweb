package diff

import "strings"

// Diff line kinds.
const (
	// LineRemoved marks a line present in the baseline but not in the result.
	LineRemoved byte = '-'
	// LineAdded marks a line new in the result.
	LineAdded byte = '+'
	// LineElided marks omitted output; Elided holds how many lines were cut.
	LineElided byte = '~'
)

// Line is one line of a text difference.
type Line struct {
	Kind byte
	Text string
	// Elided is the number of lines skipped, for LineElided.
	Elided int
}

// Text computes the difference between two normalised bodies as a multiset
// difference: first the lines that disappeared, then the lines that appeared.
//
// A line-aligned diff would be more familiar, but on HTML produced by templates
// it misaligns badly — one inserted line cascades into a wall of noise. The
// multiset form stays readable on exactly the pages a scanner has to cope with.
func Text(baseText, curText string, maxLines int) []Line {
	if baseText == curText {
		return nil
	}
	if maxLines <= 0 {
		maxLines = 40
	}
	baseLines := splitLines(baseText)
	curLines := splitLines(curText)

	removed := multisetDiff(baseLines, curLines)
	added := multisetDiff(curLines, baseLines)

	half := maxLines / 2
	if half < 1 {
		half = 1
	}

	out := make([]Line, 0, len(removed)+len(added)+2)
	appendSide := func(kind byte, lines []string) {
		limit := min(half, len(lines))
		for _, l := range lines[:limit] {
			out = append(out, Line{Kind: kind, Text: l})
		}
		if len(lines) > limit {
			out = append(out, Line{Kind: LineElided, Elided: len(lines) - limit})
		}
	}
	appendSide(LineRemoved, removed)
	appendSide(LineAdded, added)
	return out
}

// ChangedLineCount returns how many lines differ between the two texts.
func ChangedLineCount(baseText, curText string) int {
	baseLines := splitLines(baseText)
	curLines := splitLines(curText)
	return len(multisetDiff(baseLines, curLines)) + len(multisetDiff(curLines, baseLines))
}

// multisetDiff returns the lines of a that b does not have enough of, in order.
func multisetDiff(a, b []string) []string {
	if len(a) == 0 {
		return nil
	}
	avail := make(map[string]int, len(b))
	for _, l := range b {
		avail[l]++
	}
	var out []string
	for _, l := range a {
		if avail[l] > 0 {
			avail[l]--
			continue
		}
		out = append(out, l)
	}
	return out
}

// splitLines splits normalised text into non-empty, trimmed lines.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}
