package active

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// decodedViews returns a body as it is, plus the forms it takes when a long run inside it is an
// encoding of something else.
//
// A target can read a file perfectly well and then print what it read through base64 or hex —
// a logger, a JSON field, a page that treats the content as a blob. The read happened; the
// signature is simply not in the clear. Looking only at the body as it stands reports that
// target as defended, which is the quiet kind of failure: no error, no finding, nothing to
// notice.
//
// The runs are bounded so an ordinary page cannot be mistaken for an encoding of something:
// a candidate has to be long, and what it decodes to has to look like text. Without that, every
// body is "an encoding" of some byte sequence, and any byte sequence can contain anything.
const (
	encodedRunMinimum = 40
	decodedTextRatio  = 0.9
	// encodedViewLimit bounds how many runs of one body are decoded. A page can carry several long
	// runs — a session token, an inline image, a data URI — and the content a target read need not
	// be the longest of them. Every view costs a signature scan, so the longest few are decoded.
	encodedViewLimit = 4
)

func decodedViews(body []byte) []string {
	text := string(body)
	views := []string{text}
	views = append(views, decodeRuns(text, isBase64Char, decodeBase64Candidate)...)
	views = append(views, decodeRuns(text, isHexChar, decodeHexCandidate)...)
	return views
}

// decodeBase64Candidate decodes one run when it is base64 at all.
func decodeBase64Candidate(run string) ([]byte, bool) {
	// Padding is only valid at the end and the length has to be a multiple of four, so a run
	// that fails those is not base64 of anything — it is a word that happens to use the
	// alphabet.
	if len(run)%4 != 0 {
		if trimmed := strings.TrimRight(run, "="); len(trimmed)%4 != 1 {
			if padded := trimmed + strings.Repeat("=", (4-len(trimmed)%4)%4); len(padded)%4 == 0 {
				run = padded
			}
		}
	}
	out, err := base64.StdEncoding.DecodeString(run)
	return out, err == nil
}

// decodeHexCandidate decodes one run when it is hex at all.
func decodeHexCandidate(run string) ([]byte, bool) {
	if len(run)%2 != 0 {
		run = run[:len(run)-1]
	}
	out, err := hex.DecodeString(run)
	return out, err == nil
}

// decodeRuns decodes the longest runs of characters the predicate accepts, longest first, and
// returns the ones that decode to text. The caller's decoder decides whether a run means anything.
//
// More than one run is decoded because the content a target read need not be the largest run on the
// page: a form carrying a captcha beside an inclusion would otherwise hide the smaller one.
func decodeRuns(text string, accept func(byte) bool, decode func(string) ([]byte, bool)) []string {
	var longest []string
	offer := func(run string) {
		if len(run) < encodedRunMinimum {
			return
		}
		// Keep the longest few, in order, without sorting what a large page can hold: a body of
		// five megabytes holds a hundred thousand runs that qualify.
		position := len(longest)
		for index, existing := range longest {
			if len(run) > len(existing) {
				position = index
				break
			}
		}
		if position >= encodedViewLimit {
			return
		}
		longest = append(longest, "")
		copy(longest[position+1:], longest[position:])
		longest[position] = run
		if len(longest) > encodedViewLimit {
			longest = longest[:encodedViewLimit]
		}
	}

	current := strings.Builder{}
	for i := 0; i < len(text); i++ {
		if accept(text[i]) {
			current.WriteByte(text[i])
			continue
		}
		offer(current.String())
		current.Reset()
	}
	offer(current.String())

	views := make([]string, 0, len(longest))
	for _, run := range longest {
		decoded, ok := decode(run)
		if !ok || len(decoded) < encodedRunMinimum/2 || !looksLikeText(decoded) {
			continue
		}
		views = append(views, string(decoded))
	}
	return views
}

func isBase64Char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '='
}

func isHexChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// looksLikeText is the bound that keeps a page from being read as an encoding of itself.
func looksLikeText(decoded []byte) bool {
	if len(decoded) == 0 {
		return false
	}
	printable := 0
	for _, b := range decoded {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(decoded)) >= decodedTextRatio
}
