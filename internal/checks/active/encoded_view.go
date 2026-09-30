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
)

func decodedViews(body []byte) []string {
	text := string(body)
	views := []string{text}
	if decoded, ok := decodeLongRun(text, isBase64Char, func(run string) ([]byte, bool) {
		// Padding is only valid at the end and the length has to be a multiple of four, so a
		// run that fails those is not base64 of anything — it is a word that happens to use
		// the alphabet.
		if len(run)%4 != 0 {
			if trimmed := strings.TrimRight(run, "="); len(trimmed)%4 != 1 {
				if padded := trimmed + strings.Repeat("=", (4-len(trimmed)%4)%4); len(padded)%4 == 0 {
					run = padded
				}
			}
		}
		out, err := base64.StdEncoding.DecodeString(run)
		return out, err == nil
	}); ok {
		views = append(views, string(decoded))
	}
	if decoded, ok := decodeLongRun(text, isHexChar, func(run string) ([]byte, bool) {
		if len(run)%2 != 0 {
			run = run[:len(run)-1]
		}
		out, err := hex.DecodeString(run)
		return out, err == nil
	}); ok {
		views = append(views, string(decoded))
	}
	return views
}

// decodeLongRun finds the longest run of characters the predicate accepts, decodes it, and
// returns the result when it looks like text. It is the caller's decoder that decides whether
// the run means anything at all.
func decodeLongRun(text string, accept func(byte) bool, decode func(string) ([]byte, bool)) ([]byte, bool) {
	best, current := 0, strings.Builder{}
	bestRun := ""
	flush := func() {
		run := current.String()
		if len(run) > best {
			best, bestRun = len(run), run
		}
		current.Reset()
	}
	for i := 0; i < len(text); i++ {
		if accept(text[i]) {
			current.WriteByte(text[i])
			continue
		}
		flush()
	}
	flush()
	if len(bestRun) < encodedRunMinimum {
		return nil, false
	}
	decoded, ok := decode(bestRun)
	if !ok || len(decoded) < encodedRunMinimum/2 {
		return nil, false
	}
	if !looksLikeText(decoded) {
		return nil, false
	}
	return decoded, true
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
