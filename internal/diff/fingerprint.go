package diff

import (
	"hash/fnv"
	"math"
	"math/bits"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// MaxAnalyzeBytes bounds the body that takes part in similarity measurement.
// Everything beyond it still counts towards length.
const MaxAnalyzeBytes = 512 << 10

// MaxKeepText bounds the normalised text retained for diff display.
const MaxKeepText = 64 << 10

// Fingerprint is a response reduced to the features worth comparing.
type Fingerprint struct {
	// Status is the HTTP status code.
	Status int
	// Location is the redirect target, which is the whole signal when redirects
	// are not followed.
	Location string
	// ContentType is the response media type.
	ContentType string
	// RawLen is the raw body length.
	RawLen int
	// NormLen is the length after normalisation.
	NormLen int
	// NormText is the normalised text, possibly truncated.
	NormText string
	// NormHash hashes NormText, for the "byte-identical" fast path.
	NormHash uint64
	// SimHashText hashes the number-masked text, used for very short bodies.
	SimHashText uint64
	// Binary marks content that is not worth text comparison.
	Binary bool
	// LineCount is the number of lines after normalisation.
	LineCount int
	// Trigrams counts character trigrams, for cosine and Jaccard similarity.
	Trigrams map[uint32]int
	// SimHash is the SimHash fingerprint of the normalised text.
	SimHash uint64
	// Title is the HTML title.
	Title string
	// Keywords holds the labels of sensitive patterns that matched.
	Keywords map[string]struct{}
	// Echoed holds the injected values that were reflected back.
	Echoed []string
	// Elapsed is how long the request took.
	Elapsed time.Duration
	// Truncated records that the body was cut short.
	Truncated bool
	// Err carries a request failure, if there was one.
	Err string
}

// BuildFingerprint reduces a response to a comparable fingerprint.
//
// echoPairs is a flat pattern, replacement, pattern, replacement… list used to
// restore reflected injected values to their baseline form; when detectOnly is
// set the reflections are recorded instead of replaced.
func BuildFingerprint(resp *httpmsg.Response, n *Normalizer, keywords []Keyword, echoPairs []string, detectOnly bool) *Fingerprint {
	if resp == nil {
		return &Fingerprint{Err: "no response"}
	}
	f := &Fingerprint{
		Status:      resp.Status,
		RawLen:      len(resp.Body),
		Elapsed:     resp.Duration,
		Truncated:   resp.Truncated,
		ContentType: resp.Header.Get("Content-Type"),
		Location:    resp.Header.Get("Location"),
	}
	if f.Location == "" && resp.FinalURL != "" {
		// Without a Location field the landing URL is the only trace of a
		// redirect, and it is a strong signal in its own right.
		f.Location = resp.FinalURL
	}
	f.Binary = IsBinaryContentType(f.ContentType)

	body := resp.Body
	if len(body) > MaxAnalyzeBytes {
		body = body[:MaxAnalyzeBytes]
	}
	text := string(body)
	if !utf8.ValidString(text) {
		f.Binary = true
	}

	if f.Binary {
		f.NormText = ""
		f.NormLen = 0
		f.NormHash = hash64(string(resp.Body[:min(len(resp.Body), 4096)]))
		f.SimHashText = f.NormHash
		f.Keywords = matchKeywords(text, keywords)
		return f
	}

	norm, echoed := n.NormalizeEcho(body, echoPairs, detectOnly)
	f.Echoed = echoed
	f.NormLen = len(norm)
	f.NormHash = hash64(norm)
	f.NormText = norm
	if len(norm) > MaxKeepText {
		f.NormText = norm[:MaxKeepText]
	}
	// Similarity runs on the number-masked text so that counters, offsets and
	// random ids do not read as content changes. A genuine change in a number's
	// magnitude still shows up through the length comparison.
	simText := maskNumbers(norm, minMaskDigits)
	f.SimHashText = hash64(simText)
	f.Trigrams, f.SimHash, f.LineCount = gramStats(simText)
	f.Title = extractTitle(text)
	f.Keywords = matchKeywords(text, keywords)
	return f
}

// BuildErrorFingerprint represents a request that never produced a response.
func BuildErrorFingerprint(err error) *Fingerprint {
	if err == nil {
		return &Fingerprint{}
	}
	return &Fingerprint{Err: err.Error(), NormHash: hash64(err.Error())}
}

// hash64 hashes a string with FNV-1a.
func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// gramStats computes character-trigram counts and a SimHash over them.
func gramStats(s string) (map[uint32]int, uint64, int) {
	runes := []rune(s)
	grams := make(map[uint32]int, len(runes))
	var weights [64]int

	add := func(g string) {
		h32 := fnv.New32a()
		_, _ = h32.Write([]byte(g))
		grams[h32.Sum32()]++
		h64 := fnv.New64a()
		_, _ = h64.Write([]byte(g))
		v := h64.Sum64()
		for i := 0; i < 64; i++ {
			if v&(1<<uint(i)) != 0 {
				weights[i]++
			} else {
				weights[i]--
			}
		}
	}

	switch {
	case len(runes) == 0:
		return grams, 0, 0
	case len(runes) < 3:
		add(string(runes))
	default:
		for i := 0; i+3 <= len(runes); i++ {
			add(string(runes[i : i+3]))
		}
	}

	var sh uint64
	for i := 0; i < 64; i++ {
		if weights[i] > 0 {
			sh |= 1 << uint(i)
		}
	}
	lines := 0
	if s != "" {
		lines = strings.Count(s, "\n") + 1
	}
	return grams, sh, lines
}

// minMaskDigits is the shortest digit run masked in the similarity text.
const minMaskDigits = 4

// maskNumbers replaces digit runs of at least minLen characters with <N>.
// It only affects similarity measurement: lengths, displayed diffs and keyword
// matching all keep the original digits.
func maskNumbers(s string, minLen int) string {
	hasDigit := false
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c < '0' || c > '9' {
			b.WriteByte(c)
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j-i >= minLen {
			b.WriteString("<N>")
		} else {
			b.WriteString(s[i:j])
		}
		i = j
	}
	return b.String()
}

// titleRe finds the document title.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle pulls the HTML title out of a body.
func extractTitle(html string) string {
	if len(html) > MaxAnalyzeBytes {
		html = html[:MaxAnalyzeBytes]
	}
	m := titleRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.Join(strings.Fields(m[1]), " ")
}

// matchKeywords returns the labels of every keyword present in text.
func matchKeywords(text string, keywords []Keyword) map[string]struct{} {
	if len(keywords) == 0 || text == "" {
		return nil
	}
	lower := strings.ToLower(text)
	out := make(map[string]struct{})
	for _, k := range keywords {
		if k.Text == "" {
			continue
		}
		if strings.Contains(lower, k.Text) {
			label := k.Label
			if label == "" {
				label = k.Text
			}
			out[label] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Similarity holds the individual similarity measures between two fingerprints.
type Similarity struct {
	// Score is the weighted overall similarity, 0 to 1.
	Score float64
	// Cosine is the character-trigram cosine similarity.
	Cosine float64
	// Jaccard is the Jaccard similarity of the trigram sets.
	Jaccard float64
	// SimHash is the similarity derived from the SimHash Hamming distance.
	SimHash float64
	// NormLenDelta is the change in normalised length.
	NormLenDelta int
	// RawLenDelta is the change in raw length.
	RawLenDelta int
	// RawLenRatio is that change as a fraction of the baseline.
	RawLenRatio float64
}

// CompareFingerprints measures how similar two fingerprints are.
func CompareFingerprints(base, cur *Fingerprint) *Similarity {
	s := &Similarity{
		NormLenDelta: cur.NormLen - base.NormLen,
		RawLenDelta:  cur.RawLen - base.RawLen,
	}
	if base.RawLen > 0 {
		s.RawLenRatio = float64(s.RawLenDelta) / float64(base.RawLen)
	}

	if base.Binary || cur.Binary {
		// Binary bodies carry no usable text similarity; status and length
		// decide, and equal lengths are treated as identical.
		if base.RawLen == cur.RawLen {
			s.Score, s.Cosine, s.Jaccard, s.SimHash = 1, 1, 1, 1
		}
		return s
	}

	switch {
	case base.NormLen == 0 && cur.NormLen == 0:
		s.Score, s.Cosine, s.Jaccard, s.SimHash = 1, 1, 1, 1
		return s
	case base.NormLen == 0 || cur.NormLen == 0:
		return s
	}

	// Trigrams are not meaningful on very short bodies; compare the masked text
	// exactly instead.
	if base.NormLen < 32 || cur.NormLen < 32 {
		if base.SimHashText == cur.SimHashText {
			s.Score, s.Cosine, s.Jaccard, s.SimHash = 1, 1, 1, 1
		}
		return s
	}

	s.Cosine = cosine(base.Trigrams, cur.Trigrams)
	s.Jaccard = jaccard(base.Trigrams, cur.Trigrams)
	s.SimHash = 1 - float64(bits.OnesCount64(base.SimHash^cur.SimHash))/64
	s.Score = 0.5*s.Cosine + 0.2*s.Jaccard + 0.3*s.SimHash
	return s
}

func cosine(a, b map[uint32]int) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	dot, na, nb := 0.0, 0.0, 0.0
	for k, v := range a {
		na += float64(v * v)
		if w, ok := b[k]; ok {
			dot += float64(v * w)
		}
	}
	for _, v := range b {
		nb += float64(v * v)
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / math.Sqrt(na*nb)
}

func jaccard(a, b map[uint32]int) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}
