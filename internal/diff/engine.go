package diff

import (
	"sort"
	"strings"

	"github.com/guaidao2/crackweb/internal/i18n"
)

// Thresholds are the tolerances that decide when a response counts as changed.
type Thresholds struct {
	// Sim is the similarity floor: below it, content has changed.
	Sim float64
	// LenPct is the fractional length tolerance.
	LenPct float64
	// LenAbs is an absolute byte floor for the length tolerance, so that tiny
	// responses are not judged on a percentage alone.
	LenAbs int
}

// ThresholdsForSensitivity maps a 1–5 sensitivity level onto thresholds.
// Higher is more sensitive: more differences are reported, and more false
// positives come with them.
func ThresholdsForSensitivity(level int) Thresholds {
	switch level {
	case 1:
		return Thresholds{Sim: 0.90, LenPct: 0.10, LenAbs: 64}
	case 2:
		return Thresholds{Sim: 0.94, LenPct: 0.05, LenAbs: 32}
	case 4:
		return Thresholds{Sim: 0.985, LenPct: 0.01, LenAbs: 8}
	case 5:
		return Thresholds{Sim: 0.997, LenPct: 0.005, LenAbs: 1}
	default:
		return Thresholds{Sim: 0.96, LenPct: 0.02, LenAbs: 16}
	}
}

// ReasonCode identifies why two responses were judged different.
type ReasonCode string

// Reason codes.
const (
	ReasonStatus       ReasonCode = "status"
	ReasonRedirect     ReasonCode = "redirect"
	ReasonTitle        ReasonCode = "title"
	ReasonLength       ReasonCode = "length"
	ReasonBinaryLength ReasonCode = "binary-length"
	ReasonContent      ReasonCode = "content"
	ReasonKeyword      ReasonCode = "keyword"
	ReasonEmpty        ReasonCode = "empty"
	ReasonType         ReasonCode = "type"
	ReasonError        ReasonCode = "error"
	ReasonEcho         ReasonCode = "echo"
	ReasonNoBaseline   ReasonCode = "no-baseline"
)

// reasonMessageKeys maps a reason code to the catalogue key of its detail text.
var reasonMessageKeys = map[ReasonCode]i18n.Key{
	ReasonStatus:       i18n.KeyDiffReasonStatus,
	ReasonRedirect:     i18n.KeyDiffReasonRedirect,
	ReasonTitle:        i18n.KeyDiffReasonTitle,
	ReasonLength:       i18n.KeyDiffReasonLength,
	ReasonBinaryLength: i18n.KeyDiffReasonBinaryLen,
	ReasonContent:      i18n.KeyDiffReasonContent,
	ReasonKeyword:      i18n.KeyDiffReasonKeyword,
	ReasonEmpty:        i18n.KeyDiffReasonEmpty,
	ReasonType:         i18n.KeyDiffReasonType,
	ReasonError:        i18n.KeyDiffReasonError,
	ReasonEcho:         i18n.KeyDiffReasonEcho,
	ReasonNoBaseline:   i18n.KeyDiffReasonNoBaseline,
}

// reasonCaptionKeys maps a reason code to the catalogue key of its short name.
var reasonCaptionKeys = map[ReasonCode]i18n.Key{
	ReasonStatus:       i18n.KeyDiffCodeStatus,
	ReasonRedirect:     i18n.KeyDiffCodeRedirect,
	ReasonTitle:        i18n.KeyDiffCodeTitle,
	ReasonLength:       i18n.KeyDiffCodeLength,
	ReasonBinaryLength: i18n.KeyDiffCodeLength,
	ReasonContent:      i18n.KeyDiffCodeContent,
	ReasonKeyword:      i18n.KeyDiffCodeKeyword,
	ReasonEmpty:        i18n.KeyDiffCodeEmpty,
	ReasonType:         i18n.KeyDiffCodeType,
	ReasonError:        i18n.KeyDiffCodeError,
	ReasonEcho:         i18n.KeyDiffCodeEcho,
	ReasonNoBaseline:   i18n.KeyDiffCodeNoBaseline,
}

// Reason is one way in which a response differed, carrying its arguments so the
// text can be rendered in the user's language at display time rather than
// baked in at detection time.
type Reason struct {
	Code ReasonCode
	// Level rates the strength of the signal: 1 slight, 2 clear, 3 strong.
	Level int
	// Args are the values interpolated into the message template.
	Args []any
}

// MessageKey returns the catalogue key for this reason's detail text.
func (r Reason) MessageKey() i18n.Key {
	if k, ok := reasonMessageKeys[r.Code]; ok {
		return k
	}
	return i18n.Key("diff.reason." + string(r.Code))
}

// CaptionKey returns the catalogue key for this reason's short name.
func (r Reason) CaptionKey() i18n.Key {
	if k, ok := reasonCaptionKeys[r.Code]; ok {
		return k
	}
	return i18n.Key("diff.code." + string(r.Code))
}

// Message renders the detail text.
func (r Reason) Message(b *i18n.Bundle) string { return b.T(r.MessageKey(), r.Args...) }

// Caption renders the short name.
func (r Reason) Caption(b *i18n.Bundle) string { return b.T(r.CaptionKey()) }

// Verdict is the outcome of comparing a response against a baseline.
type Verdict struct {
	// Different reports a genuine, meaningful change.
	Different bool
	// Score is the overall similarity, 0 to 1.
	Score float64
	// Reasons lists why, strongest first.
	Reasons []Reason
	// Level is the strongest reason's level.
	Level int
	// Sim holds the individual similarity measures.
	Sim *Similarity
}

// Summary renders the reason captions as a comma-separated line.
func (v *Verdict) Summary(b *i18n.Bundle) string {
	if v == nil || len(v.Reasons) == 0 {
		return b.T(i18n.KeyDiffNone)
	}
	parts := make([]string, 0, len(v.Reasons))
	for _, r := range v.Reasons {
		parts = append(parts, r.Caption(b))
	}
	return strings.Join(parts, ", ")
}

// Detail renders the full reason texts, joined.
func (v *Verdict) Detail(b *i18n.Bundle) string {
	if v == nil || len(v.Reasons) == 0 {
		return ""
	}
	parts := make([]string, 0, len(v.Reasons))
	for _, r := range v.Reasons {
		parts = append(parts, r.Message(b))
	}
	return strings.Join(parts, "; ")
}

// Engine decides whether a response differs from its baseline.
type Engine struct {
	// TH holds the tolerances.
	TH Thresholds
	// Keywords is the sensitive-pattern table.
	Keywords []Keyword
	// IgnoreStatus excludes status-code changes from the verdict.
	IgnoreStatus bool
	// IgnoreLength excludes length changes.
	IgnoreLength bool
	// IgnoreKeyword excludes sensitive-keyword hits.
	IgnoreKeyword bool
	// DetectReflection treats a reflected injected value as a signal in its own
	// right, which is what reflective-XSS detection wants.
	DetectReflection bool
}

// NewEngine builds a judgement engine.
func NewEngine(th Thresholds, keywords []Keyword) *Engine {
	return &Engine{TH: th, Keywords: keywords}
}

// Judge compares cur against base and reports what changed.
func (e *Engine) Judge(base, cur *Fingerprint) *Verdict {
	if base == nil {
		return &Verdict{Reasons: []Reason{{Code: ReasonNoBaseline, Level: 1}}}
	}
	if cur == nil {
		return &Verdict{Score: 1}
	}

	v := &Verdict{Score: 1}
	sim := CompareFingerprints(base, cur)
	v.Sim = sim
	v.Score = sim.Score

	// A failed request is not a page difference. It only matters as an
	// observation when the baseline succeeded.
	if cur.Err != "" {
		if base.Err == "" {
			v.Reasons = append(v.Reasons, Reason{Code: ReasonError, Level: 1, Args: []any{cur.Err}})
		}
		return v
	}
	if base.Err != "" {
		v.Reasons = append(v.Reasons, Reason{Code: ReasonError, Level: 1, Args: []any{base.Err}})
		return v
	}

	// Fast path: byte-identical normalised content with the same status and
	// redirect target cannot be a finding.
	if base.Status == cur.Status && base.Location == cur.Location &&
		base.NormHash == cur.NormHash && !base.Binary && !cur.Binary {
		return v
	}

	if base.Status != cur.Status && !e.IgnoreStatus {
		lvl := 3
		if base.Status/100 == cur.Status/100 {
			lvl = 2
		}
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonStatus, Level: lvl,
			Args: []any{base.Status, cur.Status},
		})
	}

	if base.Location != cur.Location {
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonRedirect, Level: 3,
			Args: []any{base.Location, cur.Location},
		})
	}

	if base.Binary != cur.Binary {
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonType, Level: 3,
			Args: []any{base.ContentType, cur.ContentType},
		})
	}

	if base.Title != "" && cur.Title != "" && base.Title != cur.Title {
		v.Reasons = append(v.Reasons, Reason{
			Code: ReasonTitle, Level: 2,
			Args: []any{clip(base.Title, 60), clip(cur.Title, 60)},
		})
	}

	if !e.IgnoreLength {
		if r, ok := e.lengthReason(base, cur); ok {
			v.Reasons = append(v.Reasons, r)
		}
	}

	if !base.Binary && !cur.Binary {
		if base.NormLen > 0 && cur.NormLen == 0 {
			v.Reasons = append(v.Reasons, Reason{Code: ReasonEmpty, Level: 3})
		} else if sim.Score < e.TH.Sim {
			lvl := 2
			if sim.Score < 0.5 {
				lvl = 3
			}
			v.Reasons = append(v.Reasons, Reason{
				Code: ReasonContent, Level: lvl,
				Args: []any{sim.Score, e.TH.Sim},
			})
		}
	}

	if !e.IgnoreKeyword {
		if kw := newKeywords(base.Keywords, cur.Keywords); len(kw) > 0 {
			v.Reasons = append(v.Reasons, Reason{
				Code: ReasonKeyword, Level: 3,
				Args: []any{strings.Join(kw, ", ")},
			})
		}
	}

	if e.DetectReflection {
		if added := newStrings(base.Echoed, cur.Echoed); len(added) > 0 {
			v.Reasons = append(v.Reasons, Reason{
				Code: ReasonEcho, Level: 2,
				Args: []any{strings.Join(clipAll(added, 3), ", ")},
			})
		}
	}

	sort.SliceStable(v.Reasons, func(i, j int) bool { return v.Reasons[i].Level > v.Reasons[j].Level })
	v.Different = len(v.Reasons) > 0
	for _, r := range v.Reasons {
		if r.Level > v.Level {
			v.Level = r.Level
		}
	}
	return v
}

// lengthReason measures the length change, handling binary bodies separately
// because their normalised length is always zero.
func (e *Engine) lengthReason(base, cur *Fingerprint) (Reason, bool) {
	if base.Binary || cur.Binary {
		if base.RawLen == cur.RawLen {
			return Reason{}, false
		}
		delta := cur.RawLen - base.RawLen
		lvl := 2
		if base.RawLen > 0 && absInt(delta)*2 > base.RawLen {
			lvl = 3
		}
		return Reason{
			Code: ReasonBinaryLength, Level: lvl,
			Args: []any{base.RawLen, cur.RawLen, delta},
		}, true
	}

	delta := cur.NormLen - base.NormLen
	tol := int(float64(base.NormLen) * e.TH.LenPct)
	if tol < e.TH.LenAbs {
		tol = e.TH.LenAbs
	}
	if absInt(delta) <= tol {
		return Reason{}, false
	}
	lvl := 2
	if base.NormLen > 0 && float64(absInt(delta))/float64(base.NormLen) > 0.5 {
		lvl = 3
	}
	return Reason{
		Code: ReasonLength, Level: lvl,
		Args: []any{base.NormLen, cur.NormLen, delta, base.RawLen, cur.RawLen},
	}, true
}

// newKeywords returns the keyword labels present in cur but not in base.
func newKeywords(base, cur map[string]struct{}) []string {
	if len(cur) == 0 {
		return nil
	}
	var out []string
	for k := range cur {
		if _, ok := base[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// newStrings returns the values present in cur but not in base, preserving order.
func newStrings(base, cur []string) []string {
	if len(cur) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(base))
	for _, s := range base {
		seen[s] = struct{}{}
	}
	var out []string
	for _, s := range cur {
		if _, ok := seen[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}

// clipAll shortens a list to n entries for display.
func clipAll(in []string, n int) []string {
	out := make([]string, 0, len(in))
	for i, s := range in {
		if i >= n {
			out = append(out, "…")
			break
		}
		out = append(out, clip(s, 40))
	}
	return out
}

// clip shortens a string to n runes.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
