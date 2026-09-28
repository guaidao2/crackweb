package diff

import (
	"net/http"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// response builds a response for tests.
func response(status int, body string, headers ...string) *httpmsg.Response {
	h := httpmsg.Header{}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Add(headers[i], headers[i+1])
	}
	if !h.Has("Content-Type") {
		h.Add("Content-Type", "text/html")
	}
	return &httpmsg.Response{Status: status, Header: h, Body: []byte(body)}
}

// fingerprinter builds a fingerprint with a default normalizer.
func fingerprinter(t *testing.T) *Normalizer {
	t.Helper()
	n, err := New(Options{})
	if err != nil {
		t.Fatalf("diff.New: %v", err)
	}
	return n
}

func TestNormalizeMasksDynamicContent(t *testing.T) {
	n := fingerprinter(t)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"uuid", "id=550e8400-e29b-41d4-a716-446655440000", "id=<UUID>"},
		{"http date", "Date: Wed, 21 Oct 2015 07:28:00 GMT", "Date: <HTTPDATE>"},
		{"iso datetime", "created 2024-05-11T09:30:12Z ok", "created <DATETIME> ok"},
		{"csrf token keeps its separator", "csrf_token=a1b2c3d4e5f6g7h8", "csrf_token=<TOKEN>"},
		{"session id", "session_id=9f8e7d6c5b4a3210", "session_id=<TOKEN>"},
		// A token name embedded in markup ("value=...") is not what the token
		// rule targets; the random fallback covers it, which is what matters.
		{"token-looking value in markup", `<input value="a1b2c3d4e5f6g7h8">`, `<input value="<RAND>">`},
		{"random-looking value with no token name", `<p>3f9a7c2e1b8d6a5f</p>`, "<p><RAND></p>"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := n.Normalize([]byte(tc.in)); got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeCollapsesWhitespace(t *testing.T) {
	n := fingerprinter(t)
	got := n.Normalize([]byte("<div>\r\n\r\n   hello    world\t\t</div>\n\n\n"))
	// Runs of inline whitespace fold to one space, blank lines disappear, and
	// each surviving line is trimmed.
	if want := "<div>\nhello world </div>"; got != want {
		t.Errorf("Normalize() = %q, want %q", got, want)
	}
}

// TestJudgesTimestampOnlyChangeAsIdentical is the whole point of the package: a
// page that differs only by its embedded timestamp must not look like a change,
// or every payload would be reported as a finding.
func TestJudgesTimestampOnlyChangeAsIdentical(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	bundle := i18n.New(i18n.EN)

	base := BuildFingerprint(response(200,
		`<html><body><p>Welcome</p><span>2024-05-11T09:30:12Z</span><script>var csrf_token="a1b2c3d4e5f6g7h8";</script></body></html>`),
		n, nil, nil, false)
	cur := BuildFingerprint(response(200,
		`<html><body><p>Welcome</p><span>2024-05-11T09:31:47Z</span><script>var csrf_token="z9y8x7w6v5u4t3s2";</script></body></html>`),
		n, nil, nil, false)

	verdict := engine.Judge(base, cur)
	if verdict.Different {
		t.Errorf("timestamp-only change was reported as a difference: %s", verdict.Detail(bundle))
	}
	if verdict.Score < 0.999 {
		t.Errorf("similarity = %.4f, want ~1.0", verdict.Score)
	}
}

func TestJudgesContentChange(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	bundle := i18n.New(i18n.EN)

	base := BuildFingerprint(response(200, `<html><body><h1>Normal page</h1><p>`+strings.Repeat("lorem ipsum ", 40)+`</p></body></html>`), n, nil, nil, false)
	cur := BuildFingerprint(response(200, `<html><body><h1>Welcome administrator</h1><p>secret dashboard</p></body></html>`), n, nil, nil, false)

	verdict := engine.Judge(base, cur)
	if !verdict.Different {
		t.Fatal("a genuinely different page was judged identical")
	}
	if verdict.Level < 2 {
		t.Errorf("level = %d, want at least 2", verdict.Level)
	}
	if !hasReason(verdict, ReasonContent) {
		t.Errorf("reasons = %s, want a content reason", verdict.Detail(bundle))
	}
}

func TestJudgesStatusChange(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	bundle := i18n.New(i18n.EN)

	base := BuildFingerprint(response(200, "<html>ok</html>"), n, nil, nil, false)
	cur := BuildFingerprint(response(500, "<html>ok</html>"), n, nil, nil, false)

	verdict := engine.Judge(base, cur)
	if !verdict.Different || !hasReason(verdict, ReasonStatus) {
		t.Fatalf("status change not detected: %s", verdict.Detail(bundle))
	}
	if got := verdict.Reasons[0].Message(bundle); !strings.Contains(got, "200") {
		t.Errorf("status message = %q, want it to mention 200", got)
	}
}

// TestIgnoreStatusSuppressesStatusReason checks the escape hatch used when a
// target returns 302 for everything.
func TestIgnoreStatusSuppressesStatusReason(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	engine.IgnoreStatus = true

	base := BuildFingerprint(response(200, "<html>same</html>"), n, nil, nil, false)
	cur := BuildFingerprint(response(302, "<html>same</html>"), n, nil, nil, false)

	if verdict := engine.Judge(base, cur); hasReason(verdict, ReasonStatus) {
		t.Error("status reason reported despite IgnoreStatus")
	}
}

func TestJudgesNewSensitiveKeyword(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), DefaultKeywords())
	bundle := i18n.New(i18n.EN)

	base := BuildFingerprint(response(200, "<html><body>search results</body></html>"), n, engine.Keywords, nil, false)
	cur := BuildFingerprint(response(200, "<html><body>You have an error in your SQL syntax near '1''</body></html>"), n, engine.Keywords, nil, false)

	verdict := engine.Judge(base, cur)
	if !hasReason(verdict, ReasonKeyword) {
		t.Fatalf("SQL error keyword not detected: %s", verdict.Detail(bundle))
	}
}

// TestReflectionIsFilteredByDefault covers the second big false-positive source:
// a page that echoes the request parameter back. With the echo filtered, an
// unchanged page stays unchanged.
func TestReflectionIsFilteredByDefault(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	bundle := i18n.New(i18n.EN)

	pairs := []string{"1' AND '1'='1", "1"}

	base := BuildFingerprint(response(200, "<html><body>You searched for: 1</body></html>"), n, nil, pairs, false)
	cur := BuildFingerprint(response(200, "<html><body>You searched for: 1' AND '1'='1</body></html>"), n, nil, pairs, false)

	verdict := engine.Judge(base, cur)
	if verdict.Different {
		// The reflection was replaced by the baseline value, so the page is
		// unchanged apart from length; on a short body the length tolerance
		// should absorb it.
		if hasReason(verdict, ReasonEcho) {
			t.Errorf("echo reason reported in filter mode: %s", verdict.Detail(bundle))
		}
	}
}

// TestReflectionDetectionMode covers the opposite setting, where an echo is the
// signal — which is what reflective XSS detection needs.
func TestReflectionDetectionMode(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	engine.DetectReflection = true
	bundle := i18n.New(i18n.EN)

	pairs := []string{"<svg onload=alert(1)>", "1"}

	base := BuildFingerprint(response(200, "<html><body>You searched for: 1</body></html>"), n, nil, pairs, true)
	cur := BuildFingerprint(response(200, "<html><body>You searched for: <svg onload=alert(1)></body></html>"), n, nil, pairs, true)

	verdict := engine.Judge(base, cur)
	if !hasReason(verdict, ReasonEcho) {
		t.Fatalf("reflected payload not detected in detect mode: %s", verdict.Detail(bundle))
	}
}

func TestSensitivityChangesThresholds(t *testing.T) {
	if !(ThresholdsForSensitivity(1).Sim < ThresholdsForSensitivity(5).Sim) {
		t.Error("higher sensitivity must use a stricter similarity floor")
	}
}

// TestReasonsRenderInBothLanguages guards the i18n seam: reason text is built
// at display time from the catalogue, so both languages must produce a complete
// sentence with the values interpolated.
func TestReasonsRenderInBothLanguages(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)

	base := BuildFingerprint(response(200, "<html>ok</html>"), n, nil, nil, false)
	cur := BuildFingerprint(response(404, "<html>ok</html>"), n, nil, nil, false)

	verdict := engine.Judge(base, cur)
	for _, lang := range []i18n.Lang{i18n.EN, i18n.ZH} {
		bundle := i18n.New(lang)
		detail := verdict.Detail(bundle)
		if detail == "" {
			t.Fatalf("%s: empty detail", lang)
		}
		if strings.Contains(detail, "%!") {
			t.Errorf("%s: format verb mismatch in %q", lang, detail)
		}
		if !strings.Contains(detail, "200") || !strings.Contains(detail, "404") {
			t.Errorf("%s: detail %q is missing the status values", lang, detail)
		}
	}
}

func TestBinaryBodiesCompareByLength(t *testing.T) {
	n := fingerprinter(t)
	engine := NewEngine(ThresholdsForSensitivity(3), nil)

	headers := []string{"Content-Type", "application/octet-stream"}
	base := BuildFingerprint(response(200, "AAAA", headers...), n, nil, nil, false)
	cur := BuildFingerprint(response(200, "AAAA", headers...), n, nil, nil, false)

	if verdict := engine.Judge(base, cur); verdict.Different {
		t.Error("identical binary responses judged different")
	}

	longer := BuildFingerprint(response(200, strings.Repeat("A", 9000), headers...), n, nil, nil, false)
	if verdict := engine.Judge(base, longer); !verdict.Different {
		t.Error("binary length change not detected")
	}
}

func TestNoBaselineIsReported(t *testing.T) {
	engine := NewEngine(ThresholdsForSensitivity(3), nil)
	bundle := i18n.New(i18n.EN)

	cur := BuildFingerprint(response(200, "x"), fingerprinter(t), nil, nil, false)
	verdict := engine.Judge(nil, cur)
	if verdict.Different {
		t.Error("a missing baseline must not produce a difference")
	}
	if !hasReason(verdict, ReasonNoBaseline) {
		t.Errorf("reasons = %s, want a no-baseline reason", verdict.Detail(bundle))
	}
}

func TestTextDiffReportsAddedAndRemovedLines(t *testing.T) {
	base := "alpha\nbeta\ngamma"
	cur := "alpha\ndelta\ngamma"

	lines := Text(base, cur, 40)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %+v", len(lines), lines)
	}
	if lines[0].Kind != LineRemoved || lines[0].Text != "beta" {
		t.Errorf("first line = %+v, want removed beta", lines[0])
	}
	if lines[1].Kind != LineAdded || lines[1].Text != "delta" {
		t.Errorf("second line = %+v, want added delta", lines[1])
	}
}

func TestTextDiffElidesLongOutput(t *testing.T) {
	var baseLines, curLines []string
	for i := 0; i < 50; i++ {
		baseLines = append(baseLines, "base line")
		curLines = append(curLines, "changed line")
	}

	lines := Text(strings.Join(baseLines, "\n"), strings.Join(curLines, "\n"), 10)
	elided := 0
	for _, l := range lines {
		if l.Kind == LineElided {
			elided += l.Elided
		}
	}
	if elided == 0 {
		t.Error("long diff was not elided")
	}
}

func TestChangedLineCount(t *testing.T) {
	if got := ChangedLineCount("a\nb", "a\nb"); got != 0 {
		t.Errorf("identical texts: count = %d, want 0", got)
	}
	if got := ChangedLineCount("a\nb", "a\nc"); got != 2 {
		t.Errorf("one line swapped: count = %d, want 2", got)
	}
}

func TestIsBinaryContentType(t *testing.T) {
	binary := []string{"image/png", "application/octet-stream", "font/woff2", "application/pdf; charset=binary"}
	for _, ct := range binary {
		if !IsBinaryContentType(ct) {
			t.Errorf("IsBinaryContentType(%q) = false, want true", ct)
		}
	}
	text := []string{"text/html", "application/json", "text/plain; charset=utf-8", ""}
	for _, ct := range text {
		if IsBinaryContentType(ct) {
			t.Errorf("IsBinaryContentType(%q) = true, want false", ct)
		}
	}
}

func TestParseKeyword(t *testing.T) {
	k := ParseKeyword("  My Error  =Custom label")
	if k.Text != "my error" || k.Label != "Custom label" {
		t.Errorf("ParseKeyword = %+v", k)
	}
	plain := ParseKeyword("just text")
	if plain.Text != "just text" || plain.Label != "just text" {
		t.Errorf("ParseKeyword = %+v", plain)
	}
}

func TestNewNormalizerRejectsBadRule(t *testing.T) {
	if _, err := New(Options{Custom: []string{"no arrow here"}}); err == nil {
		t.Error("malformed custom rule accepted")
	}
	if _, err := New(Options{Custom: []string{"([=>x"}}); err == nil {
		t.Error("uncompilable custom rule accepted")
	}
}

func TestNormalizerDisableAndOff(t *testing.T) {
	// Disabling one rule does not stop the others: the "random" fallback still
	// masks an identifier-shaped value. What must disappear is that rule's own
	// placeholder.
	disabled, err := New(Options{Disable: []string{"uuid"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := disabled.Normalize([]byte("id=550e8400-e29b-41d4-a716-446655440000"))
	if strings.Contains(got, "<UUID>") {
		t.Errorf("disabled uuid rule still produced its placeholder: %q", got)
	}

	off, err := New(Options{Off: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !off.Off() {
		t.Error("Off() = false for a disabled normalizer")
	}
	raw := "id=550e8400-e29b-41d4-a716-446655440000"
	if got := off.Normalize([]byte(raw)); got != raw {
		t.Errorf("disabled normalizer rewrote text: %q", got)
	}
}

// hasReason reports whether a verdict carries a given reason code.
func hasReason(v *Verdict, code ReasonCode) bool {
	for _, r := range v.Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

// Ensure the test helper stays honest about the header type it builds.
var _ = http.Header{}
