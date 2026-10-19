package active

import (
	"html"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/diff"
)

func restoreEcho(t *testing.T, page, sent, original string) string {
	t.Helper()
	var n diff.Normalizer
	got, _ := n.NormalizeEcho([]byte(page), echoRestore(sent, original), false)
	return got
}

func phpEscapeForTest(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#039;",
	).Replace(s)
}

func hexEscapeForTest(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#x22;",
		"'", "&#x27;",
	).Replace(s)
}

func doubleEscapeForTest(s string) string {
	return strings.ReplaceAll(phpEscapeForTest(s), "&", "&amp;")
}

func TestEchoRestoreRemovesPhpEscapedReflection(t *testing.T) {
	const original = "test"
	trueOne := `test' OR '1'='1'-- -`
	trueTwo := `test' OR '2'='2'-- -`
	page := func(value string) string {
		return `<input name="q" value="` + phpEscapeForTest(value) + `">找到 3 条结果`
	}

	one := restoreEcho(t, page(trueOne), trueOne, original)
	two := restoreEcho(t, page(trueTwo), trueTwo, original)
	baseline := restoreEcho(t, page(original), original, original)

	if one != two {
		t.Fatalf("two true payloads normalised differently:\n%s\n%s", one, two)
	}
	if one != baseline {
		t.Fatalf("reflected payload did not normalise to the baseline:\n%s\n%s", one, baseline)
	}
	if strings.Contains(one, "&#039;") || strings.Contains(one, "OR") {
		t.Fatalf("escaped payload survived normalisation: %s", one)
	}
}

func TestEchoRestoreRemovesGoEscapedReflection(t *testing.T) {
	const original = "test"
	trueOne := `test' OR '1'='1'-- -`
	trueTwo := `test' OR '2'='2'-- -`
	page := func(value string) string {
		return `<input name="q" value="` + html.EscapeString(value) + `">找到 3 条结果`
	}

	one := restoreEcho(t, page(trueOne), trueOne, original)
	two := restoreEcho(t, page(trueTwo), trueTwo, original)
	if one != two {
		t.Fatalf("two true payloads normalised differently:\n%s\n%s", one, two)
	}
	if strings.Contains(one, "&#39;") || strings.Contains(one, "OR") {
		t.Fatalf("escaped payload survived normalisation: %s", one)
	}
}

func TestEchoRestoreRemovesHexEscapedReflection(t *testing.T) {
	const original = "test"
	trueOne := `test' OR '1'='1'-- -`
	trueTwo := `test' OR '2'='2'-- -`
	page := func(value string) string {
		return `<input name="q" value="` + hexEscapeForTest(value) + `">找到 3 条结果`
	}

	one := restoreEcho(t, page(trueOne), trueOne, original)
	two := restoreEcho(t, page(trueTwo), trueTwo, original)
	if one != two {
		t.Fatalf("two true payloads normalised differently:\n%s\n%s", one, two)
	}
	if strings.Contains(one, "&#x27;") || strings.Contains(one, "OR") {
		t.Fatalf("escaped payload survived normalisation: %s", one)
	}
}

func TestEchoRestoreHandlesDoubleEncodedReflection(t *testing.T) {
	const original = "test"
	sent := `test' OR '1'='1'-- -`
	page := `<input name="q" value="` + doubleEscapeForTest(sent) + `">找到 3 条结果`

	got := restoreEcho(t, page, sent, original)
	if strings.Contains(got, "&amp;#039;") || strings.Contains(got, "OR") {
		t.Fatalf("double-encoded payload survived normalisation: %s", got)
	}
}

func TestEchoRestoreReturnsRawPair(t *testing.T) {
	const sent, original = `test' OR '1'='1`, "test"
	pairs := echoRestore(sent, original)
	if len(pairs) != 2 || pairs[0] != sent || pairs[1] != original {
		t.Fatalf("echoRestore = %v, want the raw payload and its original", pairs)
	}
}
