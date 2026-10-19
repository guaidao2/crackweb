package active

import (
	"strings"
	"testing"
)

func TestStripPayloadEchoRemovesPhpEscapedReflection(t *testing.T) {
	const sent = `test' OR '1'='1'-- -`
	body := `<p>search: test&#039; OR &#039;1&#039;=&#039;1&#039;-- -</p>`
	got := stripPayloadEcho(body, sent)
	if strings.Contains(got, "OR") || strings.Contains(got, "&#039;") {
		t.Fatalf("php-escaped payload survived stripping: %s", got)
	}
}
