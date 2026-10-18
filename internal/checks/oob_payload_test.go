package checks

import (
	"net/url"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// TestOOBPayloadEncodingFollowsTheLocation keeps the callback URL intact where the
// request is not percent-decoded. A JSON string carrying an encoded URL reaches the
// application as a literal percent sequence, so the fetch never happens and a real
// blind SSRF is reported as a clean target.
func TestOOBPayloadEncodingFollowsTheLocation(t *testing.T) {
	value := "http://192.0.2.10:8081/ab12/x?y=1"

	for _, location := range []httpmsg.ParamLocation{
		httpmsg.LocQuery, httpmsg.LocBody, httpmsg.LocCookie, httpmsg.LocMultipartFilename,
	} {
		param := httpmsg.Param{In: location}
		got, ok := oobPayloadFor(param, value, 0)
		if !ok || got != url.QueryEscape(value) {
			t.Errorf("%s layer 0 = %q (ok=%v), want one round of encoding", location, got, ok)
		}
		if got, ok := oobPayloadFor(param, value, 1); !ok || got != url.QueryEscape(url.QueryEscape(value)) {
			t.Errorf("%s layer 1 = %q (ok=%v), want two rounds", location, got, ok)
		}
	}

	for _, location := range []httpmsg.ParamLocation{
		httpmsg.LocJSON, httpmsg.LocJSONBase64, httpmsg.LocMultipart,
	} {
		param := httpmsg.Param{In: location}
		got, ok := oobPayloadFor(param, value, 0)
		if !ok || got != value {
			t.Errorf("%s layer 0 = %q (ok=%v), want the value unchanged", location, got, ok)
		}
		if got, ok := oobPayloadFor(param, value, 1); ok {
			t.Errorf("%s layer 1 = %q, want no second layer for a structured body", location, got)
		}
	}
}

// TestOOBPayloadEncodingKeepsCookieAndFilenameValuesLegal: a Cookie value and a
// multipart filename are header-shaped fields. A raw newline — which several
// command-injection seeds carry — makes net/http reject the request outright, so those
// values keep the single round of encoding they always had.
func TestOOBPayloadEncodingKeepsCookieAndFilenameValuesLegal(t *testing.T) {
	value := "; sleep 3\nnslookup callback.example"
	for _, location := range []httpmsg.ParamLocation{httpmsg.LocCookie, httpmsg.LocMultipartFilename} {
		param := httpmsg.Param{In: location}
		got, ok := oobPayloadFor(param, value, 0)
		if !ok || strings.ContainsAny(got, "\r\n") {
			t.Errorf("%s = %q, want a value with no raw newline", location, got)
		}
	}
}

// TestOOBPayloadEncodingForAWrappedParameter: the field lives inside a document carried
// as another parameter, and the envelope writer escapes it. Encoding it here puts a
// percent sequence inside the document, where nothing looks for a URL.
func TestOOBPayloadEncodingForAWrappedParameter(t *testing.T) {
	param := httpmsg.Param{In: httpmsg.LocQuery, Wrapper: httpmsg.WrapJSON}
	value := "http://192.0.2.10:8081/ab12"

	if got, ok := oobPayloadFor(param, value, 0); !ok || got != value {
		t.Errorf("wrapped layer 0 = %q (ok=%v), want the value unchanged", got, ok)
	}
	if got, ok := oobPayloadFor(param, value, 1); ok {
		t.Errorf("wrapped layer 1 = %q, want no encoding layer", got)
	}
}
