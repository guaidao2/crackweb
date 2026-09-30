package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// redirectOnlySite answers like a shell that was given a command, but only the
// spellings that hide the space — `<` redirection, `$@` expansion, a pipe through
// `base64` — reach a file. The plain `; cat /etc/passwd` is echoed back without
// running, which is the target this check used to miss.
func redirectOnlySite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("ip")
		if value == "" {
			value = r.FormValue("ip")
		}
		read := strings.Contains(value, "cat<") ||
			strings.Contains(value, "passw$@d") ||
			strings.Contains(value, "passwd|base64") ||
			strings.Contains(value, "passwd |base64")
		switch {
		case read && strings.Contains(value, "base64"):
			fmt.Fprint(w, "<pre>cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=</pre>")
		case read:
			fmt.Fprint(w, "<pre>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n</pre>")
		default:
			fmt.Fprintf(w, "<pre>%s</pre>", value)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestCommandInjectionFiresThroughSpaceHidingSpellings: the file is reachable,
// and only through the spellings that avoid the space after the command name.
func TestCommandInjectionFiresThroughSpaceHidingSpellings(t *testing.T) {
	server := redirectOnlySite(t)
	h := newHarness(t)
	findings := withParameter(t, h, commandInjection{}, server.URL+"/ping?ip=127.0.0.1")
	if len(findings) == 0 {
		t.Fatal("a target that only answers the space-hiding spellings was not reported")
	}
	payload := findings[0].Payload
	if !strings.Contains(payload, "cat<") && !strings.Contains(payload, "$@") &&
		!strings.Contains(payload, "base64") {
		t.Errorf("payload = %q, want one of the new spellings", payload)
	}
}
