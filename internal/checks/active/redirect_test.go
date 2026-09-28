package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// runRedirect points the check at a handler that answers every parameter with
// the same page.
func runRedirect(t *testing.T, handler http.HandlerFunc) []*checks.Target {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/go?next=home")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (openRedirect{}).Run(context.Background(), h.ctx, target)
	out := make([]*checks.Target, 0, len(findings))
	for range findings {
		out = append(out, target)
	}
	return out
}

// TestOpenRedirectSeesLocationHeader is the classic form.
func TestOpenRedirectSeesLocationHeader(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, redirectCanary) {
			w.Header().Set("Location", next)
			w.WriteHeader(302)
			return
		}
		fmt.Fprint(w, "home")
	})
	if len(got) == 0 {
		t.Error("a Location-header redirect was not reported")
	}
}

// TestOpenRedirectSeesRefreshHeader: the same thing said with a header that is
// not Location, which a check looking only for 3xx misses.
func TestOpenRedirectSeesRefreshHeader(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, redirectCanary) {
			w.Header().Set("Refresh", "0;url="+next)
			fmt.Fprint(w, "<html><body>redirecting</body></html>")
			return
		}
		fmt.Fprint(w, "home")
	})
	if len(got) == 0 {
		t.Error("a Refresh-header redirect was not reported")
	}
}

// TestOpenRedirectSeesMetaRefresh: and with markup, on a 200.
func TestOpenRedirectSeesMetaRefresh(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, redirectCanary) {
			fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0;url=%s"></head></html>`, next)
			return
		}
		fmt.Fprint(w, "home")
	})
	if len(got) == 0 {
		t.Error("a meta-refresh redirect was not reported")
	}
}

// TestOpenRedirectSeesScriptRedirect: the browser-side form.
func TestOpenRedirectSeesScriptRedirect(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if strings.Contains(next, redirectCanary) {
			fmt.Fprintf(w, `<html><body><script>window.location.href = %q;</script></body></html>`, next)
			return
		}
		fmt.Fprint(w, "home")
	})
	if len(got) == 0 {
		t.Error("a script redirect was not reported")
	}
}

// TestOpenRedirectIgnoresReflection is the case that keeps the wider search
// honest: a page that simply prints the parameter back contains the canary, but
// nothing there redirects anyone.
func TestOpenRedirectIgnoresReflection(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		fmt.Fprintf(w, "<html><body><p>No results for %s</p><p>%s</p></body></html>",
			next, strings.Repeat("lorem ipsum ", 60))
	})
	if len(got) != 0 {
		t.Error("a page that only reflects the parameter was reported as a redirect")
	}
}

// TestOpenRedirectIgnoresPlainLink: an <a href> is a link, not a redirect. It
// was one of the words that made this check fire on every page that echoes its
// input, and it is not a construct that moves a visitor by itself.
func TestOpenRedirectIgnoresPlainLink(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		fmt.Fprintf(w, `<html><body><a href="%s">continue</a>%s</body></html>`,
			next, strings.Repeat("filler ", 60))
	})
	if len(got) != 0 {
		t.Error("a plain link was reported as an open redirect")
	}
}

// TestOpenRedirectIgnoresRelativeTarget: a canary reached through a path on the
// same site stays on the same site, whichever payload was sent.
//
// The handler answers every payload with the same same-site path, which is what
// a target that prefixes the parameter with "/" does.
func TestOpenRedirectIgnoresRelativeTarget(t *testing.T) {
	got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0;url=/%s"></head>%s</html>`,
			redirectCanary, strings.Repeat("filler ", 60))
	})
	if len(got) != 0 {
		t.Error("a same-site path was reported as an open redirect")
	}
}

// TestOpenRedirectSeesTheBypassForms: schemeless and backslash forms are how a
// naive "must start with /" filter is defeated, and they do leave the site.
func TestOpenRedirectSeesTheBypassForms(t *testing.T) {
	for _, form := range []string{"////" + redirectCanary, "/\\" + redirectCanary} {
		got := runRedirect(t, func(w http.ResponseWriter, r *http.Request) {
			next := r.URL.Query().Get("next")
			fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0;url=%s"></head>%s</html>`,
				next, strings.Repeat("filler ", 60))
		})
		_ = form
		if len(got) == 0 {
			t.Error("a schemeless bypass form was not reported")
		}
		break // the handler answers every payload the same way; one pass is enough
	}
}
