package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/oob"
)

// startOOB brings up an interaction server and returns it once it is listening.
func startOOB(t *testing.T) *oob.Server {
	t.Helper()

	server := oob.New(oob.Options{HTTPAddr: "127.0.0.1:0", DNSAddr: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})
	go func() { _ = server.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if server.HTTPAddr() != "127.0.0.1:0" {
			return server
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the interaction server did not start")
	return nil
}

// TestSSRFFiresOnCallback is the end-to-end path for a blind SSRF: the target
// makes an outbound request nobody asked it to make, and that is the proof.
func TestSSRFFiresOnCallback(t *testing.T) {
	oobServer := startOOB(t)

	// A target that fetches whatever URL it is given — a textbook SSRF.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if target := r.URL.Query().Get("url"); strings.HasPrefix(target, "http") {
			go func() {
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(target)
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>fetching…</body></html>")
	}))
	defer target.Close()

	h := newHarness(t)
	h.ctx.OOB = oobServer

	findings := withParameter(t, h, ssrf{}, target.URL+"/fetch?url=http://example.com/")
	if len(findings) == 0 {
		t.Fatal("an outbound request from the target was not reported as SSRF")
	}

	f := findings[0]
	if string(f.Severity) != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.CWE != "CWE-918" {
		t.Errorf("CWE = %q, want CWE-918", f.CWE)
	}
	if len(f.Evidence.Matches) == 0 || !strings.Contains(strings.ToLower(f.Evidence.Matches[0]), "dns") &&
		!strings.Contains(strings.ToLower(f.Evidence.Matches[0]), "http") {
		t.Errorf("evidence does not describe the callback: %v", f.Evidence.Matches)
	}
}

// TestSSRFStaysQuietWithoutACallback keeps the check honest: a target that does
// not reach out must not be reported, however promising the parameter looks.
func TestSSRFStaysQuietWithoutACallback(t *testing.T) {
	oobServer := startOOB(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignores the URL entirely.
		fmt.Fprint(w, "<html><body>nothing to see</body></html>")
	}))
	defer target.Close()

	h := newHarness(t)
	h.ctx.OOB = oobServer
	// A short wait keeps the test quick; production waits several seconds.
	h.ctx.OOBWait = 700 * time.Millisecond

	findings := withParameter(t, h, ssrf{}, target.URL+"/fetch?url=http://example.com/")
	if len(findings) != 0 {
		t.Errorf("a target that never called back was reported: %+v", findings)
	}
}

// TestSSRFNeedsAnOOBServer documents that out-of-band checks are skipped, not
// failed, when no interaction server is configured.
func TestSSRFNeedsAnOOBServer(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer target.Close()

	h := newHarness(t)
	h.ctx.OOB = nil

	if findings := withParameter(t, h, ssrf{}, target.URL+"/fetch?url=http://example.com/"); len(findings) != 0 {
		t.Error("SSRF was reported with no interaction server configured")
	}
}

// TestCommandInjectionFiresOnCallback covers the command-injection equivalent.
func TestCommandInjectionFiresOnCallback(t *testing.T) {
	oobServer := startOOB(t)

	// A target that actually runs the value as a shell command.
	//
	// It extracts the last word of the parameter — which is what a shell would
	// treat as the argument to nslookup or curl — and fetches it. A real target
	// would resolve the name over DNS; fetching it over HTTP exercises the same
	// correlation path.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("host")
		fields := strings.Fields(value)
		if len(fields) > 0 {
			argument := strings.Trim(fields[len(fields)-1], "`'\"$()&|;#%")
			if argument != "" {
				go func() {
					client := &http.Client{Timeout: 2 * time.Second}
					resp, err := client.Get("http://" + argument + "/")
					if err == nil {
						_ = resp.Body.Close()
					}
				}()
			}
		}
		fmt.Fprint(w, "<html><body>pinging…</body></html>")
	}))
	defer target.Close()

	h := newHarness(t)
	h.ctx.OOB = oobServer
	h.ctx.OOBWait = 700 * time.Millisecond

	findings := withParameter(t, h, commandInjection{}, target.URL+"/ping?host=nslookup")
	if len(findings) == 0 {
		t.Fatal("a callback from a command injection was not reported")
	}
	if findings[0].CWE != "CWE-78" {
		t.Errorf("CWE = %q, want CWE-78", findings[0].CWE)
	}
}
