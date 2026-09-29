package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// silentTarget answers everything with the same page and never refuses anything — which is
// what a modern edge looks like from the outside when it rewrites a payload instead of
// rejecting it.
func silentTarget(t *testing.T) (*httptest.Server, func() []string, func()) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RawQuery)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>nothing here</body></html>")
	}))
	t.Cleanup(server.Close)

	return server,
		func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), seen...)
		},
		func() {
			mu.Lock()
			seen = nil
			mu.Unlock()
		}
}

// TestAssumeWAFSendsAMutatedFormWhenNothingIsRefused is the whole point of the option: a
// target that filters silently gives the escalation rule no evidence, and without this the
// mutations — the part that gets through — are never sent at all.
func TestAssumeWAFSendsAMutatedFormWhenNothingIsRefused(t *testing.T) {
	server, asked, reset := silentTarget(t)
	h := newHarness(t)
	url := server.URL + "/search?q=1"

	h.ctx.AssumeWAF = false
	withParameter(t, h, sqliError{}, url)
	withoutAssume := len(asked())

	reset()
	h.ctx.AssumeWAF = true
	withParameter(t, h, sqliError{}, url)
	withAssume := len(asked())

	if withoutAssume == 0 {
		t.Fatal("the check sent nothing at all, so the comparison means nothing")
	}
	if withAssume <= withoutAssume {
		t.Errorf("--assume-waf sent %d requests, the same as without it (%d): "+
			"a silently filtered target would get no mutations", withAssume, withoutAssume)
	}
}

// TestAssumeWAFIsNotABlankCheque: the assumption buys one round of mutation, not every
// generation. The later ones still need evidence that something is filtering.
func TestAssumeWAFIsNotABlankCheque(t *testing.T) {
	server, asked, reset := silentTarget(t)
	h := newHarness(t)
	h.ctx.AssumeWAF = true
	url := server.URL + "/search?q=1"

	withParameter(t, h, sqliError{}, url)
	assumed := len(asked())

	reset()
	h.ctx.AssumeWAF = false
	withParameter(t, h, sqliError{}, url)
	plain := len(asked())

	// Two generations, not four: a target nothing is filtering must not be walked through
	// the whole mutation grammar. The bound is loose on purpose — it is here to catch the
	// assumption turning into "run everything", not to pin the exact count.
	if assumed > 8*plain {
		t.Errorf("--assume-waf cost %d requests against %d without it; the assumption is "+
			"meant to buy a couple of rounds, not the whole grammar", assumed, plain)
	}
}
