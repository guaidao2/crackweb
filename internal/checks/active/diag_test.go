package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// TestFingerprintIsSymmetric: the same response compared with itself must score
// 1.0. If it does not, every check that judges by "the response changed" is
// measuring the fingerprinting, not the target.
func TestFingerprintIsSymmetric(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>"+strings.Repeat("stable content ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	req, _ := httpmsg.NewRequest("GET", server.URL+"/x")
	resp, err := h.client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	base := h.ctx.BaselineFingerprint(&checks.Target{Request: req, Response: resp})
	again := h.ctx.Fingerprint(resp)

	if base.NormLen == 0 || again.NormLen == 0 {
		t.Logf("NormLen base=%d cur=%d (short-body path)", base.NormLen, again.NormLen)
	}
	score := diff.CompareFingerprints(base, again).Score
	t.Logf("same response vs itself: NormLen=%d/%d score=%.4f", base.NormLen, again.NormLen, score)
	if score < 0.999 {
		t.Errorf("the fingerprint is not symmetric: score=%.4f", score)
	}
}

// TestFingerprintIsStableAcrossRequests: two identical requests to a static page
// must fingerprint the same, which is what every "did it change?" judgement
// rests on.
func TestFingerprintIsStableAcrossRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Method", r.Method)
		fmt.Fprint(w, "<html><body>"+strings.Repeat("stable content ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	req, _ := httpmsg.NewRequest("GET", server.URL+"/x")

	first, err := h.client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := h.client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	a := h.ctx.Fingerprint(first)
	b := h.ctx.Fingerprint(second)
	score := diff.CompareFingerprints(a, b).Score
	t.Logf("two identical requests: NormLen=%d/%d score=%.4f", a.NormLen, b.NormLen, score)
	if score < 0.999 {
		t.Errorf("two identical requests fingerprinted differently: score=%.4f", score)
	}
}

// TestFingerprintSurvivesAnExtraHeader: adding a header the page ignores must
// not change the fingerprint, because that is exactly what the method-override
// check measures.
func TestFingerprintSurvivesAnExtraHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>"+strings.Repeat("stable content ", 40)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	req, _ := httpmsg.NewRequest("GET", server.URL+"/x")
	base, err := h.client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	mutated := req.Clone()
	mutated.Header.Set("X-HTTP-Method-Override", "DELETE")
	cur, err := h.client.Do(context.Background(), mutated)
	if err != nil {
		t.Fatalf("mutated: %v", err)
	}

	score := diff.CompareFingerprints(h.ctx.Fingerprint(base), h.ctx.Fingerprint(cur)).Score
	t.Logf("ignored header: NormLen=%d/%d score=%.4f", h.ctx.Fingerprint(base).NormLen, h.ctx.Fingerprint(cur).NormLen, score)
	if score < 0.999 {
		t.Errorf("an ignored header changed the fingerprint: score=%.4f", score)
	}
}
