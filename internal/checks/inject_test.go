package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
	"github.com/guaidao2/crackweb/internal/waf"
)

// decodeOnceWAF is a target whose filter decodes a parameter exactly once and
// then looks for a quote.
//
// That single-decode blind spot is what a double-encoded payload walks through:
// the filter turns `%2527` into `%27`, finds no quote, and allows it, while the
// application decodes again and sees one.
func decodeOnceWAF(t *testing.T) (*httptest.Server, *wafTrace) {
	t.Helper()
	trace := &wafTrace{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawQuery
		_, value, _ := strings.Cut(raw, "=")

		decodedOnce, _ := url.QueryUnescape(value)
		if strings.ContainsAny(decodedOnce, `'"`) {
			trace.record(raw, true)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<html><body>Access Denied - request blocked by security policy</body></html>`)
			return
		}

		decodedTwice, _ := url.QueryUnescape(decodedOnce)
		trace.record(raw, false)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(decodedTwice, `'"`) {
			fmt.Fprintf(w, `<html><body>You have an error in your SQL syntax near '%s' at line 1</body></html>`, decodedTwice)
			return
		}
		fmt.Fprintf(w, `<html><body><h1>Article %s</h1><p>%s</p></body></html>`, decodedTwice, strings.Repeat("lorem ipsum ", 40))
	}))
	t.Cleanup(server.Close)
	return server, trace
}

// wafTrace records what the filter saw.
type wafTrace struct {
	mu      sync.Mutex
	blocked []string
	passed  []string
}

func (t *wafTrace) record(raw string, blocked bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if blocked {
		t.blocked = append(t.blocked, raw)
		return
	}
	t.passed = append(t.passed, raw)
}

func (t *wafTrace) snapshot() (blocked, passed []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.blocked...), append([]string(nil), t.passed...)
}

// contextFor builds a check context wired to a live test server.
func contextFor(t *testing.T, wafEnabled bool) *Context {
	t.Helper()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	normalizer, err := diff.New(diff.Options{})
	if err != nil {
		t.Fatalf("diff.New: %v", err)
	}
	engine := diff.NewEngine(diff.ThresholdsForSensitivity(3), diff.DefaultKeywords())

	c := NewContext(client, i18n.New(i18n.EN), engine, normalizer)
	c.WAF = waf.NewState(wafEnabled)
	return c
}

// TestEscalatesPastAFilterThatDecodesOnce is the end-to-end property the whole
// mutation engine exists for: the plain payload is refused, and the scanner
// finds a variation the filter does not recognise.
func TestEscalatesPastAFilterThatDecodesOnce(t *testing.T) {
	server, trace := decodeOnceWAF(t)
	c := contextFor(t, true)

	request, err := httpmsg.NewRequest("GET", server.URL+"/?id=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := c.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	if len(params) == 0 {
		t.Fatal("no parameters")
	}
	target := &Target{Request: request, Response: baseline, Param: &params[0]}

	// The probe has to run first, exactly as a check does.
	c.ProbeWAF(context.Background(), target)

	attempt, err := c.SendVariants(context.Background(), target, payload.SQLi, "sqli-error",
		[]string{"'", `"`, "1' AND 1=1-- -"},
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			return strings.Contains(strings.ToLower(string(resp.Body)), "sql syntax")
		})
	if err != nil {
		t.Fatalf("SendVariants: %v", err)
	}
	if attempt == nil {
		blocked, passed := trace.snapshot()
		t.Fatalf("no payload got through the filter\n  blocked (%d): %v\n  passed (%d): %v",
			len(blocked), blocked, len(passed), passed)
	}

	if attempt.Variant.Generation == 0 {
		t.Errorf("succeeded with an unmutated payload, so the filter was not exercised")
	}
	if len(attempt.Variant.Mutators) == 0 {
		t.Error("the successful variant records no transformations")
	}
	// The payload that worked must genuinely be a mutated form of a seed.
	if !strings.Contains(string(attempt.Response.Body), "SQL syntax") {
		t.Errorf("the response is not the one the judge accepted: %q", attempt.Response.Body)
	}

	blocked, passed := trace.snapshot()
	if len(blocked) == 0 {
		t.Error("the filter never refused anything, so escalation was not tested")
	}
	if len(passed) == 0 {
		t.Error("nothing got through the filter")
	}
}

// TestEscalationIsRemembered checks that the cost is paid once: a second check
// against the same host starts where the first one finished.
func TestEscalationIsRemembered(t *testing.T) {
	server, _ := decodeOnceWAF(t)
	c := contextFor(t, true)

	request, _ := httpmsg.NewRequest("GET", server.URL+"/?id=1")
	baseline, _ := c.Do(context.Background(), request)
	params := request.Params()
	target := &Target{Request: request, Response: baseline, Param: &params[0]}

	c.ProbeWAF(context.Background(), target)
	judge := func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
		return strings.Contains(strings.ToLower(string(resp.Body)), "sql syntax")
	}
	if _, err := c.SendVariants(context.Background(), target, payload.SQLi, "sqli-error",
		[]string{"'"}, judge); err != nil {
		t.Fatalf("first pass: %v", err)
	}

	host := request.Hostname()
	if floor := c.WAF.Floor(host, "sqli-error"); floor == 0 {
		t.Error("the working generation was not remembered")
	}

	// A second check on the same host and check ID should start at that floor.
	start := c.WAF.Floor(host, "sqli-error")
	if _, err := c.SendVariants(context.Background(), target, payload.SQLi, "sqli-error",
		[]string{"'"}, judge); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if c.WAF.Floor(host, "sqli-error") < start {
		t.Error("the remembered generation went backwards")
	}
}

// TestNoEscalationAgainstAnOpenTarget keeps the common case cheap: an
// unprotected target must not be sent mutated payloads it does not need.
func TestNoEscalationAgainstAnOpenTarget(t *testing.T) {
	var seen []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawQuery
		mu.Lock()
		seen = append(seen, raw)
		mu.Unlock()

		_, value, _ := strings.Cut(raw, "=")
		decoded, _ := url.QueryUnescape(value)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(decoded, `'"`) {
			fmt.Fprintf(w, `<html><body>You have an error in your SQL syntax near '%s'</body></html>`, decoded)
			return
		}
		fmt.Fprintf(w, `<html><body><h1>Article</h1><p>%s</p></body></html>`, strings.Repeat("lorem ipsum ", 40))
	}))
	defer server.Close()

	c := contextFor(t, true)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/?id=1")
	baseline, _ := c.Do(context.Background(), request)
	params := request.Params()
	target := &Target{Request: request, Response: baseline, Param: &params[0]}

	c.ProbeWAF(context.Background(), target)
	mu.Lock()
	afterProbe := len(seen)
	mu.Unlock()

	attempt, err := c.SendVariants(context.Background(), target, payload.SQLi, "sqli-error",
		[]string{"'", `"`},
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			return strings.Contains(strings.ToLower(string(resp.Body)), "sql syntax")
		})
	if err != nil {
		t.Fatalf("SendVariants: %v", err)
	}
	if attempt == nil {
		t.Fatal("an open target produced no finding")
	}
	if attempt.Variant.Generation != 0 {
		t.Errorf("generation %d was needed against an open target", attempt.Variant.Generation)
	}

	mu.Lock()
	payloadRequests := len(seen) - afterProbe
	mu.Unlock()
	// Two seeds, at most two requests: no mutation when none is needed.
	if payloadRequests > 3 {
		t.Errorf("an open target cost %d payload requests, want no more than the seed count", payloadRequests)
	}
}

func TestProbeWAFRunsOncePerHost(t *testing.T) {
	server, trace := decodeOnceWAF(t)
	c := contextFor(t, true)

	request, _ := httpmsg.NewRequest("GET", server.URL+"/?id=1")
	baseline, _ := c.Do(context.Background(), request)
	params := request.Params()
	target := &Target{Request: request, Response: baseline, Param: &params[0]}

	c.ProbeWAF(context.Background(), target)
	_, afterFirst := trace.snapshot()
	firstCount := len(afterFirst)

	c.ProbeWAF(context.Background(), target)
	_, afterSecond := trace.snapshot()
	if len(afterSecond) != firstCount {
		t.Errorf("the second probe issued %d more requests; probing should happen once per host",
			len(afterSecond)-firstCount)
	}
}

func TestSendVariantsHandlesMissingInput(t *testing.T) {
	c := contextFor(t, false)

	if attempt, err := c.SendVariants(context.Background(), nil, payload.SQLi, "x", []string{"'"}, nil); err != nil || attempt != nil {
		t.Error("a nil target was not handled")
	}
	target := &Target{Request: &httpmsg.Request{}}
	if attempt, err := c.SendVariants(context.Background(), target, payload.SQLi, "x", []string{"'"}, nil); err != nil || attempt != nil {
		t.Error("a target without a parameter was not handled")
	}
	if attempt, err := c.SendVariants(context.Background(), target, payload.SQLi, "x", nil, nil); err != nil || attempt != nil {
		t.Error("an empty seed list was not handled")
	}
}

func TestVariantEncodingIsNotDoubled(t *testing.T) {
	// A variant that already produced transport form must not be encoded again,
	// or the application receives a literal percent sequence.
	encoded := payload.Variant{Value: "%2527", Generation: 1, Mutators: []string{"double-urlencode"}}
	if encoded.NeedsTransportEncoding() {
		t.Error("a doubly-encoded variant would be encoded a third time")
	}
	plain := payload.Variant{Value: "'", Generation: 0}
	if !plain.NeedsTransportEncoding() {
		t.Error("a plain variant would be sent unencoded")
	}
	structural := payload.Variant{Value: "1/**/AND/**/1=1", Generation: 1, Mutators: []string{"space-to-comment"}}
	if !structural.NeedsTransportEncoding() {
		t.Error("a structural rewrite still needs transport encoding")
	}
}

// TestTheRequestHookSeesEveryRequest is what --verbose prints: the hook has to
// see each request a check sends, and it has to see it once. Do is the single
// place every check's traffic passes through, which is why the hook lives there.
func TestTheRequestHookSeesEveryRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	normalizer, err := diff.New(diff.Options{})
	if err != nil {
		t.Fatalf("diff.New: %v", err)
	}
	c := NewContext(client, i18n.New(i18n.EN),
		diff.NewEngine(diff.ThresholdsForSensitivity(3), diff.DefaultKeywords()), normalizer)

	var (
		mu   sync.Mutex
		seen []string
	)
	c.OnRequest = func(req *httpmsg.Request) {
		mu.Lock()
		seen = append(seen, req.Method+" "+req.URLString())
		mu.Unlock()
	}

	request, err := httpmsg.NewRequest("GET", server.URL+"/item?id=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := c.Do(context.Background(), request); err != nil {
		t.Fatalf("Do: %v", err)
	}

	params := request.Params()
	if len(params) == 0 {
		t.Fatal("the test request has no parameters")
	}
	target := &Target{Request: request, Param: &params[0]}
	if _, _, err := c.Inject(context.Background(), target, "1,1"); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("the hook saw %d request(s), want 2: %v", len(seen), seen)
	}
	if !strings.HasSuffix(seen[1], "id=1%2C1") {
		t.Errorf("the hook saw %q, want the injected value", seen[1])
	}
}
