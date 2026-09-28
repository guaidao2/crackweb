package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
	"github.com/guaidao2/crackweb/internal/waf"
)

// disagreeingLayers is a target whose filter and application parse a repeated
// parameter differently — the exact condition parameter pollution exploits.
//
// The filter reads the first occurrence and refuses a quote. The application
// reads the last. Neither is behaving oddly on its own; it is the disagreement
// that is exploitable.
func disagreeingLayers(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var saw []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values, ok := r.URL.Query()["id"]
		if !ok || len(values) == 0 {
			fmt.Fprint(w, "<html><body>missing parameter</body></html>")
			return
		}
		saw = append(saw, strings.Join(values, "|"))

		// The filter: first occurrence only.
		if strings.ContainsAny(values[0], `'"`) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "<html><body>Access Denied - request blocked by security policy</body></html>")
			return
		}
		// The application: last occurrence wins.
		effective := values[len(values)-1]
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(effective, `'"`) {
			fmt.Fprintf(w, "<html><body>You have an error in your SQL syntax near '%s'</body></html>", effective)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Article %s</h1><p>%s</p></body></html>",
			effective, strings.Repeat("lorem ipsum ", 40))
	}))
	t.Cleanup(server.Close)
	return server, &saw
}

// TestHPPDefeatsAFilterThatReadsTheFirstOccurrence is the technique's whole
// purpose: the payload is refused on its own and accepted when hidden behind a
// duplicate.
func TestHPPDefeatsAFilterThatReadsTheFirstOccurrence(t *testing.T) {
	server, saw := disagreeingLayers(t)

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	normalizer, _ := diff.New(diff.Options{})
	engine := diff.NewEngine(diff.ThresholdsForSensitivity(3), diff.DefaultKeywords())

	c := NewContext(client, i18n.New(i18n.EN), engine, normalizer)
	c.WAF = waf.NewState(true)

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

	lowerBaseline := strings.ToLower(string(baseline.Body))
	attempt, err := c.SendVariants(context.Background(), target, payload.SQLi, "sqli-error",
		[]string{"'"},
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			return strings.Contains(strings.ToLower(string(resp.Body)), "sql syntax") &&
				!strings.Contains(lowerBaseline, "sql syntax")
		})
	if err != nil {
		t.Fatalf("SendVariants: %v", err)
	}
	if attempt == nil {
		t.Fatalf("the polluted payload did not get through; requests seen: %v", *saw)
	}
	if !attempt.Polluted {
		t.Error("the attempt is not marked as polluted, so the report would not explain how it worked")
	}
	// The request that worked must genuinely carry the parameter twice.
	if got := strings.Count(attempt.Request.URLString(), "id="); got != 2 {
		t.Errorf("the successful request has %d occurrences of the parameter, want 2: %s",
			got, attempt.Request.URLString())
	}
	// And the payload must not be in the first slot — that is the one the filter
	// reads.
	values := attempt.Request.URL.Query()["id"]
	if len(values) < 2 || strings.ContainsAny(values[0], `'"`) {
		t.Errorf("the payload landed in the checked position: %v", values)
	}
}

// TestMutateHPPKeepsTheOriginalValue documents the shape of the mutation, since
// putting the payload first would defeat its own purpose.
func TestMutateHPPKeepsTheOriginalValue(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.com/item?id=42&page=2")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	params := request.Params()
	if len(params) == 0 {
		t.Fatal("no parameters")
	}

	mutated, err := MutateHPP(request, params[0], "' OR 1=1--", EncodeURL)
	if err != nil {
		t.Fatalf("MutateHPP: %v", err)
	}

	values := mutated.URL.Query()["id"]
	if len(values) != 2 {
		t.Fatalf("got %d occurrences, want 2: %s", len(values), mutated.URLString())
	}
	if values[0] != "42" {
		t.Errorf("the original value was displaced: %q", values[0])
	}
	if values[1] != "' OR 1=1--" {
		t.Errorf("the payload is not the second occurrence: %q", values[1])
	}
	// Other parameters survive untouched.
	if mutated.URL.Query().Get("page") != "2" {
		t.Error("another parameter was disturbed")
	}
}

func TestMutateHPPHandlesFormBodies(t *testing.T) {
	request, _ := httpmsg.NewRequest("POST", "http://example.com/login")
	request.Body = []byte("user=admin&pass=secret")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Length", "22")

	params := request.Params()
	var pass *httpmsg.Param
	for i := range params {
		if params[i].Name == "pass" {
			pass = &params[i]
		}
	}
	if pass == nil {
		t.Fatal("no pass parameter")
	}

	mutated, err := MutateHPP(request, *pass, "' OR '1'='1", EncodeURL)
	if err != nil {
		t.Fatalf("MutateHPP: %v", err)
	}
	body := string(mutated.Body)
	if !strings.Contains(body, "user=admin") {
		t.Errorf("the other field was lost: %q", body)
	}
	if strings.Count(body, "pass=") != 2 {
		t.Errorf("the parameter was not duplicated: %q", body)
	}
	if got := mutated.Header.Get("Content-Length"); got != fmt.Sprint(len(mutated.Body)) {
		t.Errorf("Content-Length = %q, want %d", got, len(mutated.Body))
	}
}

func TestMutateHPPRejectsCookieLocation(t *testing.T) {
	request, _ := httpmsg.NewRequest("GET", "http://example.com/")
	request.Header.Set("Cookie", "session=abc")
	params := request.CookieParams()
	if len(params) == 0 {
		t.Fatal("no cookie parameters")
	}
	if _, err := MutateHPP(request, params[0], "x", EncodeNone); err == nil {
		t.Error("HPP was applied to a cookie, where its semantics are different")
	}
}
