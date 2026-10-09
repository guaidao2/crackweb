package template

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// These tests pin the engine to the behaviour nuclei implements, one semantic at
// a time. They are the contract the package comment describes: a template is run
// the way nuclei would run it, or refused with a reason, and never quietly run
// into a different answer.

// runAgainstServer parses a template and executes it against a path on a
// server, returning the findings.
func runAgainstServer(t *testing.T, source string, server *httptest.Server, path string) []*finding.Finding {
	t.Helper()

	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	client, err := httpclient.New(httpclient.Options{})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	target, err := httpmsg.NewRequest("GET", server.URL+path)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return NewRunner(client).Execute(context.Background(), tmpl, target, nil, nil)
}

// TestAttackTypesSendWhatNucleiSends pins the three attack types.
//
// The default is batteringram: one payload list is in play at a time, so two
// lists of two and three describe five requests — not six. pitchfork advances
// every list together and stops at the shortest. clusterbomb is the cross
// product. Reading the attack type as decoration and always sending the cross
// product changes which requests a template sends, and therefore which findings
// it can produce.
func TestAttackTypesSendWhatNucleiSends(t *testing.T) {
	cases := []struct {
		name   string
		attack string
		want   []string
	}{
		{
			name: "default is batteringram",
			want: []string{"x=1", "x=2", "y=x", "y=y", "y=z"},
		},
		{
			name:   "pitchfork advances together",
			attack: "attack: pitchfork",
			want:   []string{"x=1&y=x", "x=2&y=y"},
		},
		{
			name:   "clusterbomb is the cross product",
			attack: "attack: clusterbomb",
			want: []string{
				"x=1&y=x", "x=1&y=y", "x=1&y=z",
				"x=2&y=x", "x=2&y=y", "x=2&y=z",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Only the bound pairs are recorded: a payload name this attack
				// type left unbound renders as its own placeholder, and that is
				// the difference under test.
				var bound []string
				for _, pair := range strings.Split(r.URL.RawQuery, "&") {
					if pair != "" && !strings.Contains(pair, "{{") {
						bound = append(bound, pair)
					}
				}
				sort.Strings(bound)
				seen = append(seen, strings.Join(bound, "&"))
				fmt.Fprint(w, "nothing to see here")
			}))
			defer server.Close()

			source := fmt.Sprintf(`
id: attack-types
info:
  name: attack types
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/p?x={{x}}&y={{y}}"
    %s
    payloads:
      x: ["1", "2"]
      y: ["x", "y", "z"]
    matchers:
      - type: word
        words: ["this never matches"]
`, tc.attack)

			runAgainstServer(t, source, server, "/")

			sort.Strings(seen)
			if strings.Join(seen, " | ") != strings.Join(tc.want, " | ") {
				t.Errorf("sent %v, want %v", seen, tc.want)
			}
		})
	}
}

// TestEmptyOperatorBlockIsRefusedNotReported pins the fix for a false positive:
// a block with neither matchers nor extractors used to be reported as a hit
// ("request completed"), so every template with a scaffolding-shaped block
// reported its target as vulnerable. nuclei refuses the template outright.
func TestEmptyOperatorBlockIsRefusedNotReported(t *testing.T) {
	source := `
id: empty-operators
info:
  name: empty operators
  severity: high
http:
  - method: GET
    path:
      - "{{RootURL}}/"
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reasons := strings.Join(tmpl.Unsupported(), "; ")
	if !strings.Contains(reasons, "no matchers") {
		t.Errorf("a block with no matchers and no extractors was accepted: %v", reasons)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer server.Close()

	client, _ := httpclient.New(httpclient.Options{})
	target, _ := httpmsg.NewRequest("GET", server.URL+"/")
	if findings := NewRunner(client).Execute(context.Background(), tmpl, target, nil, nil); len(findings) != 0 {
		t.Errorf("an empty operator block reported %d finding(s)", len(findings))
	}
}

// TestCaseInsensitiveIsOnlyHonouredByWordMatchers pins a refusal, not a
// feature: nuclei compiles a case-insensitive regex matcher into an error
// ("case-insensitive flag is supported only for 'word' matchers"), so crackweb
// refuses the template instead of matching case-sensitively and behaving as if
// the flag had been written.
func TestCaseInsensitiveIsOnlyHonouredByWordMatchers(t *testing.T) {
	source := `
id: bad-case-insensitive
info:
  name: case-insensitive regex
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers:
      - type: regex
        case-insensitive: true
        regex:
          - "admin"
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reasons := strings.Join(tmpl.Unsupported(), "; ")
	if !strings.Contains(reasons, "case-insensitive") {
		t.Errorf("a case-insensitive regex matcher was accepted: %v", reasons)
	}
}

// TestMatcherWithoutItsValuesIsRefused covers the same class of mistake: a
// matcher that names a type and forgets the values for it. nuclei refuses to
// compile it, and running it would answer "no match" for a template the author
// meant to work, which reads like a clean target.
func TestMatcherWithoutItsValuesIsRefused(t *testing.T) {
	source := `
id: matcher-without-values
info:
  name: matcher without values
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers:
      - type: regex
        status: [200]
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reasons := strings.Join(tmpl.Unsupported(), "; ")
	if !strings.Contains(reasons, "no values") {
		t.Errorf("a regex matcher with no regex was accepted: %v", reasons)
	}
	if !strings.Contains(reasons, "status") {
		t.Errorf("a regex matcher carrying a status list was accepted: %v", reasons)
	}
}

// TestExtractorsFeedLaterRequests covers the shape most templates are built
// from: one request obtains a token and the next one uses it.
func TestExtractorsFeedLaterRequests(t *testing.T) {
	var second string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			fmt.Fprint(w, `<input name="csrf" value="tok-12345">`)
			return
		}
		second = r.URL.Query().Get("csrf")
		fmt.Fprint(w, "welcome")
	}))
	defer server.Close()

	source := `
id: extract-then-use
info:
  name: extract and reuse
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/login"
    extractors:
      - type: regex
        name: csrf
        internal: true
        group: 1
        regex:
          - 'name="csrf" value="(tok-[0-9]+)"'
  - method: GET
    path:
      - "{{RootURL}}/admin?csrf={{csrf}}"
    matchers:
      - type: word
        words: ["welcome"]
`
	findings := runAgainstServer(t, source, server, "/")

	if second != "tok-12345" {
		t.Errorf("the second request carried csrf=%q, want the extracted token", second)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

// TestMultiValueExtractionIteratesWhenAsked pins nuclei's two behaviours for a
// multi-valued internal extraction: the first value once, or one request per
// value when the template asks for it with iterate-all.
func TestMultiValueExtractionIteratesWhenAsked(t *testing.T) {
	cases := []struct {
		name       string
		iterateAll string
		want       int
	}{
		{name: "first value only", want: 1},
		{name: "iterate-all sends one request per value", iterateAll: "iterate-all: true", want: 3},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/list" {
					fmt.Fprint(w, "token=11 token=22 token=33")
					return
				}
				seen = append(seen, r.URL.Query().Get("token"))
				fmt.Fprint(w, "no match here")
			}))
			defer server.Close()

			source := fmt.Sprintf(`
id: iterate-values
info:
  name: iterate values
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/list"
    extractors:
      - type: regex
        name: tokens
        internal: true
        group: 1
        regex:
          - 'token=([0-9]+)'
  - method: GET
    path:
      - "{{RootURL}}/item?token={{tokens}}"
    %s
    matchers:
      - type: word
        words: ["this never matches"]
`, tc.iterateAll)

			runAgainstServer(t, source, server, "/")

			if len(seen) != tc.want {
				t.Errorf("sent %d follow-up request(s) (%v), want %d", len(seen), seen, tc.want)
			}
		})
	}
}

// TestReqConditionNumbersEveryRequest pins req-condition: the conversation is
// kept under numbered names, so a matcher can compare two responses instead of
// only seeing the one in hand.
func TestReqConditionNumbersEveryRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	source := `
id: req-condition
info:
  name: conversation
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/first"
      - "{{RootURL}}/second"
    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 500"
`
	findings := runAgainstServer(t, source, server, "/")

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.HasSuffix(findings[0].URL, "/second") {
		t.Errorf("finding was reported against %s, want the request that completed the condition", findings[0].URL)
	}
}

// TestInternalMatcherGatesButIsNotEvidence pins two nuclei rules at once: an
// internal matcher takes part in the condition and stays out of the output.
func TestInternalMatcherGatesButIsNotEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "crackweb-test")
		fmt.Fprint(w, "the marker is here")
	}))
	defer server.Close()

	source := `
id: internal-matcher
info:
  name: internal matcher
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        internal: true
        part: header
        words: ["crackweb-test"]
      - type: word
        words: ["marker"]
`
	findings := runAgainstServer(t, source, server, "/")

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	evidence := strings.Join(findings[0].Evidence.Matches, ", ")
	if strings.Contains(evidence, "crackweb-test") {
		t.Errorf("internal matcher appeared in the evidence: %q", evidence)
	}
	if !strings.Contains(evidence, "marker") {
		t.Errorf("public matcher did not appear in the evidence: %q", evidence)
	}
}

// TestMatchAllCollectsEveryOccurrence pins match-all, which is how a template
// collects every link on a page rather than the first one.
func TestMatchAllCollectsEveryOccurrence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/one">1</a><a href="/two">2</a><a href="/three">3</a>`)
	}))
	defer server.Close()

	source := `
id: match-all
info:
  name: match all
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers:
      - type: regex
        match-all: true
        regex:
          - 'href="(/[a-z]+)"'
`
	findings := runAgainstServer(t, source, server, "/")

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if len(findings[0].Evidence.Matches) != 3 {
		t.Errorf("evidence = %v, want every occurrence", findings[0].Evidence.Matches)
	}
}

// TestWordMatcherRendersVariables pins the rendering of {{...}} inside a word
// matcher's words, which is how a template matches on something it extracted or
// on a helper variable.
func TestWordMatcherRendersVariables(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "welcome to the crackweb test server")
	}))
	defer server.Close()

	source := `
id: render-words
info:
  name: render words
  severity: info
variables:
  marker: crackweb test
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers:
      - type: word
        words: ["welcome to the {{marker}} server"]
`
	if findings := runAgainstServer(t, source, server, "/"); len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

// TestRedirectsAreFollowedOnlyWhenAsked pins the redirect fields. A template
// that wants the page behind a 302 asks for it; one that matches on the 302 must
// be given the 302.
func TestRedirectsAreFollowedOnlyWhenAsked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "landed on the final page")
	}))
	defer server.Close()

	source := `
id: redirects
info:
  name: redirects
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/start"
    matchers:
      - type: word
        words: ["landed on the final page"]
`
	if findings := runAgainstServer(t, source, server, "/"); len(findings) != 0 {
		t.Errorf("a redirect was followed without being asked for: %d finding(s)", len(findings))
	}

	following := strings.Replace(source, "    matchers:", "    redirects: true\n    matchers:", 1)
	if findings := runAgainstServer(t, following, server, "/"); len(findings) != 1 {
		t.Errorf("redirects: true did not follow the redirect: %d finding(s)", len(findings))
	}
}

// TestHostRedirectsStopsAtAnotherHost pins host-redirects. The same server is
// reachable as 127.0.0.1 and as localhost, so a redirect between the two names
// leaves the host and must not be followed.
func TestHostRedirectsStopsAtAnotherHost(t *testing.T) {
	var otherHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, otherHost+"/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "landed on the final page")
	}))
	defer server.Close()
	otherHost = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	source := `
id: host-redirects
info:
  name: host redirects
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/start"
    host-redirects: true
    matchers:
      - type: word
        words: ["landed on the final page"]
`
	if findings := runAgainstServer(t, source, server, "/"); len(findings) != 0 {
		t.Errorf("host-redirects followed a redirect to another host: %d finding(s)", len(findings))
	}
}

// TestCookiesCarryBetweenBlocksAndCanBeDisabled pins nuclei's cookie handling:
// a template's requests reuse cookies unless the block turns it off.
func TestCookiesCarryBetweenBlocksAndCanBeDisabled(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  string
	}{
		{name: "cookies are reused by default", want: "session-42"},
		{name: "disable-cookie stops it", field: "disable-cookie: true", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "session-42"})
					fmt.Fprint(w, "logged in")
					return
				}
				if cookie, err := r.Cookie("session"); err == nil {
					seen = cookie.Value
				}
				fmt.Fprint(w, "no match here")
			}))
			defer server.Close()

			source := fmt.Sprintf(`
id: cookie-reuse
info:
  name: cookie reuse
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/login"
    extractors:
      - type: regex
        name: page
        regex:
          - "(logged in)"
  - method: GET
    path:
      - "{{RootURL}}/private"
    %s
    matchers:
      - type: word
        words: ["this never matches"]
`, tc.field)

			runAgainstServer(t, source, server, "/")

			if seen != tc.want {
				t.Errorf("the second request carried session=%q, want %q", seen, tc.want)
			}
		})
	}
}

// TestPayloadFileIsReadNotSent pins the payload file form: a bare scalar names a
// helper file, and treating the filename as the payload sends a request that can
// never match.
func TestPayloadFileIsReadNotSent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pages.txt"), []byte("admin\nlogin\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	source := `
id: payload-file
info:
  name: payload file
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/?page={{pages}}"
    payloads:
      pages: pages.txt
    matchers:
      - type: word
        words: ["this never matches"]
`
	if err := os.WriteFile(filepath.Join(dir, "payload-file.yaml"), []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Query().Get("page"))
		fmt.Fprint(w, "nothing here")
	}))
	defer server.Close()

	templates, errs := LoadDir(dir)
	if len(errs) > 0 {
		t.Fatalf("LoadDir: %v", errs)
	}
	if len(templates) != 1 {
		t.Fatalf("loaded %d templates, want 1", len(templates))
	}

	client, _ := httpclient.New(httpclient.Options{})
	target, _ := httpmsg.NewRequest("GET", server.URL+"/")
	NewRunner(client).Execute(context.Background(), templates[0], target, nil, nil)

	if strings.Join(seen, ",") != "admin,login" {
		t.Errorf("payloads sent were %v, want the file's lines", seen)
	}
}

// TestMissingPayloadFileRefusesTheTemplate pins the other half of that rule: a
// template whose wordlist is missing is refused, not run with the filename as
// its payload.
func TestMissingPayloadFileRefusesTheTemplate(t *testing.T) {
	dir := t.TempDir()
	source := `
id: missing-payload
info:
  name: missing payload
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/?page={{pages}}"
    payloads:
      pages: not-here.txt
    matchers:
      - type: word
        words: ["x"]
`
	if err := os.WriteFile(filepath.Join(dir, "missing-payload.yaml"), []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	templates, errs := LoadDir(dir)
	if len(templates) != 0 {
		t.Error("a template with a missing payload file was loaded")
	}
	if len(errs) == 0 {
		t.Error("the missing payload file was not reported")
	}
}

// TestPayloadBudgetIsReportedNotSilent pins the request budget: exceeding it is
// announced when templates are loaded, and the run sends exactly what was
// announced.
func TestPayloadBudgetIsReportedNotSilent(t *testing.T) {
	dir := t.TempDir()
	values := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		values = append(values, fmt.Sprintf(`"%d"`, i))
	}
	source := fmt.Sprintf(`
id: budget
info:
  name: budget
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/?n={{n}}"
    payloads:
      n: [%s]
    matchers:
      - type: word
        words: ["this never matches"]
`, strings.Join(values, ", "))
	if err := os.WriteFile(filepath.Join(dir, "budget.yaml"), []byte(source), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Query().Get("n"))
		fmt.Fprint(w, "nothing here")
	}))
	defer server.Close()

	client, _ := httpclient.New(httpclient.Options{})
	runner := NewRunner(client)
	loaded, unsupported, truncated, errs := LoadChecks(runner, []string{dir})
	if len(errs) > 0 || len(unsupported) > 0 {
		t.Fatalf("LoadChecks: errs=%v unsupported=%v", errs, unsupported)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d checks, want 1", len(loaded))
	}
	if len(truncated) != 1 || truncated[0].Described != 100 || truncated[0].Sent != MaxPayloadCombinations {
		t.Fatalf("truncation was not reported: %+v", truncated)
	}

	target, _ := httpmsg.NewRequest("GET", server.URL+"/")
	runner.Execute(context.Background(), loaded[0].Template(), target, nil, nil)
	if len(seen) != MaxPayloadCombinations {
		t.Errorf("sent %d request(s), want %d", len(seen), MaxPayloadCombinations)
	}
}

// TestJSONExtractorEvaluatesTheSupportedSubset pins the shapes of jq crackweb
// evaluates, and that the rest are refused rather than guessed at.
func TestJSONExtractorEvaluatesTheSupportedSubset(t *testing.T) {
	document := `{"token":"abc123","other":null,"data":{"items":[{"id":1},{"id":2}]}}`

	cases := []struct {
		expression string
		want       []string
	}{
		{expression: ".token", want: []string{"abc123"}},
		{expression: ".data.items[]", want: []string{"{\"id\":1}", "{\"id\":2}"}},
		{expression: ".data.items[1].id", want: []string{"2"}},
		{expression: ".missing // .token", want: []string{"abc123"}},
	}
	for _, tc := range cases {
		got := extractJSON(Extractor{Type: "json", JSON: StringList{tc.expression}}, document)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("extractJSON(%q) = %v, want %v", tc.expression, got, tc.want)
		}
	}

	for _, expression := range []string{".a | .b", "select(.id == 1)", ".items[].name | length", ".a||.b"} {
		if jsonPathSupported(expression) {
			t.Errorf("%q was accepted as a json path", expression)
		}
	}
}

// TestKValAndDSLExtractorsReadNamedData pins the two extractors that read the
// response's data by name rather than by part.
func TestKValAndDSLExtractorsReadNamedData(t *testing.T) {
	data := map[string]Value{
		"body":         StringValue("the body"),
		"status_code":  NumberValue(200),
		"content_type": StringValue("application/json"),
	}

	kval := extractorValues(Extractor{Type: "kval", KVal: StringList{"content_type", "status_code"}}, nil, data)
	if strings.Join(kval, ",") != "application/json,200" {
		t.Errorf("kval values = %v", kval)
	}

	dsl := extractorValues(Extractor{Type: "dsl", DSL: StringList{"status_code"}}, nil, data)
	if strings.Join(dsl, ",") != "200" {
		t.Errorf("dsl values = %v", dsl)
	}

	// An expression over a variable this response does not have produces
	// nothing, rather than an empty value that a later request would send.
	missing := extractorValues(Extractor{Type: "dsl", DSL: StringList{"dns_cname"}}, nil, data)
	if len(missing) != 0 {
		t.Errorf("dsl over an unknown variable = %v, want nothing", missing)
	}
}

// TestDSLExpressionsResolveStringMarkers pins the marker nuclei resolves before
// evaluating a DSL expression: a variable written inside a string literal.
func TestDSLExpressionsResolveStringMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the token is tok-abc-123 in this page")
	}))
	defer server.Close()

	source := `
id: dsl-markers
info:
  name: dsl markers
  severity: info
variables:
  needle: tok-abc-123
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "contains(body, '{{needle}}')"
      - type: dsl
        dsl:
          - "status_code == 200"
`
	if findings := runAgainstServer(t, source, server, "/"); len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

// TestBaseURLAndPathJoinWithoutADoubleSlash pins the join nuclei performs: a
// template that writes "{{BaseURL}}/admin" against a target ending in "/" sends
// one request for /app/admin, not one for /app//admin.
func TestBaseURLAndPathJoinWithoutADoubleSlash(t *testing.T) {
	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		fmt.Fprint(w, "no match here")
	}))
	defer server.Close()

	source := `
id: baseurl-join
info:
  name: baseurl join
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: word
        words: ["this never matches"]
`
	runAgainstServer(t, source, server, "/app/")

	if seen != "/app/admin" {
		t.Errorf("request path = %q, want /app/admin", seen)
	}
}

// TestPartsAreTheNamesNucleiUses pins the part mapping: a part is a name in the
// data a response produces, and a name that is not there is not a part — not
// even for a negative matcher.
func TestPartsAreTheNamesNucleiUses(t *testing.T) {
	response := &httpmsg.Response{
		Status: 200,
		Header: httpmsg.NewHeader(httpmsg.KV{Name: "Content-Type", Value: "application/json"}),
		Body:   []byte("the body"),
	}

	data := map[string]Value{
		"body":         StringValue("the body"),
		"all_headers":  StringValue("Content-Type: application/json\n"),
		"status_code":  NumberValue(200),
		"content_type": StringValue("application/json"),
	}

	cases := []struct {
		part  string
		want  string
		found bool
	}{
		{part: "", want: "the body", found: true},
		{part: "body", want: "the body", found: true},
		{part: "header", want: "Content-Type: application/json\n", found: true},
		{part: "all", want: "the bodyContent-Type: application/json\n", found: true},
		{part: "content_type", want: "application/json", found: true},
		{part: "status_code", want: "200", found: true},
		{part: "raw", found: false},
		{part: "not_a_part", found: false},
	}
	for _, tc := range cases {
		got, found := partOf(tc.part, response, data)
		if found != tc.found || (found && got != tc.want) {
			t.Errorf("partOf(%q) = %q, %v; want %q, %v", tc.part, got, found, tc.want, tc.found)
		}
	}
}

// TestVariablesResolveInDocumentOrder pins the variables block: nuclei evaluates
// it in the order it was written, re-walking it as values arrive, so one
// variable may build on another.
func TestVariablesResolveInDocumentOrder(t *testing.T) {
	source := `
id: variables
info:
  name: variables
  severity: info
variables:
  base: "{{RootURL}}/api"
  version: "v2"
  endpoint: "{{base}}/{{version}}"
http:
  - method: GET
    path:
      - "{{endpoint}}"
    matchers:
      - type: word
        words: ["this never matches"]
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	base, err := url.Parse("https://example.com/app")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	vars := BuiltinVariables(base)
	tmpl.evaluateVariables(vars)

	if got := vars["endpoint"].String(); got != "https://example.com/api/v2" {
		t.Errorf("endpoint = %q", got)
	}
}

// TestWordMatcherEncodingHex pins "encoding: hex", which nuclei decodes when the
// template is compiled.
func TestWordMatcherEncodingHex(t *testing.T) {
	source := `
id: hex-words
info:
  name: hex words
  severity: info
http:
  - method: GET
    path:
      - "{{RootURL}}/"
    matchers:
      - type: word
        encoding: hex
        words:
          - "414243"
`
	tmpl, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := tmpl.Requests_()[0].Matchers[0].Words[0]; got != "ABC" {
		t.Errorf("hex word = %q, want ABC", got)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "xABCx")
	}))
	defer server.Close()

	client, _ := httpclient.New(httpclient.Options{})
	target, _ := httpmsg.NewRequest("GET", server.URL+"/")
	if findings := NewRunner(client).Execute(context.Background(), tmpl, target, nil, nil); len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}
