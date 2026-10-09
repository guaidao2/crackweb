package template

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// MaxPayloadCombinations bounds how many requests one template may make. A
// template with several payload lists can describe thousands of requests, and
// an unbounded loop against a slow target is a denial of service on the
// scanner.
//
// The bound is announced rather than silent: a template that describes more
// combinations than this is still scanned, with the first MaxPayloadCombinations
// of them, and the loader reports how many were left out. A run that quietly
// covered a fraction of a template would report "nothing found" for a template
// nobody actually ran.
const MaxPayloadCombinations = 64

// Runner executes templates against targets.
type Runner struct {
	// Client sends the requests.
	Client *httpclient.Client
	// Bundle is unused by the runner itself but kept for callers that render
	// findings from the same place.
	Bundle any

	mu sync.Mutex
	// derived caches the clients a block asks for, keyed by the redirect and
	// cookie policy it named, so a template that follows redirects builds one
	// client instead of one per request.
	derived map[string]*httpclient.Client
}

// NewRunner builds a template runner.
func NewRunner(client *httpclient.Client) *Runner {
	return &Runner{Client: client}
}

// Execute runs one template against a target and returns what it found.
//
// observe, when it is not nil, is called with every request the template sends.
// It is a parameter rather than a field on the Runner because one runner serves
// every template in a scan — that is what a shared connection pool is for — and
// the counter it feeds belongs to the scan running this target.
func (r *Runner) Execute(ctx context.Context, tmpl *Template, target *httpmsg.Request, baseline *httpmsg.Response, observe func(*httpmsg.Request)) []*finding.Finding {
	if tmpl == nil || target == nil {
		return nil
	}

	vars := BuiltinVariables(target.URL)
	// The template's own identity is part of the data nuclei hands a DSL
	// expression, and templates do use it to say what they matched.
	vars["template-id"] = StringValue(tmpl.ID)
	vars["template-path"] = StringValue(tmpl.path)
	vars["type"] = StringValue("http")
	tmpl.evaluateVariables(vars)

	// Cookies are reused between the blocks of one template, which is nuclei's
	// default; a block turns that off with disable-cookie.
	jar, _ := cookiejar.New(nil)
	run := &templateRun{
		runner:   r,
		tmpl:     tmpl,
		target:   target,
		baseline: baseline,
		vars:     vars,
		internal: map[string][]string{},
		jar:      jar,
		observe:  observe,
	}

	for index := range tmpl.Requests_() {
		matched := run.block(ctx, tmpl.Requests_()[index])
		if matched && tmpl.StopAtFirstMatch {
			break
		}
	}
	return run.findings
}

// templateRun is one execution of one template against one target.
//
// It carries the state a template builds while it runs: the values its earlier
// blocks extracted, which the later blocks read, and the cookie jar nuclei
// keeps for the template's lifetime.
type templateRun struct {
	runner   *Runner
	tmpl     *Template
	target   *httpmsg.Request
	baseline *httpmsg.Response

	// vars are the variables every request block starts from. An extractor adds
	// what it found here, which is how data flows from one block to the next.
	vars map[string]Value
	// internal holds the values of extractors marked internal. Those are the
	// ones a later block can be iterated over, one request per value.
	internal map[string][]string
	// jar is shared by the blocks of the template.
	jar http.CookieJar
	// observe reports each request to the scan that started this run.
	observe func(*httpmsg.Request)
	// findings accumulates what the run reported.
	findings []*finding.Finding
}

// block executes one http: block and reports whether it matched.
func (run *templateRun) block(ctx context.Context, block HTTPRequest) bool {
	targets := block.Path
	if len(targets) == 0 {
		// A raw block carries its own request line.
		targets = block.Raw
	}
	if len(targets) == 0 {
		return false
	}

	client := run.runner.clientFor(run.jar, block)
	// req-condition keeps the conversation. nuclei stores every request's
	// variables under a numbered name as well as its own, so a matcher can
	// compare response 1 with response 2 instead of only seeing the last one.
	conversation := map[string]Value{}
	requestNumber := 0
	matched := false

	// The sets an internal extractor produced do not depend on the payloads, so
	// they are built once for the block rather than once per payload value.
	dynamicSets := run.dynamicSets(block)
	for _, raw := range targets {
		for _, payloadVars := range payloadSets(block) {
			for _, dynamicVars := range dynamicSets {
				scoped := mergeVars(run.vars, payloadVars)
				scoped = mergeVars(scoped, dynamicVars)

				request, err := buildRequest(block, raw, run.target, scoped)
				if err != nil || request == nil {
					continue
				}
				resp, err := run.send(ctx, client, request)
				if err != nil {
					continue
				}

				requestNumber++
				data := responseVariables(request, resp, scoped)
				run.extract(block, resp, data)
				if block.ReqCondition {
					conversation = numberVariables(conversation, data, requestNumber)
				}

				evidence, ok := matchBlock(block, resp, mergeVars(conversation, data))
				if !ok {
					continue
				}

				run.findings = append(run.findings, buildFinding(run.tmpl, request, resp, evidence, run.baseline))
				matched = true
				if run.tmpl.StopAtFirstMatch || block.StopAtFirstMatch {
					return matched
				}
			}
		}
	}
	return matched
}

// send performs the request and reports it to the scan.
func (run *templateRun) send(ctx context.Context, client *httpclient.Client, request *httpmsg.Request) (*httpmsg.Response, error) {
	if run.observe != nil {
		run.observe(request)
	}

	// The client carries the block's redirect and cookie policy, so a template
	// that asks to follow redirects sees the page it lands on and one that does
	// not sees the 302 it matched on.
	return client.Do(ctx, request)
}

// clientFor returns the client a block's redirect and cookie fields ask for.
func (r *Runner) clientFor(jar http.CookieJar, block HTTPRequest) *httpclient.Client {
	policy := httpclient.RedirectPolicy{
		Follow:     block.Redirects || block.HostRedirects || block.ProtocolRedirects,
		SameHost:   block.HostRedirects,
		SameScheme: block.ProtocolRedirects,
		Max:        block.MaxRedirects,
	}
	useJar := !block.DisableCookie

	key := fmt.Sprintf("%t|%t|%t|%d|%t|%p", policy.Follow, policy.SameHost, policy.SameScheme, policy.Max, useJar, jar)
	r.mu.Lock()
	if client, ok := r.derived[key]; ok {
		r.mu.Unlock()
		return client
	}
	if r.derived == nil {
		r.derived = map[string]*httpclient.Client{}
	}
	client := r.Client.Derived(policy, jar, useJar)
	r.derived[key] = client
	r.mu.Unlock()
	return client
}

// buildRequest turns a path or raw block into a request.
func buildRequest(block HTTPRequest, raw string, target *httpmsg.Request, vars map[string]Value) (*httpmsg.Request, error) {
	// A raw block is a full request line plus headers; crackweb parses it the
	// same way it parses a pasted capture.
	if strings.HasPrefix(strings.TrimSpace(strings.ToUpper(raw)), "GET ") ||
		strings.Contains(raw, " HTTP/1.") {
		request, err := httpmsg.ParseRequest([]byte(Expand(raw, vars)), httpmsg.ParseOptions{
			ForceHTTPS: target.Scheme() == "https",
		})
		if err != nil {
			return nil, err
		}
		request.Origin = httpmsg.OriginReplay
		return request, nil
	}

	rawURL := Expand(raw, vars)
	joinedWithSlash := leadingVariableSlash(raw)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		base := target.URLString()
		if strings.HasSuffix(base, "/") && strings.HasPrefix(rawURL, "/") {
			rawURL = base + strings.TrimPrefix(rawURL, "/")
		} else {
			rawURL = strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(rawURL, "/")
		}
	}
	// A template joins a variable to a path — "{{BaseURL}}/admin" — and nuclei
	// trims the target's own trailing slash before that join, so the two
	// spellings name one page rather than two. A template that writes its own
	// double slash keeps both, which trimming the variable leaves alone.
	if joinedWithSlash {
		if base := target.URLString(); strings.HasSuffix(base, "/") && strings.HasPrefix(rawURL, base+"/") {
			rawURL = strings.TrimSuffix(base, "/") + rawURL[len(base):]
		}
	}
	if _, err := url.Parse(rawURL); err != nil {
		return nil, err
	}

	method := block.Method
	if method == "" {
		method = "GET"
	}
	request, err := httpmsg.NewRequest(strings.ToUpper(method), rawURL)
	if err != nil {
		return nil, err
	}
	request.Origin = httpmsg.OriginReplay

	for name, value := range block.Headers {
		request.Header.Set(name, Expand(value, vars))
	}
	if block.Body != "" {
		body := Expand(block.Body, vars)
		request.Body = []byte(body)
		request.Header.Set("Content-Length", fmt.Sprint(len(body)))
		if request.Header.Get("Content-Type") == "" {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if request.Header.Get("Host") == "" {
		request.Header.Set("Host", request.URL.Host)
	}
	return request, nil
}

// leadingVariableSlash reports whether a path begins with a variable followed by
// a slash, which is how nuclei decides to trim the target's own trailing slash
// before joining.
func leadingVariableSlash(path string) bool {
	rest := strings.TrimPrefix(strings.TrimSpace(path), "{{")
	if rest == path {
		return false
	}
	end := strings.Index(rest, "}}")
	if end < 0 || end == 0 {
		return false
	}
	for i := 0; i < end; i++ {
		b := rest[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' {
			continue
		}
		return false
	}
	return strings.HasPrefix(rest[end+2:], "/")
}

// payloadSets expands a block's payloads into the variable sets to send, which
// is where nuclei's three attack types differ.
//
// batteringram (the default) sends each payload list in turn, binding one name
// per request: two lists of five are ten requests. pitchfork advances every list
// together, so it makes as many requests as the shortest list. clusterbomb is
// the cross product, which is what "try every combination" means. Reading the
// attack type as decoration and always sending the cross product is how a
// template ends up sending thousands of requests nuclei never sends.
func payloadSets(block HTTPRequest) []map[string]Value {
	if len(block.Payloads) == 0 {
		return []map[string]Value{{}}
	}

	// Deterministic order, so a run is reproducible and the cap is meaningful.
	names := make([]string, 0, len(block.Payloads))
	for name, payload := range block.Payloads {
		if len(payload.Values()) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []map[string]Value{{}}
	}

	switch strings.ToLower(strings.TrimSpace(block.Attack)) {
	case "pitchfork":
		return pitchforkSets(names, block.Payloads)
	case "clusterbomb":
		return clusterbombSets(names, block.Payloads)
	default:
		return batteringRamSets(names, block.Payloads)
	}
}

// batteringRamSets binds one payload name at a time, up to the budget.
func batteringRamSets(names []string, payloads map[string]Payload) []map[string]Value {
	var sets []map[string]Value
	for _, name := range names {
		for _, value := range payloads[name].Values() {
			if len(sets) >= MaxPayloadCombinations {
				return sets
			}
			sets = append(sets, map[string]Value{name: StringValue(value)})
		}
	}
	return sets
}

// pitchforkSets advances every list together, so the shortest list decides how
// many requests are made.
func pitchforkSets(names []string, payloads map[string]Payload) []map[string]Value {
	shortest := len(payloads[names[0]].Values())
	for _, name := range names {
		if n := len(payloads[name].Values()); n < shortest {
			shortest = n
		}
	}

	var sets []map[string]Value
	for i := 0; i < shortest; i++ {
		if len(sets) >= MaxPayloadCombinations {
			break
		}
		set := make(map[string]Value, len(names))
		for _, name := range names {
			set[name] = StringValue(payloads[name].Values()[i])
		}
		sets = append(sets, set)
	}
	return sets
}

// clusterbombSets is the cross product of every payload list.
func clusterbombSets(names []string, payloads map[string]Payload) []map[string]Value {
	sets := []map[string]Value{{}}
	for _, name := range names {
		var next []map[string]Value
		for _, set := range sets {
			for _, value := range payloads[name].Values() {
				if len(next) >= MaxPayloadCombinations {
					break
				}
				clone := make(map[string]Value, len(set)+1)
				for k, v := range set {
					clone[k] = v
				}
				clone[name] = StringValue(value)
				next = append(next, clone)
			}
		}
		sets = next
	}
	return sets
}

// payloadCombinationCount returns how many requests a block's payloads describe
// before the budget is applied. The loader compares it with MaxPayloadCombinations
// so it can say what a run will leave out.
func payloadCombinationCount(block HTTPRequest) int {
	if len(block.Payloads) == 0 {
		return 1
	}

	count := 0
	switch strings.ToLower(strings.TrimSpace(block.Attack)) {
	case "pitchfork":
		first := true
		for _, payload := range block.Payloads {
			values := len(payload.Values())
			if values == 0 {
				continue
			}
			if first || values < count {
				count = values
			}
			first = false
		}
	case "clusterbomb":
		count = 1
		for _, payload := range block.Payloads {
			values := len(payload.Values())
			if values == 0 {
				continue
			}
			count *= values
		}
	default:
		for _, payload := range block.Payloads {
			count += len(payload.Values())
		}
	}
	if count < 1 {
		return 1
	}
	return count
}

// dynamicSets returns the variable sets a block is sent with when an earlier
// block's internal extractor produced values.
//
// nuclei sends one request with the first value of each extraction, and one
// request per value (every list advancing together, short ones repeating their
// last value) when the template asks for it with "iterate-all". The difference
// matters for the common login-then-reuse shape: without it, a template that
// extracted three CSRF tokens only ever tries the first.
func (run *templateRun) dynamicSets(block HTTPRequest) []map[string]Value {
	if len(run.internal) == 0 {
		return []map[string]Value{{}}
	}

	names := make([]string, 0, len(run.internal))
	for name, values := range run.internal {
		if len(values) > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []map[string]Value{{}}
	}

	if !block.IterateAll {
		set := make(map[string]Value, len(names))
		for _, name := range names {
			set[name] = StringValue(run.internal[name][0])
		}
		return []map[string]Value{set}
	}

	longest := 0
	for _, name := range names {
		if n := len(run.internal[name]); n > longest {
			longest = n
		}
	}

	var sets []map[string]Value
	for i := 0; i < longest; i++ {
		set := make(map[string]Value, len(names))
		for _, name := range names {
			values := run.internal[name]
			if i < len(values) {
				set[name] = StringValue(values[i])
				continue
			}
			set[name] = StringValue(values[len(values)-1])
		}
		sets = append(sets, set)
	}
	return sets
}

// responseVariables builds the variables that describe a response.
//
// The names are nuclei's, because a template is written against them: body,
// all_headers, header, status_code, content_length, duration, the response's
// headers with dashes turned into underscores, its cookies by name, and the
// request and response as they went over the wire.
func responseVariables(request *httpmsg.Request, resp *httpmsg.Response, vars map[string]Value) map[string]Value {
	out := make(map[string]Value, len(vars)+16)
	for k, v := range vars {
		out[k] = v
	}
	if resp == nil {
		return out
	}

	body := string(resp.Body)
	header := headerText(resp.Header)

	out["body"] = StringValue(body)
	out["all_headers"] = StringValue(header)
	out["header"] = StringValue(header)
	out["raw"] = StringValue(string(resp.Raw()))
	out["response"] = StringValue(string(resp.Raw()))
	out["status_code"] = NumberValue(float64(resp.Status))
	out["content_length"] = NumberValue(float64(contentLength(resp)))
	out["duration"] = NumberValue(resp.Duration.Seconds())
	out["cookie"] = StringValue(strings.Join(resp.Header.Values("Set-Cookie"), "; "))

	// Individual headers are exposed under their name with dashes turned into
	// underscores, which is the spelling nuclei templates use.
	for _, field := range resp.Header.All() {
		key := strings.ReplaceAll(strings.ToLower(field.Name), "-", "_")
		if _, exists := out[key]; !exists {
			out[key] = StringValue(field.Value)
		}
	}
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		name, value, ok := responseCookie(cookie)
		if !ok {
			continue
		}
		if _, exists := out[name]; !exists {
			out[name] = StringValue(value)
		}
	}
	if request != nil {
		out["request"] = StringValue(string(request.Raw()))
		out["host"] = StringValue(request.Hostname())
		out["scheme"] = StringValue(request.Scheme())
	}
	return out
}

// contentLength is the length nuclei reports: what the response says it sent
// when it says anything, and the body it actually sent otherwise.
func contentLength(resp *httpmsg.Response) int {
	if raw := strings.TrimSpace(resp.Header.Get("Content-Length")); raw != "" {
		if length, err := strconv.Atoi(raw); err == nil && length >= 0 {
			return length
		}
	}
	return len(resp.Body)
}

// responseCookie pulls the name and value out of a Set-Cookie header, which is
// how nuclei exposes a response's cookies to a DSL expression.
func responseCookie(header string) (name, value string, ok bool) {
	pair := strings.SplitN(header, ";", 2)[0]
	name, value, ok = strings.Cut(pair, "=")
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	if !ok || name == "" {
		return "", "", false
	}
	return name, value, true
}

// extract runs a block's extractors and adds what they found to the run.
func (run *templateRun) extract(block HTTPRequest, resp *httpmsg.Response, data map[string]Value) {
	for _, extractor := range block.Extractors {
		name := strings.TrimSpace(extractor.Name)
		if name == "" {
			// An unnamed extractor has nothing to bind its values to; nuclei
			// only prints them.
			continue
		}

		values := extractorValues(extractor, resp, data)
		if len(values) == 0 {
			continue
		}

		// Both kinds of extractor stay readable for the rest of the template,
		// which is what nuclei's event accumulation does. Only an internal one
		// also drives the requests that follow.
		data[name] = extractedValue(values)
		run.vars[name] = extractedValue(values)
		if !extractor.Internal {
			continue
		}
		run.internal[name] = values
		// nuclei exposes a multi-valued internal extraction under numbered
		// names as well, so a template can reach the second value by name.
		for index, value := range values {
			data[name+strconv.Itoa(index)] = StringValue(value)
		}
	}
}

// extractedValue renders what an extractor found.
//
// A single value is itself. Several values become one space-separated string,
// which is usable in a request where nuclei would hand over a list.
func extractedValue(values []string) Value {
	if len(values) == 1 {
		return StringValue(values[0])
	}
	return StringValue(strings.Join(values, " "))
}

// numberVariables stores one request's variables under a numbered name.
func numberVariables(conversation, data map[string]Value, requestNumber int) map[string]Value {
	if conversation == nil {
		conversation = map[string]Value{}
	}
	suffix := "_" + strconv.Itoa(requestNumber)
	for name, value := range data {
		conversation[name+suffix] = value
	}
	return conversation
}

// partOf returns the response text a matcher or extractor looks at, and whether
// that part exists.
//
// nuclei resolves a part by name against the same data a DSL expression sees,
// so "content_type" is a header and "status_code" is the status; a name it does
// not know is not a part rather than an empty string, and a matcher over a part
// that does not exist does not match — not even a negative one. Answering an
// unknown part with "" would make every word matcher on it match, which is how
// a template reports a leak for a header the server never sent.
func partOf(part string, resp *httpmsg.Response, data map[string]Value) (string, bool) {
	if resp == nil {
		return "", false
	}

	switch strings.ToLower(strings.TrimSpace(part)) {
	case "", "body":
		return string(resp.Body), true
	case "header":
		return headerText(resp.Header), true
	case "all":
		return string(resp.Body) + headerText(resp.Header), true
	}

	if value, ok := data[strings.TrimSpace(part)]; ok {
		return value.String(), true
	}
	return "", false
}

// matchBlock evaluates a block's matchers.
//
// matchers-condition decides how the matchers combine — "and" requires all of
// them, anything else (the default) requires one — and each matcher's own
// condition decides how its values combine.
func matchBlock(block HTTPRequest, resp *httpmsg.Response, data map[string]Value) ([]string, bool) {
	if resp == nil {
		return nil, false
	}
	if len(block.Matchers) == 0 {
		// A block with no matchers and no extractors is refused when the
		// template is loaded; a block that only extracts is scaffolding for a
		// later request and reports nothing. Either way there is nothing to
		// report here.
		return nil, false
	}

	requireAll := strings.EqualFold(strings.TrimSpace(block.MatchersCondition), "and")
	var evidence []string
	matched := 0

	for _, matcher := range block.Matchers {
		ok, detail := matchOne(matcher, resp, data)
		if ok && !matcher.Internal {
			// An internal matcher decides whether the block matched but is not
			// evidence: nuclei hides it from the output.
			evidence = append(evidence, detail...)
		}
		if ok {
			matched++
			if !requireAll {
				return evidence, true
			}
			continue
		}
		if requireAll {
			return nil, false
		}
	}

	if requireAll {
		return evidence, true
	}
	return evidence, matched > 0
}

// matchOne evaluates a single matcher.
func matchOne(matcher Matcher, resp *httpmsg.Response, data map[string]Value) (bool, []string) {
	kind := strings.ToLower(strings.TrimSpace(matcher.Type))
	if kind == "" {
		kind = "word"
	}

	var (
		ok      bool
		details []string
	)

	switch kind {
	case "status":
		for _, want := range matcher.Status {
			if resp.Status == want {
				ok = true
				details = append(details, fmt.Sprintf("status %d", resp.Status))
				break
			}
		}

	case "size":
		for _, want := range matcher.Size {
			if len(resp.Body) == want {
				ok = true
				details = append(details, fmt.Sprintf("body length %d", len(resp.Body)))
				break
			}
		}

	case "word":
		text, found := partOf(matcher.Part, resp, data)
		if !found {
			return false, nil
		}
		if matcher.CaseInsensitive {
			text = strings.ToLower(text)
		}
		ok, details = matchWords(matcher, text, data)

	case "regex":
		text, found := partOf(matcher.Part, resp, data)
		if !found {
			return false, nil
		}
		ok, details = matchRegexes(matcher, text)

	case "binary":
		text, found := partOf(matcher.Part, resp, data)
		if !found {
			return false, nil
		}
		ok, details = matchBinary(matcher, text)

	case "dsl":
		ok, details = matchDSL(matcher, data)

	default:
		return false, nil
	}

	if matcher.Negative {
		return !ok, nil
	}
	return ok, details
}

// matchWords applies a word matcher's condition to its word list.
func matchWords(matcher Matcher, corpus string, data map[string]Value) (bool, []string) {
	if len(matcher.Words) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(strings.TrimSpace(matcher.Condition), "and")

	var hits []string
	for _, word := range matcher.Words {
		// A word may carry a variable, which is how a template matches on what
		// it extracted or on a helper such as {{Hostname}}.
		needle := Expand(word, data)
		if matcher.CaseInsensitive {
			needle = strings.ToLower(needle)
		}
		if !strings.Contains(corpus, needle) {
			if requireAll {
				return false, nil
			}
			continue
		}

		hits = append(hits, word)
		if !requireAll && !matcher.MatchAll {
			return true, hits
		}
	}

	if requireAll && len(hits) != len(matcher.Words) {
		return false, nil
	}
	return len(hits) > 0, hits
}

// matchRegexes applies a regex matcher's condition to its pattern list.
//
// match-all keeps scanning after the first hit so every occurrence becomes
// evidence, which is what a template uses to collect every link on a page
// rather than the first one.
func matchRegexes(matcher Matcher, corpus string) (bool, []string) {
	if len(matcher.Regex) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(strings.TrimSpace(matcher.Condition), "and")

	var hits []string
	matchedPatterns := 0
	for _, pattern := range matcher.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// Uncompilable patterns are refused when the template is loaded, so
			// this is a pattern that slipped through: no match, never a panic.
			if requireAll {
				return false, nil
			}
			continue
		}

		found := re.FindAllString(corpus, -1)
		if len(found) == 0 {
			if requireAll {
				return false, nil
			}
			continue
		}

		matchedPatterns++
		hits = append(hits, found...)
		if !requireAll && !matcher.MatchAll {
			return true, found[:1]
		}
	}

	if requireAll {
		return matchedPatterns == len(matcher.Regex), hits
	}
	return len(hits) > 0, hits
}

// matchBinary compares hex-encoded byte sequences.
func matchBinary(matcher Matcher, corpus string) (bool, []string) {
	if len(matcher.Binary) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(strings.TrimSpace(matcher.Condition), "and")

	var hits []string
	matchedValues := 0
	for _, encoded := range matcher.Binary {
		raw, err := hex.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			continue
		}
		if !strings.Contains(corpus, string(raw)) {
			if requireAll {
				return false, nil
			}
			continue
		}

		matchedValues++
		hits = append(hits, encoded)
		if !requireAll && !matcher.MatchAll {
			return true, hits
		}
	}

	if requireAll {
		return matchedValues == len(matcher.Binary), hits
	}
	return len(hits) > 0, hits
}

// matchDSL evaluates a matcher's expressions.
//
// An expression that cannot be evaluated — a variable the template did not
// define, a syntax error — is not a match. nuclei does the same, and the
// alternative is worse than it sounds: an unknown name that evaluated to ""
// turns contains(body, name) into "every response contains the empty string".
func matchDSL(matcher Matcher, data map[string]Value) (bool, []string) {
	if len(matcher.DSL) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(strings.TrimSpace(matcher.Condition), "and")

	var hits []string
	for _, expression := range matcher.DSL {
		// A DSL expression may carry a variable inside a string literal, which
		// nuclei resolves before evaluating.
		value, err := EvalBool(Expand(expression, data), data)
		if err == nil && value {
			hits = append(hits, expression)
			if !requireAll {
				return true, hits
			}
			continue
		}
		if requireAll {
			return false, nil
		}
	}

	if requireAll {
		return len(hits) == len(matcher.DSL), hits
	}
	return len(hits) > 0, hits
}

// headerText renders the header block.
func headerText(header httpmsg.Header) string {
	var b strings.Builder
	for _, field := range header.All() {
		b.WriteString(field.Name)
		b.WriteString(": ")
		b.WriteString(field.Value)
		b.WriteString("\n")
	}
	return b.String()
}

// buildFinding turns a matched template into a finding.
func buildFinding(tmpl *Template, request *httpmsg.Request, resp *httpmsg.Response, evidence []string, baseline *httpmsg.Response) *finding.Finding {
	severity := finding.ParseSeverity(tmpl.Info.Severity)

	f := &finding.Finding{
		CheckID:     "template:" + tmpl.ID,
		Title:       tmpl.Info.Name,
		Description: tmpl.Info.Description,
		Severity:    severity,
		Confidence:  finding.ConfidenceFirm,
		TemplateID:  tmpl.ID,
		Method:      request.Method,
		URL:         request.URLString(),
		FoundAt:     time.Now(),
	}

	f.Tags = append(f.Tags, tmpl.Info.Tags...)
	if len(tmpl.Info.Reference) > 0 {
		f.References = append(f.References, tmpl.Info.Reference...)
	}
	if len(tmpl.Info.Classification.CVEID) > 0 {
		f.Tags = append(f.Tags, tmpl.Info.Classification.CVEID...)
	}
	if len(tmpl.Info.Classification.CWEID) > 0 {
		f.CWE = tmpl.Info.Classification.CWEID[0]
	}

	f.Evidence.Request = request.Raw()
	f.Evidence.Response = resp.Raw()
	if len(f.Evidence.Response) > 8192 {
		f.Evidence.Response = f.Evidence.Response[:8192]
	}
	if baseline != nil {
		f.Evidence.Baseline = baseline.Body
	}
	f.Evidence.Matches = evidence
	f.Evidence.Duration = resp.Duration

	return f
}

// mergeVars combines two variable maps without mutating either.
func mergeVars(base, extra map[string]Value) map[string]Value {
	out := make(map[string]Value, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
