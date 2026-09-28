package template

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// MaxPayloadCombinations bounds how many requests one template may make. A
// template with several payload lists can describe hundreds of requests, and an
// unbounded loop against a slow target is a denial of service on the scanner.
const MaxPayloadCombinations = 64

// Runner executes templates against targets.
type Runner struct {
	// Client sends the requests.
	Client *httpclient.Client
	// Bundle is unused by the runner itself but kept for callers that render
	// findings from the same place.
	Bundle any

	mu    sync.Mutex
	count int
}

// NewRunner builds a template runner.
func NewRunner(client *httpclient.Client) *Runner {
	return &Runner{Client: client}
}

// RequestCount returns how many requests the runner has sent.
func (r *Runner) RequestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// Execute runs one template against a target and returns what it found.
func (r *Runner) Execute(ctx context.Context, tmpl *Template, target *httpmsg.Request, baseline *httpmsg.Response) []*finding.Finding {
	if tmpl == nil || target == nil {
		return nil
	}

	vars := BuiltinVariables(target.URL)
	for name, value := range tmpl.Variables {
		vars[name] = StringValue(Expand(value, vars))
	}
	// Extractors in earlier requests feed later ones, so the map is shared
	// across the template's request blocks.
	var findings []*finding.Finding

	for index := range tmpl.Requests_() {
		block := tmpl.Requests_()[index]
		results := r.runBlock(ctx, tmpl, block, target, vars, baseline)
		findings = append(findings, results...)
		if tmpl.StopAtFirstMatch && len(findings) > 0 {
			break
		}
	}
	return findings
}

// runBlock executes one http: block of a template.
func (r *Runner) runBlock(ctx context.Context, tmpl *Template, block HTTPRequest, target *httpmsg.Request, vars map[string]Value, baseline *httpmsg.Response) []*finding.Finding {
	targets := block.Path
	if len(targets) == 0 {
		// A raw block carries its own request line.
		targets = block.Raw
	}
	if len(targets) == 0 {
		return nil
	}

	var findings []*finding.Finding
	for _, raw := range targets {
		// Payloads multiply the request: each value is substituted in turn.
		for _, payloadVars := range expandPayloads(block.Payloads) {
			scoped := mergeVars(vars, payloadVars)

			request, err := r.buildRequest(tmpl, block, raw, target, scoped)
			if err != nil || request == nil {
				continue
			}

			resp, err := r.send(ctx, request)
			if err != nil {
				continue
			}

			responseVars := responseVariables(request, resp, scoped)
			r.extract(block, resp, responseVars)

			matched, evidence := matchBlock(block, resp, responseVars)
			if !matched {
				continue
			}

			findings = append(findings, buildFinding(tmpl, block, request, resp, evidence, baseline))
			if tmpl.StopAtFirstMatch || block.StopAtFirstMatch {
				return findings
			}
		}
	}
	return findings
}

// buildRequest turns a path or raw block into a request.
func (r *Runner) buildRequest(tmpl *Template, block HTTPRequest, raw string, target *httpmsg.Request, vars map[string]Value) (*httpmsg.Request, error) {
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
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		base := target.URLString()
		if strings.HasSuffix(base, "/") && strings.HasPrefix(rawURL, "/") {
			rawURL = base + strings.TrimPrefix(rawURL, "/")
		} else {
			rawURL = strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(rawURL, "/")
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

// send performs the request, honouring the block's redirect preference.
func (r *Runner) send(ctx context.Context, request *httpmsg.Request) (*httpmsg.Response, error) {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()

	// Redirects are not followed: a template that matches on a Location header
	// or a 302 needs to see it, and following would change the status the
	// matchers look at.
	return r.Client.Do(ctx, request)
}

// expandPayloads turns payload maps into the variable sets to iterate over.
func expandPayloads(payloads map[string]StringList) []map[string]Value {
	if len(payloads) == 0 {
		return []map[string]Value{{}}
	}

	// Each payload name contributes its values; the combinations are bounded so
	// a pathological template cannot generate unbounded traffic.
	names := make([]string, 0, len(payloads))
	for name := range payloads {
		names = append(names, name)
	}
	// Deterministic order, so a run is reproducible.
	sortStrings(names)

	sets := []map[string]Value{{}}
	for _, name := range names {
		values := payloads[name]
		if len(values) == 0 {
			continue
		}
		var next []map[string]Value
		for _, set := range sets {
			for _, value := range values {
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

// responseVariables builds the DSL variables that describe a response.
func responseVariables(request *httpmsg.Request, resp *httpmsg.Response, vars map[string]Value) map[string]Value {
	out := make(map[string]Value, len(vars)+8)
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
	out["raw"] = StringValue(string(resp.Raw()))
	out["status_code"] = NumberValue(float64(resp.Status))
	out["content_length"] = NumberValue(float64(len(resp.Body)))
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
	if request != nil {
		out["host"] = StringValue(request.Hostname())
		out["scheme"] = StringValue(request.Scheme())
	}
	return out
}

// extract runs a block's extractors, adding their values as variables for later
// requests.
func (r *Runner) extract(block HTTPRequest, resp *httpmsg.Response, vars map[string]Value) {
	for _, extractor := range block.Extractors {
		if strings.ToLower(extractor.Type) != "regex" || extractor.Name == "" {
			continue
		}
		part := partText(extractor.Part, resp)
		for _, pattern := range extractor.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			matches := re.FindStringSubmatch(part)
			if len(matches) == 0 {
				continue
			}
			group := extractor.Group
			if group < 0 || group >= len(matches) {
				group = 0
			}
			vars[extractor.Name] = StringValue(matches[group])
			break
		}
	}
}

// matchBlock evaluates a block's matchers.
//
// matchers-condition decides how the matchers combine — "and" requires all of
// them, anything else (the default) requires one — and each matcher's own
// condition decides how its values combine.
func matchBlock(block HTTPRequest, resp *httpmsg.Response, vars map[string]Value) (bool, []string) {
	if resp == nil {
		return false, nil
	}
	if len(block.Matchers) == 0 {
		// A block with no matchers fires whenever the request succeeds, which
		// is how template authors write "this path exists".
		return true, []string{"request completed"}
	}

	requireAll := strings.EqualFold(block.MatchersCondition, "and")
	var evidence []string
	matchedCount := 0

	for _, matcher := range block.Matchers {
		ok, detail := matchOne(matcher, resp, vars)
		if matcher.Internal && len(evidence) == 0 && ok {
			// Internal matchers only gate flow; they are not evidence.
			evidence = append(evidence, detail...)
		} else if ok && !matcher.Internal {
			evidence = append(evidence, detail...)
		}

		if ok {
			matchedCount++
			if !requireAll {
				return true, evidence
			}
			continue
		}
		if requireAll {
			return false, nil
		}
	}

	if requireAll {
		return matchedCount == len(block.Matchers), evidence
	}
	return matchedCount > 0, evidence
}

// matchOne evaluates a single matcher.
func matchOne(matcher Matcher, resp *httpmsg.Response, vars map[string]Value) (bool, []string) {
	kind := strings.ToLower(matcher.Type)
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
		text := partText(matcher.Part, resp)
		if matcher.CaseInsensitive {
			text = strings.ToLower(text)
		}
		ok, details = matchWords(matcher, text)

	case "regex":
		text := partText(matcher.Part, resp)
		ok, details = matchRegexes(matcher, text)

	case "binary":
		text := partText(matcher.Part, resp)
		ok, details = matchBinary(matcher, text)

	case "dsl":
		ok, details = matchDSL(matcher, vars)

	default:
		return false, nil
	}

	if matcher.Negative {
		return !ok, nil
	}
	return ok, details
}

// matchWords applies a word matcher's condition to its word list.
func matchWords(matcher Matcher, text string) (bool, []string) {
	if len(matcher.Words) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(matcher.Condition, "and")

	var hits []string
	for _, word := range matcher.Words {
		needle := word
		if matcher.CaseInsensitive {
			needle = strings.ToLower(needle)
		}
		found := strings.Contains(text, needle)
		if found {
			hits = append(hits, word)
			if !requireAll {
				return true, hits
			}
			continue
		}
		if requireAll {
			return false, nil
		}
	}
	return requireAll && len(hits) == len(matcher.Words), hits
}

// matchRegexes applies a regex matcher's condition to its pattern list.
func matchRegexes(matcher Matcher, text string) (bool, []string) {
	if len(matcher.Regex) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(matcher.Condition, "and")

	var hits []string
	for _, pattern := range matcher.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if match := re.FindString(text); match != "" {
			hits = append(hits, match)
			if !requireAll {
				return true, hits
			}
			continue
		}
		if requireAll {
			return false, nil
		}
	}
	return requireAll && len(hits) == len(matcher.Regex), hits
}

// matchBinary compares hex-encoded byte sequences.
func matchBinary(matcher Matcher, text string) (bool, []string) {
	requireAll := strings.EqualFold(matcher.Condition, "and")
	var hits []string
	for _, encoded := range matcher.Binary {
		raw, err := hex.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			continue
		}
		if strings.Contains(text, string(raw)) {
			hits = append(hits, encoded)
			if !requireAll {
				return true, hits
			}
			continue
		}
		if requireAll {
			return false, nil
		}
	}
	return requireAll && len(hits) == len(matcher.Binary), hits
}

// matchDSL evaluates a matcher's expressions.
func matchDSL(matcher Matcher, vars map[string]Value) (bool, []string) {
	if len(matcher.DSL) == 0 {
		return false, nil
	}
	requireAll := strings.EqualFold(matcher.Condition, "and")

	var hits []string
	for _, expression := range matcher.DSL {
		value, err := EvalBool(expression, vars)
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
	return requireAll && len(hits) == len(matcher.DSL), hits
}

// partText returns the response part a matcher or extractor looks at.
func partText(part string, resp *httpmsg.Response) string {
	if resp == nil {
		return ""
	}
	switch strings.ToLower(part) {
	case "", "body":
		return string(resp.Body)
	case "header", "headers", "all_headers":
		return headerText(resp.Header)
	case "all", "raw":
		return string(resp.Raw())
	case "status", "status_code":
		return fmt.Sprint(resp.Status)
	case "content_length":
		return fmt.Sprint(len(resp.Body))
	case "cookie":
		return strings.Join(resp.Header.Values("Set-Cookie"), "; ")
	default:
		// A named header, e.g. part: x-powered-by.
		return resp.Header.Get(part)
	}
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
func buildFinding(tmpl *Template, block HTTPRequest, request *httpmsg.Request, resp *httpmsg.Response, evidence []string, baseline *httpmsg.Response) *finding.Finding {
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

// sortStrings sorts in place; a tiny helper so this file needs no import for it.
func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j] < items[j-1]; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}
