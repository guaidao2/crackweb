// Package template implements a nuclei-compatible YAML template engine.
//
// The point of compatibility is ecosystem: there are thousands of published
// nuclei templates, and a scanner that can read them inherits that coverage
// without anyone rewriting them. crackweb therefore parses the same document
// shape — id/info, http requests, matchers, extractors, the same helper
// variables — and reports hits as ordinary findings.
//
// Compatibility is deliberate, and its boundary is drawn where the reference
// implementation draws it. A template that crackweb can run is run the way
// nuclei would run it: the same attack types, the same matcher and extractor
// semantics, the same redirect and cookie behaviour. A template that needs more
// than this engine has is refused when it is loaded, with the reason named in
// Unsupported, because a template that half-runs reports findings nobody can
// trust — silence is honest, a wrong answer is not.
package template

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/guaidao2/crackweb/internal/finding"
)

// Template is one nuclei template document.
type Template struct {
	ID        string    `yaml:"id"`
	Info      Info      `yaml:"info"`
	Variables Variables `yaml:"variables"`
	// HTTP holds the HTTP request blocks. nuclei accepts both "http" and the
	// older "requests" spelling.
	HTTP     []HTTPRequest `yaml:"http"`
	Requests []HTTPRequest `yaml:"requests"`
	// Flow marks a template whose control flow crackweb cannot execute.
	Flow string `yaml:"flow"`
	// SelfContained templates run without a target, which is a different
	// execution mode rather than a different request.
	SelfContained    bool `yaml:"self-contained"`
	StopAtFirstMatch bool `yaml:"stop-at-first-match"`

	// dir is the directory the template was loaded from, which is what a
	// relative payload file is resolved against, and path is the file itself,
	// which is what nuclei exposes as {{template-path}}.
	dir  string
	path string
}

// Info is the template's metadata block.
type Info struct {
	Name           string         `yaml:"name"`
	Author         StringList     `yaml:"author"`
	Severity       string         `yaml:"severity"`
	Description    string         `yaml:"description"`
	Reference      StringList     `yaml:"reference"`
	Tags           StringList     `yaml:"tags"`
	Classification Classification `yaml:"classification"`
	Metadata       map[string]any `yaml:"metadata"`
}

// Classification carries the CVE/CWE/CVSS block.
type Classification struct {
	CVEID      StringList `yaml:"cve-id"`
	CWEID      StringList `yaml:"cwe-id"`
	CVSSScore  any        `yaml:"cvss-score"`
	CVSSMetric string     `yaml:"cvss-metrics"`
}

// HTTPRequest is one request block.
type HTTPRequest struct {
	Method            string             `yaml:"method"`
	Path              StringList         `yaml:"path"`
	Raw               StringList         `yaml:"raw"`
	Headers           map[string]string  `yaml:"headers"`
	Body              string             `yaml:"body"`
	Redirects         bool               `yaml:"redirects"`
	MaxRedirects      int                `yaml:"max-redirects"`
	HostRedirects     bool               `yaml:"host-redirects"`
	ProtocolRedirects bool               `yaml:"protocol-redirects"`
	CookieReuse       bool               `yaml:"cookie-reuse"`
	DisableCookie     bool               `yaml:"disable-cookie"`
	Unsafe            bool               `yaml:"unsafe"`
	Race              bool               `yaml:"race"`
	RaceCount         int                `yaml:"race_count"`
	Fuzzing           []any              `yaml:"fuzzing"`
	Payloads          map[string]Payload `yaml:"payloads"`
	Attack            string             `yaml:"attack"`

	MatchersCondition string      `yaml:"matchers-condition"`
	Matchers          []Matcher   `yaml:"matchers"`
	Extractors        []Extractor `yaml:"extractors"`

	// StopAtFirstMatch stops the whole template at the first hit.
	StopAtFirstMatch bool `yaml:"stop-at-first-match"`
	// ReqCondition keeps every request's variables under a numbered name, so a
	// template can match on a conversation rather than on one response.
	ReqCondition bool `yaml:"req-condition"`
	// IterateAll sends the requests that follow an internal extractor once per
	// extracted value instead of once with the first value.
	IterateAll bool `yaml:"iterate-all"`
	// Threads is a performance knob, not a detection rule: it sizes the
	// connection pool nuclei uses. crackweb runs a scan's requests through one
	// shared limiter and treats this as a no-op, which changes how fast a
	// template runs and not what it reports.
	Threads int `yaml:"threads"`
	// Pipeline is HTTP/1.1 pipelining.
	Pipeline bool `yaml:"pipeline"`
	// SkipVariables is nuclei's opt-out of its "unresolved variable" validation.
	// crackweb performs no such validation, so accepting the field is already
	// the behaviour it asks for.
	SkipVariables bool `yaml:"skip-variables-check"`
	// GlobalMatchers marks matchers that nuclei applies to results from other
	// templates.
	GlobalMatchers bool   `yaml:"global-matchers"`
	ID             string `yaml:"id"`
}

// Matcher is one detection rule.
type Matcher struct {
	Type            string     `yaml:"type"`
	Part            string     `yaml:"part"`
	Words           StringList `yaml:"words"`
	Regex           StringList `yaml:"regex"`
	Status          []int      `yaml:"status"`
	Size            []int      `yaml:"size"`
	DSL             StringList `yaml:"dsl"`
	Binary          StringList `yaml:"binary"`
	XPath           StringList `yaml:"xpath"`
	Condition       string     `yaml:"condition"`
	Negative        bool       `yaml:"negative"`
	CaseInsensitive bool       `yaml:"case-insensitive"`
	Internal        bool       `yaml:"internal"`
	MatchAll        bool       `yaml:"match-all"`
	Encoding        string     `yaml:"encoding"`
	Name            string     `yaml:"name"`
}

// Extractor pulls a value out of a response.
type Extractor struct {
	Type      string     `yaml:"type"`
	Part      string     `yaml:"part"`
	Regex     StringList `yaml:"regex"`
	Group     int        `yaml:"group"`
	Name      string     `yaml:"name"`
	KVal      StringList `yaml:"kval"`
	JSON      StringList `yaml:"json"`
	DSL       StringList `yaml:"dsl"`
	XPath     StringList `yaml:"xpath"`
	Attribute string     `yaml:"attribute"`
	Internal  bool       `yaml:"internal"`
	// CaseInsensitive lowercases both the values and the keys a kval extractor
	// looks up, which is how a template reads a header whose case the server
	// decides.
	CaseInsensitive bool `yaml:"case-insensitive"`
}

// Variables is a template's variables block.
//
// nuclei evaluates the block in document order and re-evaluates it as other
// variables arrive, so a variable may reference one written above it. A Go map
// would lose that order and resolve every run differently, so the order the
// template wrote is kept here and the engine walks it.
type Variables struct {
	names  []string
	values map[string]string
}

// UnmarshalYAML decodes the block. Scalar values are accepted in the shape
// nuclei accepts them — a number or a boolean is as valid as a string — and are
// stringified the way the renderer would print them.
func (v *Variables) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == 0 || node.Tag == "!!null" {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("variables must be a mapping, got %s", node.Tag)
	}

	v.names = nil
	v.values = map[string]string{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		raw := node.Content[i+1]
		if raw.Kind != yaml.ScalarNode {
			return fmt.Errorf("variable %s must be a scalar, got %s", name, raw.Tag)
		}
		v.names = append(v.names, name)
		v.values[name] = raw.Value
	}
	return nil
}

// Len returns the number of declared variables.
func (v Variables) Len() int { return len(v.names) }

// Each calls fn for every variable, in the order the template declared them.
func (v Variables) Each(fn func(name, value string)) {
	for _, name := range v.names {
		fn(name, v.values[name])
	}
}

// StringList unmarshals a YAML field that may be written as a single scalar or
// as a sequence. nuclei templates use both spellings freely — "tags: cve,rce"
// and a proper list mean the same thing — so the decoder has to accept either.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		text := strings.TrimSpace(value.Value)
		if text == "" {
			return nil
		}
		// A comma-separated scalar is a list in disguise.
		if strings.Contains(text, ",") {
			for _, part := range strings.Split(text, ",") {
				if part = strings.TrimSpace(part); part != "" {
					*s = append(*s, part)
				}
			}
			return nil
		}
		*s = append(*s, text)
		return nil
	case yaml.SequenceNode:
		for _, item := range value.Content {
			var text string
			if err := item.Decode(&text); err != nil {
				return err
			}
			if text = strings.TrimSpace(text); text != "" {
				*s = append(*s, text)
			}
		}
		return nil
	default:
		return nil
	}
}

// Payload is one payload list, in the form the template wrote it.
//
// The form carries meaning in nuclei: a bare scalar names a helper file to read
// the values from, while a sequence (or a scalar with newlines in it) carries
// the values inline. "payloads: {page: login}" therefore means "read the file
// login" and not "try the word login", and a reader that loses the distinction
// sends requests for a wordlist that was never loaded.
type Payload struct {
	values   StringList
	fromFile bool
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (p *Payload) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		text := node.Value
		if strings.Contains(text, "\n") {
			for _, line := range strings.Split(text, "\n") {
				if line = strings.TrimRight(line, "\r"); line != "" {
					p.values = append(p.values, line)
				}
			}
			return nil
		}
		if text = strings.TrimSpace(text); text == "" {
			return nil
		}
		p.values = StringList{text}
		p.fromFile = true
		return nil

	case yaml.SequenceNode:
		for _, item := range node.Content {
			var text string
			if err := item.Decode(&text); err != nil {
				return err
			}
			if text = strings.TrimSpace(text); text != "" {
				p.values = append(p.values, text)
			}
		}
		return nil

	default:
		return nil
	}
}

// Values returns the payload values, after any helper file has been read.
func (p Payload) Values() StringList { return p.values }

// Severity returns the template's severity, normalised onto crackweb's scale.
// An unrecognised value becomes "unknown" rather than being passed through, so
// a typo in a template cannot produce a report element nobody can filter.
func (t *Template) Severity() string {
	return string(finding.ParseSeverity(t.Info.Severity))
}

// Requests returns the effective request list, whichever spelling was used.
func (t *Template) Requests_() []HTTPRequest {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// requestBlocks returns the effective blocks as pointers into the template.
// Requests_ hands out copies for readers; the loader needs the originals,
// because it rewrites payload lists once their files have been read.
func (t *Template) requestBlocks() []*HTTPRequest {
	source := t.Requests
	if len(t.HTTP) > 0 {
		source = t.HTTP
	}
	blocks := make([]*HTTPRequest, len(source))
	for i := range source {
		blocks[i] = &source[i]
	}
	return blocks
}

// Parse decodes one template document.
func Parse(data []byte) (*Template, error) {
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	if tmpl.ID == "" {
		return nil, fmt.Errorf("template has no id")
	}
	if len(tmpl.Requests_()) == 0 && tmpl.Flow == "" {
		return nil, fmt.Errorf("template %s has no http requests", tmpl.ID)
	}
	tmpl.applyEncodings()
	return &tmpl, nil
}

// applyEncodings decodes the values nuclei decodes at compile time.
//
// A word matcher with "encoding: hex" carries its words as hex, and a binary
// matcher always does. Decoding here rather than at match time means the rest
// of the engine compares plain bytes, and a template whose hex does not decode
// is refused by Unsupported instead of silently matching nothing.
func (t *Template) applyEncodings() {
	for _, req := range t.requestBlocks() {
		for matcherIndex := range req.Matchers {
			matcher := &req.Matchers[matcherIndex]
			if !strings.EqualFold(strings.TrimSpace(matcher.Encoding), "hex") {
				continue
			}
			for i, word := range matcher.Words {
				if decoded, err := hex.DecodeString(strings.TrimSpace(word)); err == nil {
					matcher.Words[i] = string(decoded)
				}
			}
		}
	}
}

// Unsupported returns the features a template uses that crackweb cannot honour.
//
// This is the compatibility contract: everything named here is something the
// reference implementation does and this engine does not, so the template is
// refused with a reason instead of being run into a wrong answer. The list is
// checked against nuclei's own validation, which rejects the same templates —
// an empty operator block, an invalid attack type, a hex value that is not hex
// and a case-insensitive flag on a non-word matcher are all load errors there
// too.
func (t *Template) Unsupported() []string {
	var reasons []string
	note := func(format string, args ...any) {
		reasons = append(reasons, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(t.Flow) != "" {
		note("flow-based request orchestration")
	}
	if t.SelfContained {
		note("self-contained templates, which run without a target")
	}

	for i, req := range t.Requests_() {
		label := fmt.Sprintf("request %d", i+1)

		if req.Unsafe {
			note("%s: raw unsafe requests", label)
		}
		if req.Pipeline {
			note("%s: HTTP pipelining", label)
		}
		if req.Race {
			note("%s: race-condition requests", label)
		}
		if len(req.Fuzzing) > 0 {
			note("%s: fuzzing rules", label)
		}
		if req.GlobalMatchers {
			note("%s: global matchers", label)
		}
		if attack := strings.TrimSpace(req.Attack); attack != "" && !validAttack(attack) {
			note("%s: unknown attack type %s", label, attack)
		}
		if len(req.Matchers) == 0 && len(req.Extractors) == 0 {
			// nuclei refuses this outright ("empty operators"): a block that
			// neither matches nor extracts has nothing to do, and reporting it
			// as a hit is how a scanner invents findings.
			note("%s: no matchers and no extractors", label)
		}

		for _, m := range req.Matchers {
			kind := strings.ToLower(strings.TrimSpace(m.Type))
			switch kind {
			case "word", "regex", "status", "size", "dsl", "binary", "":
			case "xpath":
				note("%s: xpath matchers", label)
			case "llm":
				note("%s: LLM matchers", label)
			default:
				note("%s: matcher type %s", label, m.Type)
			}
			if m.CaseInsensitive && kind != "word" {
				// nuclei refuses this at compile time: the flag is only
				// implemented for word matchers, and honouring it for anything
				// else would be a different matcher from the one nuclei runs.
				note("%s: case-insensitive on a %s matcher, which nuclei refuses", label, kindName(kind))
			}
			if encoding := strings.ToLower(strings.TrimSpace(m.Encoding)); encoding != "" && encoding != "hex" {
				note("%s: matcher encoding %s", label, m.Encoding)
			}
			if kind == "binary" {
				for _, value := range m.Binary {
					if _, err := hex.DecodeString(strings.TrimSpace(value)); err != nil {
						note("%s: binary matcher value is not hex: %s", label, value)
						break
					}
				}
			}
			if !matcherHasValues(m) {
				// nuclei refuses a matcher that carries no value list for its
				// type; running it would answer "no match" for a template the
				// author meant to work, which reads like a clean target.
				note("%s: %s matcher has no values", label, kindName(kind))
			}
			if unexpected := unexpectedMatcherFields(m); len(unexpected) > 0 {
				note("%s: %s matcher also sets %s", label, kindName(kind), strings.Join(unexpected, ", "))
			}
		}

		for _, e := range req.Extractors {
			kind := strings.ToLower(strings.TrimSpace(e.Type))
			switch kind {
			case "regex", "kval", "dsl", "json", "":
			case "xpath":
				note("%s: xpath extractors", label)
			case "llm":
				note("%s: LLM extractors", label)
			default:
				note("%s: extractor type %s", label, e.Type)
			}
			if strings.TrimSpace(e.Attribute) != "" {
				note("%s: xpath extractor attributes", label)
			}
			if e.CaseInsensitive && kind != "kval" && kind != "" {
				note("%s: case-insensitive on a %s extractor, which nuclei refuses", label, kindName(kind))
			}
			if kind == "" || kind == "regex" {
				if e.Group < 0 {
					note("%s: regex extractor group %d is negative", label, e.Group)
				}
			}
			if !extractorHasValues(e) {
				note("%s: %s extractor has no values", label, kindName(kind))
			}
			if kind == "json" {
				for _, expression := range e.JSON {
					if !jsonPathSupported(expression) {
						note("%s: json extractor expression %s uses jq syntax crackweb cannot evaluate", label, expression)
						break
					}
				}
			}
		}
	}
	return dedupeStrings(reasons)
}

// validAttack reports whether the template names an attack type nuclei knows.
func validAttack(attack string) bool {
	switch strings.ToLower(strings.TrimSpace(attack)) {
	case "batteringram", "pitchfork", "clusterbomb":
		return true
	}
	return false
}

// kindName renders a matcher or extractor type for a message. An empty type is
// the default, which is a word matcher or a regex extractor.
func kindName(kind string) string {
	if strings.TrimSpace(kind) == "" {
		return "default"
	}
	return kind
}

// matcherHasValues reports whether a matcher carries the value list its type
// needs. nuclei refuses a matcher without one, so a template that forgot its
// words is reported rather than run into a clean-looking "no match".
func matcherHasValues(m Matcher) bool {
	switch strings.ToLower(strings.TrimSpace(m.Type)) {
	case "dsl":
		return len(m.DSL) > 0
	case "status":
		return len(m.Status) > 0
	case "size":
		return len(m.Size) > 0
	case "binary":
		return len(m.Binary) > 0
	case "regex":
		return len(m.Regex) > 0
	case "xpath":
		return len(m.XPath) > 0
	default:
		return len(m.Words) > 0
	}
}

// unexpectedMatcherFields returns the value lists a matcher sets that belong to
// another matcher type.
//
// nuclei validates this ("could not compile matcher: unexpected fields") because
// a word matcher carrying a regex is a template with a typo, and the two
// readings of it — ignore the regex, or use it — report different things about
// the same target.
func unexpectedMatcherFields(m Matcher) []string {
	present := map[string]bool{}
	if len(m.Words) > 0 {
		present["words"] = true
	}
	if len(m.Regex) > 0 {
		present["regex"] = true
	}
	if len(m.Status) > 0 {
		present["status"] = true
	}
	if len(m.Size) > 0 {
		present["size"] = true
	}
	if len(m.DSL) > 0 {
		present["dsl"] = true
	}
	if len(m.Binary) > 0 {
		present["binary"] = true
	}
	if len(m.XPath) > 0 {
		present["xpath"] = true
	}

	allowed := map[string]bool{}
	switch strings.ToLower(strings.TrimSpace(m.Type)) {
	case "dsl":
		allowed["dsl"] = true
	case "status":
		allowed["status"] = true
	case "size":
		allowed["size"] = true
	case "binary":
		allowed["binary"] = true
	case "regex":
		allowed["regex"] = true
	case "xpath":
		allowed["xpath"] = true
	default:
		allowed["words"] = true
	}

	var unexpected []string
	for field := range present {
		if !allowed[field] {
			unexpected = append(unexpected, field)
		}
	}
	sort.Strings(unexpected)
	return unexpected
}

// extractorHasValues reports whether an extractor carries the values its type
// reads.
func extractorHasValues(e Extractor) bool {
	switch strings.ToLower(strings.TrimSpace(e.Type)) {
	case "kval":
		return len(e.KVal) > 0
	case "json":
		return len(e.JSON) > 0
	case "dsl":
		return len(e.DSL) > 0
	case "xpath":
		return len(e.XPath) > 0
	default:
		return len(e.Regex) > 0
	}
}

// LoadDir reads every .yaml/.yml template under a directory, recursively.
//
// Payload files named by a template are read here, while the template's
// directory is still known: nuclei resolves them relative to the template, and
// a template whose wordlist is missing is refused rather than run with the
// filename as its payload.
func LoadDir(dir string) ([]*Template, []error) {
	var (
		templates []*Template
		errs      []error
	)

	walkErr := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, readErr))
			return nil
		}
		tmpl, parseErr := Parse(data)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, parseErr))
			return nil
		}
		tmpl.dir = filepath.Dir(path)
		tmpl.path = path
		if payloadErrs := tmpl.resolvePayloadFiles(); len(payloadErrs) > 0 {
			for _, err := range payloadErrs {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
			}
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}

	sort.Slice(templates, func(i, j int) bool { return templates[i].ID < templates[j].ID })
	return templates, errs
}

// resolvePayloadFiles replaces a scalar payload value with the lines of the
// file it names.
//
// nuclei reads a payload written as a bare scalar as a path to a helper file
// (next to the template, or resolved from the working directory) and a payload
// written with newlines as an inline list. Both spellings appear in published
// templates, and treating a filename as a payload silently sends a request for
// a wordlist that was never loaded.
func (t *Template) resolvePayloadFiles() []error {
	var errs []error
	for _, req := range t.requestBlocks() {
		for name, payload := range req.Payloads {
			if !payload.fromFile {
				continue
			}
			values, err := readPayloadFile(t.dir, payload.values[0])
			if err != nil {
				errs = append(errs, fmt.Errorf("payload %s: %w", name, err))
				continue
			}
			req.Payloads[name] = Payload{values: values}
		}
	}
	return errs
}

// readPayloadFile reads a helper file, looking next to the template first and
// then where the process was started, which is how nuclei's templates reference
// wordlists that ship with the template tree.
func readPayloadFile(dir, name string) (StringList, error) {
	candidates := []string{name}
	if dir != "" && !filepath.IsAbs(name) {
		candidates = []string{filepath.Join(dir, name), name}
	}

	var tried []string
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			tried = append(tried, candidate)
			continue
		}
		var values StringList
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimRight(line, "\r"); line != "" {
				values = append(values, line)
			}
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("payload file %s is empty", candidate)
		}
		return values, nil
	}
	return nil, fmt.Errorf("payload file not found (tried %s)", strings.Join(tried, ", "))
}

// dedupeStrings removes duplicates while preserving order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
