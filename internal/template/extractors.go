package template

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// extractorValues runs one extractor over a response.
//
// The four types nuclei implements for HTTP each read a different thing: regex
// reads a part of the response as text, kval reads the response's named data
// (headers, status_code, body and the rest), json reads a part as a JSON
// document, and dsl evaluates expressions over the data. The values come back
// in the order they were found, without repeats, because a later request
// substitutes them one at a time.
func extractorValues(extractor Extractor, resp *httpmsg.Response, data map[string]Value) []string {
	switch strings.ToLower(strings.TrimSpace(extractor.Type)) {
	case "", "regex":
		corpus, ok := partOf(extractor.Part, resp, data)
		if !ok {
			return nil
		}
		return extractRegexes(extractor, corpus)

	case "kval":
		return extractKVal(extractor, data)

	case "json":
		corpus, ok := partOf(extractor.Part, resp, data)
		if !ok {
			return nil
		}
		return extractJSON(extractor, corpus)

	case "dsl":
		return extractDSL(extractor, data)

	default:
		return nil
	}
}

// extractRegexes pulls every match of every pattern out of the corpus.
//
// nuclei collects all of them rather than the first: a template that extracted
// a CSRF token per form, or a list of links, means all of them, and a reader
// that stops at the first hands the next request the wrong value.
func extractRegexes(extractor Extractor, corpus string) []string {
	if extractor.Group < 0 {
		return nil
	}

	var values []string
	for _, pattern := range extractor.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		for _, match := range re.FindAllStringSubmatch(corpus, -1) {
			if extractor.Group >= len(match) {
				// The pattern has no such group, so there is nothing to extract
				// from this match. nuclei skips the match rather than falling
				// back to the whole thing, which would extract the wrong text.
				continue
			}
			values = appendUnique(values, match[extractor.Group])
		}
	}
	return values
}

// extractKVal reads values out of the response's named data, which is how a
// template says "tell me what the Content-Type header was".
//
// nuclei lowercases the keys a template names and, when the extractor asks for
// it, the keys and text of the data it looks in — a server chooses the case of
// a header name, so a template cannot.
func extractKVal(extractor Extractor, data map[string]Value) []string {
	lookup := data
	if extractor.CaseInsensitive {
		lookup = make(map[string]Value, len(data))
		for name, value := range data {
			lookup[strings.ToLower(name)] = StringValue(strings.ToLower(value.String()))
		}
	}

	var values []string
	for _, key := range extractor.KVal {
		value, ok := lookup[strings.ToLower(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		values = appendUnique(values, value.String())
	}
	return values
}

// extractJSON reads a part of the response as JSON and evaluates a jq path over
// it.
func extractJSON(extractor Extractor, corpus string) []string {
	var document any
	if err := json.Unmarshal([]byte(corpus), &document); err != nil {
		return nil
	}

	var values []string
	for _, expression := range extractor.JSON {
		alternatives, err := parseJSONPath(expression)
		if err != nil {
			continue
		}
		for _, path := range alternatives {
			found := evalJSONPath(path, document)
			if len(found) == 0 {
				// jq's alternative operator: try the next path when this one
				// finds nothing, which is how a template reads a token that
				// lives under one of several names.
				continue
			}
			for _, value := range found {
				values = appendUnique(values, jsonText(value))
			}
			break
		}
	}
	return values
}

// extractDSL evaluates expressions over the response's data.
func extractDSL(extractor Extractor, data map[string]Value) []string {
	var values []string
	for _, expression := range extractor.DSL {
		// A DSL expression may carry a variable inside a string literal, which
		// nuclei resolves before evaluating.
		value, err := Eval(Expand(expression, data), data)
		if err != nil {
			if strings.HasPrefix(err.Error(), "no parameter") {
				// The expression refers to something this response does not
				// have (a DNS or TLS variable, say); that is not a reason to
				// abandon the other expressions.
				continue
			}
			return nil
		}
		if text := value.String(); text != "" {
			values = appendUnique(values, text)
		}
	}
	return values
}

// appendUnique adds a value unless it is already there, keeping the order the
// values were found in.
func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// jsonText renders an extracted JSON value the way nuclei does: a scalar as its
// own text, anything else as JSON.
func jsonText(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		if encoded, err := json.Marshal(value); err == nil {
			return string(encoded)
		}
		return fmt.Sprint(value)
	}
}

// jsonStepKind is the kind of one step in a jq path.
type jsonStepKind int

const (
	// jsonField reads one field of an object.
	jsonField jsonStepKind = iota
	// jsonIndex reads one element of an array.
	jsonIndex
	// jsonEach reads every element of an array, or every value of an object.
	jsonEach
)

// jsonStep is one step of a jq path.
type jsonStep struct {
	kind  jsonStepKind
	name  string
	index int
}

// parseJSONPath parses the part of jq crackweb evaluates.
//
// nuclei runs its json extractor expressions through gojq, so most of the
// language is available there. crackweb implements the shapes published
// templates actually use — field access, array indexes, iteration over
// everything, and jq's alternative operator — and refuses the rest when the
// template is loaded. That refusal is the point: a jq program this engine
// half-understood would extract a value that looks plausible and is wrong.
func parseJSONPath(expression string) ([][]jsonStep, error) {
	// "//" is jq's alternative operator: use the first path that finds
	// something. A path never contains "//" itself, so splitting is exact.
	parts := strings.Split(expression, "//")
	paths := make([][]jsonStep, 0, len(parts))
	for _, part := range parts {
		path, err := parseJSONSteps(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// jsonPathSupported reports whether a json extractor expression is one crackweb
// can evaluate exactly.
func jsonPathSupported(expression string) bool {
	_, err := parseJSONPath(expression)
	return err == nil
}

// parseJSONSteps parses one path: a chain of .name, [0] and [] steps.
func parseJSONSteps(text string) ([]jsonStep, error) {
	if text == "" {
		return nil, fmt.Errorf("empty json path")
	}

	var path []jsonStep
	for i := 0; i < len(text); {
		switch text[i] {
		case '.':
			i++
			name, next := readJSONName(text, i)
			if name == "" {
				// A bare "." is identity: the whole document. A name that looks
				// like a number is not a field either, and the round after this
				// one reports it.
				continue
			}
			path = append(path, jsonStep{kind: jsonField, name: name})
			i = next

		case '[':
			end := strings.IndexByte(text[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unclosed [ in json path")
			}
			inside := strings.TrimSpace(text[i+1 : i+end])
			switch {
			case inside == "":
				path = append(path, jsonStep{kind: jsonEach})
			case isJSONIndex(inside):
				index, _ := strconv.Atoi(inside)
				path = append(path, jsonStep{kind: jsonIndex, index: index})
			default:
				return nil, fmt.Errorf("unsupported json path selector [%s]", inside)
			}
			i += end + 1

		case ' ', '\t', '\n':
			i++

		default:
			return nil, fmt.Errorf("unsupported json path syntax at %q", text[i:])
		}
	}
	return path, nil
}

// readJSONName reads an identifier, which is what jq allows after a dot without
// quoting.
func readJSONName(text string, start int) (string, int) {
	i := start
	for i < len(text) {
		b := text[i]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' {
			i++
			continue
		}
		break
	}
	if i == start {
		return "", start
	}
	name := text[start:i]
	if name[0] >= '0' && name[0] <= '9' {
		// jq reads ".123" as a number, not a field name; a template that means
		// the field writes it some other way, and crackweb refuses that rather
		// than reading the wrong value.
		return "", start
	}
	return name, i
}

// isJSONIndex reports whether a bracket selector is a plain array index.
func isJSONIndex(text string) bool {
	if text == "" {
		return false
	}
	start := 0
	if text[0] == '-' {
		start = 1
	}
	if start == len(text) {
		return false
	}
	for i := start; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return false
		}
	}
	return true
}

// evalJSONPath applies a path to a decoded JSON document.
func evalJSONPath(path []jsonStep, document any) []any {
	values := []any{document}
	for _, step := range path {
		var next []any
		for _, value := range values {
			switch step.kind {
			case jsonField:
				if object, ok := value.(map[string]any); ok {
					if field, ok := object[step.name]; ok {
						next = append(next, field)
					}
				}

			case jsonIndex:
				array, ok := value.([]any)
				if !ok {
					continue
				}
				index := step.index
				if index < 0 {
					index += len(array)
				}
				if index >= 0 && index < len(array) {
					next = append(next, array[index])
				}

			case jsonEach:
				switch container := value.(type) {
				case []any:
					next = append(next, container...)
				case map[string]any:
					// jq walks the keys in order, so a template reading every
					// value of an object gets them in the same order twice.
					keys := make([]string, 0, len(container))
					for key := range container {
						keys = append(keys, key)
					}
					sort.Strings(keys)
					for _, key := range keys {
						next = append(next, container[key])
					}
				}
			}
		}
		values = next
	}
	return values
}
