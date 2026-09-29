// Package apidoc turns an API description into the requests it describes.
//
// An OpenAPI document is the best input a scanner can be handed: every path, every method,
// and for each one the parameters with their names, types and locations — including the
// endpoints a crawler will never find because nothing links to them, and the request-body
// schema that says what a JSON endpoint expects. Nothing else a target publishes is worth
// as much per byte.
//
// Both generations of the format are read here rather than in two packages. They describe
// the same thing in different words, and a caller holding a response should not have to
// know which one it got; the differences are confined to where the base address and the
// request body are spelled out.
package apidoc

import (
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/httpmsg"

	"gopkg.in/yaml.v3"
)

// Limits on what is generated from one document. A description can list thousands of
// operations, and a scan that spends its whole budget on one file has stopped being a scan.
const (
	// MaxOperations bounds how many requests one document contributes.
	MaxOperations = 200
	// maxSampleDepth and maxSampleFields bound the body that is invented from a schema.
	maxSampleDepth  = 4
	maxSampleFields = 8
)

// Document is one parsed description.
type Document struct {
	// Title and Version are what the document calls itself, for the log line that says what
	// was found.
	Title   string
	Version string
	// Requests are the operations, ready to send.
	Requests []*httpmsg.Request
}

// Parse reads a description and returns the requests it lists.
//
// documentURL is where the bytes came from, which is the last word on where the operations
// live when the document itself does not say. The second result is false when the bytes are
// not a description at all, which is the common case: this runs on every JSON response the
// crawler happens to fetch.
func Parse(data []byte, documentURL *url.URL) (*Document, bool) {
	if len(data) == 0 {
		return nil, false
	}

	var raw rawDocument
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, false
	}
	if raw.Paths == nil || (raw.Swagger == "" && raw.OpenAPI == "") {
		return nil, false
	}

	base := raw.baseURL(documentURL)
	if base == nil {
		return nil, false
	}

	doc := &Document{Title: raw.Info.Title, Version: raw.Info.Version}
	for _, documentPath := range sortedKeys(raw.Paths) {
		operations := raw.Paths[documentPath]
		for _, method := range sortedKeys(operations) {
			operation, ok := operations[method]
			if !ok || !isHTTPMethod(method) {
				continue
			}
			if len(doc.Requests) >= MaxOperations {
				return doc, true
			}
			if request, ok := buildRequest(method, documentPath, operation, base); ok {
				doc.Requests = append(doc.Requests, request)
			}
		}
	}
	return doc, true
}

// LooksLikeDocument reports whether bytes could be a description, without parsing them.
//
// It runs on every JSON response the crawler fetches, so it is a substring test rather than
// a decode: the cheap answer decides whether the expensive one is worth having.
func LooksLikeDocument(data []byte) bool {
	if len(data) == 0 || len(data) > maxDocumentBytes {
		return false
	}
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	text := strings.ToLower(string(head))
	return strings.Contains(text, "swagger") || strings.Contains(text, "openapi")
}

// maxDocumentBytes bounds what is parsed. A description larger than this is a download.
const maxDocumentBytes = 8 << 20

// rawDocument is the part of both formats this package reads. The two spell the same things
// differently — 2.0 keeps the host and base path at the top level, 3.x lists servers — so
// both spellings are here and whichever is present is used.
type rawDocument struct {
	Swagger  string `yaml:"swagger"`
	OpenAPI  string `yaml:"openapi"`
	Info     rawInfo
	Host     string   `yaml:"host"`
	BasePath string   `yaml:"basePath"`
	Schemes  []string `yaml:"schemes"`
	Servers  []struct {
		URL string `yaml:"url"`
	} `yaml:"servers"`
	Paths map[string]map[string]rawOperation `yaml:"paths"`
}

type rawInfo struct {
	Title   string `yaml:"title"`
	Version string `yaml:"version"`
}

type rawOperation struct {
	Parameters  []rawParameter  `yaml:"parameters"`
	RequestBody *rawRequestBody `yaml:"requestBody"`
}

type rawParameter struct {
	Name    string         `yaml:"name"`
	In      string         `yaml:"in"`
	Type    string         `yaml:"type"`
	Format  string         `yaml:"format"`
	Example any            `yaml:"example"`
	Default any            `yaml:"default"`
	Enum    []any          `yaml:"enum"`
	Schema  map[string]any `yaml:"schema"`
}

type rawRequestBody struct {
	Content map[string]rawMediaType `yaml:"content"`
}

type rawMediaType struct {
	Schema map[string]any `yaml:"schema"`
	// media is the type this entry was reached by, which the request has to be sent with.
	media string
}

// baseURL resolves where the operations live.
//
// The document is asked first: 3.x names its servers, 2.0 names a host and a base path. When
// neither says anything the address the bytes were fetched from decides, with the file name
// dropped — a description served at /api/swagger.json most likely describes /api/.
//
// A host the document names but the caller did not authorise is not a problem here: every
// generated request is still filtered by the crawler's scope before it is sent.
func (d *rawDocument) baseURL(documentURL *url.URL) *url.URL {
	for _, server := range d.Servers {
		if server.URL == "" {
			continue
		}
		parsed, err := url.Parse(server.URL)
		if err != nil {
			continue
		}
		if documentURL != nil {
			return documentURL.ResolveReference(parsed)
		}
		if parsed.IsAbs() {
			return parsed
		}
	}

	if d.Host != "" {
		scheme := "https"
		if len(d.Schemes) > 0 && d.Schemes[0] != "" {
			scheme = d.Schemes[0]
		} else if documentURL != nil && documentURL.Scheme != "" {
			scheme = documentURL.Scheme
		}
		return &url.URL{Scheme: scheme, Host: d.Host, Path: d.BasePath}
	}

	if documentURL == nil {
		return nil
	}
	base := *documentURL
	base.RawQuery = ""
	base.Fragment = ""
	base.RawFragment = ""
	base.Path = path.Dir(base.Path)
	if base.Path == "." {
		base.Path = "/"
	}
	return &base
}

// buildRequest turns one operation into a request, or reports that it cannot be addressed.
func buildRequest(method, template string, operation rawOperation, base *url.URL) (*httpmsg.Request, bool) {
	target := *base
	target.Path = joinPaths(base.Path, template)
	target.RawPath = ""

	query := url.Values{}
	contentType := ""
	var body []byte

	for _, parameter := range operation.Parameters {
		switch strings.ToLower(parameter.In) {
		case "path":
			// A path parameter has no default: leaving the placeholder in the address would
			// send a request to a literal "{id}".
			target.Path = strings.ReplaceAll(target.Path, "{"+parameter.Name+"}", sampleValue(parameter))
		case "query":
			query.Set(parameter.Name, sampleValue(parameter))
		case "body":
			// 2.0 carries the request body as a parameter.
			if body == nil && parameter.Schema != nil {
				body = encodeSample(parameter.Schema)
				contentType = "application/json"
			}
		case "formdata":
			query.Set(parameter.Name, sampleValue(parameter))
		}
	}

	if operation.RequestBody != nil {
		if media, ok := preferredMedia(operation.RequestBody.Content); ok {
			body = encodeSample(media.Schema)
			contentType = media.media
		}
	}

	target.RawQuery = query.Encode()
	request, err := httpmsg.NewRequest(method, target.String())
	if err != nil {
		return nil, false
	}
	if len(body) > 0 {
		request.Body = body
		request.Header.Set("Content-Length", strconv.Itoa(len(body)))
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
	}
	return request, true
}

// joinPaths puts a document's base path in front of an operation's path.
func joinPaths(basePath, operationPath string) string {
	if basePath == "" || basePath == "/" {
		basePath = ""
	}
	joined := strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(operationPath, "/")
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

// preferredMedia picks the media type to send from what an operation accepts. JSON is
// preferred because it is what the endpoints worth reaching speak.
func preferredMedia(content map[string]rawMediaType) (rawMediaType, bool) {
	for _, wanted := range []string{"application/json", "application/merge-patch+json", "text/json"} {
		if media, ok := content[wanted]; ok {
			media.media = wanted
			return media, true
		}
	}
	// Deterministic second choice: a map iterates in random order.
	for _, name := range sortedKeys(content) {
		if strings.Contains(name, "json") {
			media := content[name]
			media.media = name
			return media, true
		}
	}
	return rawMediaType{}, false
}

// sampleValue returns a value to send for a parameter.
//
// What the document itself says is used first — an example, a default, the first member of
// an enum — and only then the smallest thing the declared type would accept. The aim is a
// value the endpoint will accept, because one it rejects never reaches the code under test.
func sampleValue(parameter rawParameter) string {
	for _, candidate := range []any{parameter.Example, parameter.Default} {
		if value := scalarString(candidate); value != "" {
			return value
		}
	}
	if len(parameter.Enum) > 0 {
		if value := scalarString(parameter.Enum[0]); value != "" {
			return value
		}
	}
	if parameter.Schema != nil {
		if value := scalarString(parameter.Schema["example"]); value != "" {
			return value
		}
		if kind, _ := parameter.Schema["type"].(string); kind != "" {
			return sampleForType(kind, stringField(parameter.Schema, "format"))
		}
	}
	return sampleForType(parameter.Type, parameter.Format)
}

// sampleForType returns the simplest value of a declared type.
func sampleForType(kind, format string) string {
	switch strings.ToLower(kind) {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "string":
		switch strings.ToLower(format) {
		case "date":
			return "2020-01-01"
		case "date-time":
			return "2020-01-01T00:00:00Z"
		case "uuid":
			return "00000000-0000-0000-0000-000000000000"
		case "email":
			return "user@example.com"
		}
		return "a"
	}
	return "1"
}

// encodeSample renders a body for a schema. A schema it cannot read produces no body at all,
// rather than one that fails to parse — a request the endpoint rejects tests nothing.
func encodeSample(schema map[string]any) []byte {
	if schema == nil {
		return nil
	}
	sample := sampleJSON(schema, 0)
	if sample == nil {
		return nil
	}
	encoded, err := jsonMarshal(sample)
	if err != nil {
		return nil
	}
	return encoded
}

// sampleJSON builds the smallest document a schema would accept.
//
// Only the fields the schema requires are filled, plus one more when nothing is required so
// that the body is not an empty object. An invented optional field can change what an
// operation does, and the point is to reach it, not to exercise it.
func sampleJSON(schema map[string]any, depth int) any {
	if schema == nil || depth > maxSampleDepth {
		return nil
	}

	switch kind := stringField(schema, "type"); kind {
	case "object", "":
		properties, _ := schema["properties"].(map[string]any)
		if properties == nil {
			return map[string]any{}
		}
		required := stringSet(schema["required"])
		out := map[string]any{}
		for _, name := range sortedKeys(properties) {
			if len(out) >= maxSampleFields {
				break
			}
			if len(required) > 0 && !required[name] {
				continue
			}
			child, _ := properties[name].(map[string]any)
			out[name] = sampleJSON(child, depth+1)
		}
		return out
	case "array":
		items, _ := schema["items"].(map[string]any)
		return []any{sampleJSON(items, depth+1)}
	case "integer", "number":
		return 1
	case "boolean":
		return true
	default:
		return "a"
	}
}

// scalarString renders a scalar as the text a parameter value has to be.
func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	}
	return ""
}

// stringField reads a string member of a decoded mapping.
func stringField(mapping map[string]any, name string) string {
	if mapping == nil {
		return ""
	}
	value, _ := mapping[name].(string)
	return value
}

// stringSet turns a decoded list of names into a set.
func stringSet(value any) map[string]bool {
	list, _ := value.([]any)
	if len(list) == 0 {
		return nil
	}
	out := make(map[string]bool, len(list))
	for _, item := range list {
		if name, ok := item.(string); ok {
			out[name] = true
		}
	}
	return out
}

// sortedKeys returns a mapping's keys in order, so a document always produces the same
// requests in the same sequence.
func sortedKeys[M ~map[string]V, V any](mapping M) []string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// isHTTPMethod reports whether a key under a path names an operation.
func isHTTPMethod(name string) bool {
	switch strings.ToLower(name) {
	case "get", "put", "post", "delete", "options", "head", "patch", "trace":
		return true
	}
	return false
}

// jsonMarshal encodes a generated body. The standard encoder is used rather than a
// hand-rolled one: this is produced from a schema, so its shape is known and it will not
// carry anything that needs the careful escaping the injection paths do.
func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}
