package httpmsg

import (
	"net/url"
	"strconv"
	"strings"
)

// ParamLocation says where a parameter was found. Values are the strings that
// appear in reports, so they stay human-readable on purpose.
type ParamLocation string

// Parameter locations crackweb knows how to address.
const (
	// LocQuery is a parameter in the URL query string.
	LocQuery ParamLocation = "query"
	// LocBody is a parameter in a form-encoded request body.
	LocBody ParamLocation = "body"
	// LocCookie is a cookie value.
	LocCookie ParamLocation = "cookie"
	// LocJSON is a field in a JSON request body.
	LocJSON ParamLocation = "json"
	// LocJSONBase64 is a field in a JSON body that is base64-encoded before it is sent.
	// Rewriting one means decoding the envelope, editing the document and re-encoding it.
	LocJSONBase64 ParamLocation = "json-base64"
	// LocMultipart is the content of a text part in a multipart/form-data body.
	LocMultipart ParamLocation = "multipart"
	// LocMultipartFilename is the file name of a file part in a multipart/form-data body,
	// which is the input an upload endpoint turns into the stored file's name.
	LocMultipartFilename ParamLocation = "multipart-filename"
)

// Wrapper says how a structured value is carried on the wire, for values that do not sit
// in the request at all but inside one of its parameters.
//
// An API that takes its input as one encoded blob — `?id={"uid":1}` or `?id=eyJ1aWQiOjF9`
// — puts a whole document where a value would be. Replacing that parameter's value would
// break the document before it was ever parsed, so the fields inside it are addressed as
// parameters in their own right and the envelope is rebuilt around each mutation.
type Wrapper uint8

// Wrapper kinds.
const (
	// WrapNone means the value is addressed directly: a query, form or cookie parameter, a
	// field of a JSON body, a multipart part.
	WrapNone Wrapper = iota
	// WrapJSON means the value is a field of a JSON document carried as another
	// parameter's value.
	WrapJSON
	// WrapBase64JSON means that document is base64-encoded before it is sent.
	WrapBase64JSON
)

// Param is one addressable parameter, i.e. one place the scanner can inject
// into. Both the decoded and the on-the-wire form are kept: the decoded values
// are what a check reasons about, while the raw forms are what gets edited in
// place, so a mutation never disturbs the URL-encoding of its neighbours.
type Param struct {
	// Name is the decoded parameter name. For a value inside a document it is the outer
	// name and the field path joined with dots, e.g. "id.uid".
	Name string
	// Value is the decoded parameter value.
	Value string
	// In says which part of the request the parameter lives in.
	In ParamLocation
	// RawName is the parameter name exactly as it appears on the wire.
	RawName string
	// RawValue is the parameter value exactly as it appears on the wire.
	RawValue string
	// Occurrence disambiguates parameters that share a name and location,
	// counting from zero in wire order.
	Occurrence int
	// Path locates a value inside a structured document, as a list of field names and array
	// indices: []string{"user", "name"} or []string{"items", "0", "id"}. It is empty for
	// query, form and cookie parameters, whose value the name alone finds.
	Path []string
	// Wrapper says what carries the document the value lives in, when it is not the body
	// itself.
	Wrapper Wrapper
	// Outer names the parameter whose value carries that document, and OuterOccurrence
	// picks between parameters sharing the name. Both are only meaningful when Wrapper is
	// not WrapNone.
	Outer           string
	OuterOccurrence int
}

// IsEmpty reports whether the parameter carries no value, which is common for
// drop-down and checkbox style injection points.
func (p Param) IsEmpty() bool { return p.Value == "" }

// Key renders a stable identifier for the parameter, e.g. "query:id#0" or, for a field
// inside a parameter's own value, "query:id#0/uid#0".
func (p Param) Key() string {
	if p.Wrapper != WrapNone {
		return string(p.In) + ":" + p.Outer + "#" + strconv.Itoa(p.OuterOccurrence) +
			"/" + strings.Join(p.Path, ".") + "#" + strconv.Itoa(p.Occurrence)
	}
	return string(p.In) + ":" + p.Name + "#" + strconv.Itoa(p.Occurrence)
}

// Params returns every injectable parameter of the request: query string, body
// and cookies, in that order, followed by the fields of any JSON document carried as one
// of their values.
//
// Parameters that cannot be addressed individually — a path segment, a structure deeper
// than the addressable bounds — are intentionally not reported rather than guessed at;
// each would need its own mutation strategy to be done without corrupting the request.
func (r *Request) Params() []Param {
	params := r.QueryParams()
	params = append(params, r.BodyParams()...)
	params = append(params, r.CookieParams()...)
	return expandWrapped(params)
}

// maxWrappedFields bounds how many fields are taken from one parameter's value, so a
// single large blob cannot fill the scan queue on its own.
const maxWrappedFields = 32

// expandWrapped adds the fields of a JSON document carried as a parameter's value.
//
// Such a parameter's value is not a value at all — it is a document, and replacing it
// wholesale leaves the target parsing something that is no longer JSON, so the request
// either fails or reaches the application as an empty parameter. Addressing the fields
// inside it lets the envelope be rebuilt around each mutation, which is the only way a
// parameter of this shape can be tested at all.
//
// The parameter keeps its own entry in the list. A target may well use the value as a
// whole as well as parse it, and dropping it would lose that.
func expandWrapped(params []Param) []Param {
	out := params
	for _, param := range params {
		if param.Wrapper != WrapNone || param.Value == "" {
			continue
		}
		switch param.In {
		case LocQuery, LocBody:
		default:
			continue
		}
		document, wrapper, ok := unwrapParameterValue(param.Value)
		if !ok {
			continue
		}
		slots, ok := scanJSON(document)
		if !ok {
			continue
		}

		counter := map[string]int{}
		count := 0
		for _, slot := range slots {
			if count >= maxWrappedFields {
				break
			}
			name := param.Name + "." + strings.Join(slot.path, ".")
			value := jsonFieldValue(document, slot)
			out = append(out, Param{
				Name:            name,
				Value:           value,
				In:              param.In,
				RawName:         slot.path[len(slot.path)-1],
				RawValue:        value,
				Path:            slot.path,
				Wrapper:         wrapper,
				Outer:           param.Name,
				OuterOccurrence: param.Occurrence,
				Occurrence:      counter[name],
			})
			counter[name]++
			count++
		}
	}
	return out
}

// maxWrappedDocumentBytes bounds the document taken out of a parameter's value. Beyond
// this the value is a payload rather than a parameter, and decoding it would cost more
// than the fields inside it are worth — all the more so because this runs on the
// deduplication path, once for every submitted request.
const maxWrappedDocumentBytes = 64 << 10

// unwrapParameterValue reports whether a parameter's value carries a JSON document, and
// whether that document was base64-encoded before it was put there.
func unwrapParameterValue(value string) ([]byte, Wrapper, bool) {
	if len(value) > maxWrappedDocumentBytes {
		return nil, WrapNone, false
	}
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if _, ok := scanJSON([]byte(trimmed)); ok {
			return []byte(trimmed), WrapJSON, true
		}
	}
	// Some clients encode the whole document before handing it to the parameter.
	if decoded, ok := decodeBase64JSON([]byte(trimmed)); ok {
		return decoded, WrapBase64JSON, true
	}
	return nil, WrapNone, false
}

// QueryParams returns the parameters in the URL query string.
func (r *Request) QueryParams() []Param {
	if r.URL == nil {
		return nil
	}
	return parseOrderedPairs(r.URL.RawQuery, LocQuery)
}

// BodyParams returns the parameters in the request body: form fields, JSON fields or
// multipart parts, according to the media type. Anything else yields nil.
func (r *Request) BodyParams() []Param {
	if !r.HasBody() {
		return nil
	}
	switch contentType := r.ContentType(); {
	case contentType == "application/x-www-form-urlencoded":
		return parseOrderedPairs(string(r.Body), LocBody)
	case isJSONContentType(contentType):
		return r.jsonParams()
	case strings.HasPrefix(contentType, "multipart/form-data"):
		return r.multipartParams()
	default:
		return nil
	}
}

// jsonParams returns the addressable fields of a JSON body. A document that arrives
// base64-encoded is unwrapped and scanned too, so a parameter carried that way is still
// reachable.
func (r *Request) jsonParams() []Param {
	slots, ok := scanJSON(r.Body)
	loc := LocJSON
	if !ok {
		decoded, decodedOK := decodeBase64JSON(r.Body)
		if !decodedOK {
			return nil
		}
		if slots, ok = scanJSON(decoded); !ok {
			return nil
		}
		loc = LocJSONBase64
	}
	body := r.Body
	if loc == LocJSONBase64 {
		body, _ = decodeBase64JSON(r.Body)
	}
	return jsonSlotsToParams(body, slots, loc)
}

// jsonSlotsToParams turns scanned fields into parameters. Two fields reachable by the
// same path — JSON allows a repeated key — are told apart by an occurrence counter, the
// same way repeated query parameters are.
func jsonSlotsToParams(body []byte, slots []jsonSlot, loc ParamLocation) []Param {
	if len(slots) == 0 {
		return nil
	}
	var (
		params  []Param
		counter = map[string]int{}
	)
	for _, slot := range slots {
		if slot.start < 0 || slot.end > len(body) || slot.start >= slot.end {
			continue
		}
		raw := string(body[slot.start:slot.end])
		value := jsonFieldValue(body, slot)
		name := strings.Join(slot.path, ".")
		params = append(params, Param{
			Name:       name,
			Value:      value,
			In:         loc,
			RawName:    slot.path[len(slot.path)-1],
			RawValue:   raw,
			Path:       slot.path,
			Occurrence: counter[name],
		})
		counter[name]++
	}
	return params
}

// CookieParams returns the cookies sent with the request.
func (r *Request) CookieParams() []Param {
	raw := r.Header.Get("Cookie")
	if raw == "" {
		return nil
	}
	return parseCookieHeader(raw)
}

// parseOrderedPairs splits "a=1&b=2" style input into parameters, preserving
// wire order and tolerating the oddities real traffic contains: bare names with
// no '=', empty segments, and repeated names.
//
// It deliberately does not use url.ParseQuery, which sorts the result into a map
// and therefore loses exactly the ordering and duplication a faithful
// in-place mutation needs.
func parseOrderedPairs(raw string, loc ParamLocation) []Param {
	if raw == "" {
		return nil
	}
	var (
		params  []Param
		counter = map[string]int{}
	)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name := decodeComponent(rawName)
		params = append(params, Param{
			Name:       name,
			Value:      decodeComponent(rawValue),
			In:         loc,
			RawName:    rawName,
			RawValue:   rawValue,
			Occurrence: counter[name],
		})
		counter[name]++
	}
	return params
}

// parseCookieHeader splits a Cookie field into parameters.
func parseCookieHeader(raw string) []Param {
	var (
		params  []Param
		counter = map[string]int{}
	)
	for _, pair := range strings.Split(raw, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		rawName = strings.TrimSpace(rawName)
		name := decodeComponent(rawName)
		params = append(params, Param{
			Name:       name,
			Value:      decodeComponent(rawValue),
			In:         LocCookie,
			RawName:    rawName,
			RawValue:   rawValue,
			Occurrence: counter[name],
		})
		counter[name]++
	}
	return params
}

// decodeComponent percent-decodes one query component, falling back to the raw
// text when it is not valid encoding. Real captures routinely contain
// half-encoded values, and refusing to scan them would be worse than scanning
// them with the bytes as they stand.
func decodeComponent(s string) string {
	if s == "" {
		return ""
	}
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	return s
}
