package httpmsg

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
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
	// WrapBase64 means the value itself is a base64-encoded string rather than a JSON
	// document. A parameter carrying `YQ==` is addressed as the text it decodes to, and
	// a mutation is re-encoded in the alphabet and padding the value already used. Such a
	// value is addressed in every location that has a way back to it — a query or form
	// parameter, a cookie, a field of a JSON body, the content or file name of a
	// multipart part — and the enclosing value is rebuilt around each mutation.
	WrapBase64
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
	// Base64Style records which base64 spelling a WrapBase64 value used, so a mutation
	// is written back in the same alphabet and padding. Empty for other wrappers.
	Base64Style string
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
	if p.Wrapper == WrapBase64 {
		return string(p.In) + ":" + p.Outer + "#" + strconv.Itoa(p.OuterOccurrence) +
			"/base64#" + strconv.Itoa(p.Occurrence)
	}
	if p.Wrapper != WrapNone {
		return string(p.In) + ":" + p.Outer + "#" + strconv.Itoa(p.OuterOccurrence) +
			"/" + strings.Join(p.Path, ".") + "#" + strconv.Itoa(p.Occurrence)
	}
	return string(p.In) + ":" + p.Name + "#" + strconv.Itoa(p.Occurrence)
}

// Params returns every injectable parameter of the request: query string, body
// and cookies, in that order, followed by what those values carry — the fields of a JSON
// document, and the text a base64 value decodes to.
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

// expandWrapped adds what a parameter's value carries when the value is not a value of
// its own: the fields of a JSON document, or the text a base64 string decodes to.
//
// A parameter carrying a document is not carrying a value at all, and replacing it
// wholesale leaves the target parsing something that is no longer JSON, so the request
// either fails or reaches the application as an empty parameter. Addressing the fields
// inside it lets the envelope be rebuilt around each mutation, which is the only way a
// parameter of this shape can be tested at all. A base64 value has the same problem in a
// smaller form: the application decodes it, so a payload written into the base64 text
// itself arrives as something that is not the payload.
//
// Both are addressed wherever a location gives a way back to the enclosing value — a
// query pair, a form field, a cookie, a field of a JSON body and the content or file name
// of a multipart part. The parameter keeps its own entry in the list either way: a target
// may well use the value as a whole as well as decode or parse it, and dropping it would
// lose that.
func expandWrapped(params []Param) []Param {
	out := params
	for _, param := range params {
		if param.Wrapper != WrapNone || param.Value == "" {
			continue
		}
		if !carriesInnerValue(param.In) {
			continue
		}
		// Only a value carried as one parameter of a name=value list can be a document
		// in its own right. A field of a JSON body is already a field, and a multipart
		// part is one; treating either as an envelope would address a structure the
		// request does not have.
		if param.In == LocQuery || param.In == LocBody {
			if document, wrapper, ok := unwrapParameterValue(param.Value); ok {
				out = append(out, expandDocument(param, document, wrapper)...)
				continue
			}
		}
		// A value that is not a document may still be a base64-encoded scalar. Its
		// decoded text is the value the application sees, so it is addressable in the
		// same way; a payload is re-encoded with the same alphabet and padding.
		if text, style, decoded := unwrapBase64Scalar(scalarValue(param)); decoded {
			out = append(out, base64ScalarParam(param, text, style))
		}
	}
	return out
}

// carriesInnerValue reports whether a value at this location has an enclosing value that
// can be rebuilt around a change to it.
//
// Every location the scanner addresses has a way back: a query or form pair is found by
// name, a cookie by name within the Cookie field, a JSON field by its path, a multipart
// part by its name. A location without one would produce a parameter whose mutation could
// never be sent, which reads in the report like a parameter that was tested and found
// clean.
func carriesInnerValue(loc ParamLocation) bool {
	switch loc {
	case LocQuery, LocBody, LocCookie, LocJSON, LocJSONBase64, LocMultipart, LocMultipartFilename:
		return true
	default:
		return false
	}
}

// expandDocument returns the fields of a JSON document carried as a parameter's value.
func expandDocument(param Param, document []byte, wrapper Wrapper) []Param {
	slots, ok := scanJSON(document)
	if !ok {
		return nil
	}
	var out []Param
	counter := map[string]int{}
	for _, slot := range slots {
		if len(out) >= maxWrappedFields {
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
	}
	return out
}

// scalarValue returns the text a location hands the application, which is what a base64
// value there encodes.
//
// It is the decoded value everywhere but in a Cookie field: a cookie value is not
// form-encoded, so its '+' is a literal plus rather than a space. The query decoder the
// other locations share would turn the '+' of a standard-alphabet base64 value into a
// space and leave the whole cookie unaddressed, which reads in the report as a value that
// was tested and found clean.
func scalarValue(param Param) string {
	if param.In != LocCookie {
		return param.Value
	}
	if unescaped, err := url.PathUnescape(param.RawValue); err == nil {
		return unescaped
	}
	return param.RawValue
}

// base64ScalarParam returns the parameter that addresses the text a base64 value decodes
// to, whatever location that value sits in.
//
// The enclosing parameter is kept on it — the name or path that finds the value again,
// the occurrence that tells two same-named ones apart, and the base64 spelling it used —
// because a mutation has to be written back into that shape: base64 again, in the same
// alphabet and padding, in the place the original value was found.
func base64ScalarParam(param Param, text, style string) Param {
	return Param{
		Name:            param.Name + ".base64",
		Value:           text,
		In:              param.In,
		RawName:         param.RawName,
		RawValue:        param.RawValue,
		Base64Style:     style,
		Path:            param.Path,
		Occurrence:      param.Occurrence,
		Wrapper:         WrapBase64,
		Outer:           param.Name,
		OuterOccurrence: param.Occurrence,
	}
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

// unwrapBase64Scalar reports whether a value is a canonical base64 string that decodes
// to text, and returns that text together with the spelling it used. It is narrower than
// a plain base64 decode on purpose: a session id, a hash or a random token also uses a
// base64 alphabet, but its bytes are not text; and a short ordinary value such as
// `en` or `all` decodes under a non-padded decoder while its canonical encoding differs.
// Requiring the canonical round-trip is what keeps those values from becoming parameters
// that do not exist.
func unwrapBase64Scalar(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 2 || len(trimmed) > maxWrappedDocumentBytes {
		return "", "", false
	}
	// A JWT is a dot-separated triple, not one base64 value. Its segments are handled by
	// the checks that know what a token is.
	if strings.Contains(trimmed, ".") {
		return "", "", false
	}

	styles := []struct {
		name     string
		encoding *base64.Encoding
	}{
		{base64StyleStd, base64.StdEncoding},
		{base64StyleStdRaw, base64.RawStdEncoding},
		{base64StyleURL, base64.URLEncoding},
		{base64StyleURLRaw, base64.RawURLEncoding},
	}
	var decoded []byte
	style := ""
	for _, candidate := range styles {
		out, err := candidate.encoding.DecodeString(trimmed)
		if err != nil || candidate.encoding.EncodeToString(out) != trimmed {
			continue
		}
		decoded, style = out, candidate.name
		break
	}
	if len(decoded) == 0 || !utf8.Valid(decoded) {
		return "", "", false
	}

	printable, alphanumeric := 0, false
	for _, b := range decoded {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
			alphanumeric = true
		}
	}
	if !alphanumeric || float64(printable)/float64(len(decoded)) < 0.9 {
		return "", "", false
	}
	return string(decoded), style, true
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
