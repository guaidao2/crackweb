package httpmsg

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// A JSON body is the same kind of injection surface a form body is: an API that takes
// application/json carries parameters, just in a different envelope. Before this file
// existed the scanner skipped such a body entirely, so every parameter of a JSON API was
// untested — which looks exactly like a clean target in the report.
//
// Two properties shape the implementation:
//
//   - The value is rewritten in place. Only the bytes of the field being replaced are
//     touched; every other field keeps its original text, its original spacing and its
//     original escaping, so a finding can be reproduced byte for byte.
//   - The scanner is hand-written rather than built on encoding/json. Getting a byte
//     range out of the standard decoder is awkward, and its marshaller escapes '<', '>'
//     and '&' as \u003c etc., which would hide the very reflection a cross-site
//     scripting check looks for.

// jsonKind is how a JSON value is written on the wire.
type jsonKind uint8

const (
	jsonString  jsonKind = iota // "text"
	jsonNumber                  // 12, -1.5e3
	jsonLiteral                 // true, false, null
	jsonObject
	jsonArray
)

// Bounds that keep a malformed or hostile document from costing more than it is worth.
// They are limits on what is *addressed*, not on what is parsed: a document that exceeds
// them is simply not treated as addressable rather than being rejected.
const (
	maxJSONDepth  = 8
	maxJSONFields = 512
)

// jsonSlot is one addressable field: the path that reaches it and the byte range its
// value occupies in the body.
type jsonSlot struct {
	path  []string
	start int
	end   int
	kind  jsonKind
}

// scanJSON returns every addressable field of a JSON document in document order. The
// second result is false when body is not a well-formed JSON document, or when it is
// larger than the scanner is willing to address.
func scanJSON(body []byte) ([]jsonSlot, bool) {
	s := &jsonScanner{data: body}
	s.skipSpace()
	if s.pos >= len(s.data) {
		return nil, false
	}
	// Only a document whose top level is an object or an array has fields to address. A
	// bare scalar is a value without a name, and accepting one would make any short
	// string pass for a JSON body.
	switch s.data[s.pos] {
	case '{', '[':
	default:
		return nil, false
	}
	if !s.parseValue(nil, 0) {
		return nil, false
	}
	s.skipSpace()
	if s.pos != len(s.data) || s.tooBig {
		return nil, false
	}
	return s.slots, true
}

// jsonScanner walks a document byte by byte.
type jsonScanner struct {
	data   []byte
	pos    int
	slots  []jsonSlot
	tooBig bool
}

// parseValue consumes one value at the current position and records it when it is a
// scalar reachable by a path.
func (s *jsonScanner) parseValue(path []string, depth int) bool {
	if s.pos >= len(s.data) {
		return false
	}
	switch c := s.data[s.pos]; {
	case c == '{':
		return s.parseObject(path, depth)
	case c == '[':
		return s.parseArray(path, depth)
	case c == '"':
		start := s.pos
		if !s.skipString() {
			return false
		}
		s.record(path, start, jsonString)
		return true
	case c == 't' || c == 'f' || c == 'n':
		start := s.pos
		if !s.skipLiteral() {
			return false
		}
		s.record(path, start, jsonLiteral)
		return true
	default:
		start := s.pos
		if !s.skipNumber() {
			return false
		}
		s.record(path, start, jsonNumber)
		return true
	}
}

// record keeps one scalar. The top-level value has no path and is therefore not
// addressable: there is no name under which to report or inject into it.
func (s *jsonScanner) record(path []string, start int, kind jsonKind) {
	if len(path) == 0 {
		return
	}
	if len(s.slots) >= maxJSONFields {
		s.tooBig = true
		return
	}
	s.slots = append(s.slots, jsonSlot{
		path:  append([]string(nil), path...),
		start: start,
		end:   s.pos,
		kind:  kind,
	})
}

// parseObject consumes an object, descending into each member.
func (s *jsonScanner) parseObject(path []string, depth int) bool {
	if depth >= maxJSONDepth {
		return s.skipContainer()
	}
	s.pos++ // '{'
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		return true
	}
	for {
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return false
		}
		keyStart := s.pos
		if !s.skipString() {
			return false
		}
		key, ok := unquoteJSON(s.data[keyStart:s.pos])
		if !ok {
			return false
		}
		s.skipSpace()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return false
		}
		s.pos++
		s.skipSpace()
		if !s.parseValue(append(path, key), depth+1) {
			return false
		}
		s.skipSpace()
		if s.pos >= len(s.data) {
			return false
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return true
		default:
			return false
		}
	}
}

// parseArray consumes an array, descending into each element. An element is addressed by
// its index, which is what lets a check name the exact slot of a repeated structure.
func (s *jsonScanner) parseArray(path []string, depth int) bool {
	if depth >= maxJSONDepth {
		return s.skipContainer()
	}
	s.pos++ // '['
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		return true
	}
	for index := 0; ; index++ {
		s.skipSpace()
		if !s.parseValue(append(path, strconv.Itoa(index)), depth+1) {
			return false
		}
		s.skipSpace()
		if s.pos >= len(s.data) {
			return false
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return true
		default:
			return false
		}
	}
}

// skipContainer steps over a balanced object or array without recording anything inside
// it, which is what happens once a document is nested deeper than the scanner addresses.
func (s *jsonScanner) skipContainer() bool {
	depth := 0
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case '"':
			if !s.skipString() {
				return false
			}
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				s.pos++
				return true
			}
		}
		s.pos++
	}
	return false
}

// skipString consumes a string literal, escape sequences included.
func (s *jsonScanner) skipString() bool {
	if s.pos >= len(s.data) || s.data[s.pos] != '"' {
		return false
	}
	s.pos++
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case '\\':
			s.pos += 2
		case '"':
			s.pos++
			return true
		default:
			s.pos++
		}
	}
	return false
}

// skipNumber consumes a number, stopping at the character that ends it.
func (s *jsonScanner) skipNumber() bool {
	start := s.pos
	for s.pos < len(s.data) && !isJSONDelimiter(s.data[s.pos]) {
		s.pos++
	}
	return s.pos > start
}

// skipLiteral consumes true, false or null.
func (s *jsonScanner) skipLiteral() bool {
	for _, literal := range []string{"true", "false", "null"} {
		if bytes.HasPrefix(s.data[s.pos:], []byte(literal)) {
			s.pos += len(literal)
			return true
		}
	}
	return false
}

// skipSpace steps over the whitespace JSON allows between tokens.
func (s *jsonScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// isJSONDelimiter reports whether a byte ends a number.
func isJSONDelimiter(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

// unquoteJSON undoes the escaping of a string literal, returning the text between the
// quotes.
func unquoteJSON(raw []byte) (string, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	inner := raw[1 : len(raw)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		return string(inner), true
	}
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); {
		if inner[i] != '\\' {
			b.WriteByte(inner[i])
			i++
			continue
		}
		if i+1 >= len(inner) {
			return "", false
		}
		switch inner[i+1] {
		case '"', '\\', '/':
			b.WriteByte(inner[i+1])
			i += 2
		case 'b':
			b.WriteByte('\b')
			i += 2
		case 'f':
			b.WriteByte('\f')
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'u':
			if i+6 > len(inner) {
				return "", false
			}
			v, err := strconv.ParseUint(string(inner[i+2:i+6]), 16, 32)
			if err != nil {
				return "", false
			}
			b.WriteRune(rune(v))
			i += 6
		default:
			return "", false
		}
	}
	return b.String(), true
}

// jsonFieldValue renders a scanned field the way a check reads it: a string field without
// its quotes, anything else exactly as it was written.
func jsonFieldValue(document []byte, slot jsonSlot) string {
	if slot.start < 0 || slot.end > len(document) || slot.start > slot.end {
		return ""
	}
	raw := document[slot.start:slot.end]
	if slot.kind == jsonString {
		if unquoted, ok := unquoteJSON(raw); ok {
			return unquoted
		}
	}
	return string(raw)
}

// jsonStringLiteral renders payload as a JSON string. Only the characters JSON requires
// are escaped: '<', '>' and '&' are deliberately left as they are, because escaping them
// would hide the reflection a cross-site scripting check exists to find.
func jsonStringLiteral(payload string) string {
	var b strings.Builder
	b.Grow(len(payload) + 2)
	b.WriteByte('"')
	for i := 0; i < len(payload); i++ {
		switch c := payload[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// replaceJSONField rewrites the field at path with payload, written as a JSON string so
// that an injected value cannot alter the document's structure. occurrence
// disambiguates a path that appears more than once. Every other byte of body is kept as
// it was.
func replaceJSONField(body []byte, path []string, occurrence int, payload string) ([]byte, bool) {
	slots, ok := scanJSON(body)
	if !ok {
		return nil, false
	}
	seen := 0
	for _, slot := range slots {
		if !samePath(slot.path, path) {
			continue
		}
		if seen != occurrence {
			seen++
			continue
		}
		out := make([]byte, 0, len(body)+len(payload)+2)
		out = append(out, body[:slot.start]...)
		out = append(out, jsonStringLiteral(payload)...)
		out = append(out, body[slot.end:]...)
		return out, true
	}
	return nil, false
}

// samePath compares two field paths.
func samePath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// decodeBase64JSON unwraps a body that carries a base64-encoded JSON document. Some APIs
// transport a parameter that way precisely so it is not edited in transit; without this
// step every field inside such a body would be invisible to the scanner.
func decodeBase64JSON(body []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(string(trimmed))
		if err != nil || len(decoded) == 0 {
			continue
		}
		if _, ok := scanJSON(decoded); ok {
			return decoded, true
		}
	}
	return nil, false
}

// encodeBase64JSON re-wraps a document that ReplaceJSONField produced for a base64 body.
func encodeBase64JSON(doc []byte) []byte {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(doc)))
	base64.StdEncoding.Encode(out, doc)
	return out
}

// isJSONContentType reports whether a media type carries a JSON document. The "+json"
// suffix is included because that is how registered vendor types spell it.
func isJSONContentType(mediaType string) bool {
	if mediaType == "" {
		return false
	}
	return mediaType == "application/json" || mediaType == "text/json" ||
		strings.HasSuffix(mediaType, "+json")
}
