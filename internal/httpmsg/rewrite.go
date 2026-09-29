package httpmsg

import (
	"net/url"
	"strconv"
	"strings"
)

// RewriteBody replaces one parameter's value inside a structured body — a JSON document
// or a multipart part — and returns the new body.
//
// These locations need their own path rather than the plain "encode a value and put it
// where the old one was" the query, form and cookie locations use, because neither is
// percent-encoded on the wire: a payload placed in a JSON document has to be quoted as a
// JSON string, and a multipart part is raw bytes. Applying the transport encoding to
// them would deliver a literal percent sequence instead of the injected value.
//
// The second result is false when the body is not of the kind param describes, or when
// the field is no longer present — which can happen when a request was rewritten in
// between, and is reported rather than silently ignored.
func RewriteBody(body []byte, contentType string, param Param, payload string) ([]byte, bool) {
	switch param.In {
	case LocJSON:
		return replaceJSONField(body, param.Path, param.Occurrence, payload)

	case LocJSONBase64:
		document, ok := decodeBase64JSON(body)
		if !ok {
			return nil, false
		}
		updated, ok := replaceJSONField(document, param.Path, param.Occurrence, payload)
		if !ok {
			return nil, false
		}
		return encodeBase64JSON(updated), true

	case LocMultipart:
		return replaceMultipartField(body, multipartBoundary(contentType), param.RawName, param.Occurrence, payload, false)

	case LocMultipartFilename:
		return replaceMultipartField(body, multipartBoundary(contentType), param.RawName, param.Occurrence, payload, true)

	default:
		return nil, false
	}
}

// RewriteWrapped replaces a value that lives inside a JSON document carried as another
// parameter's value, rebuilding the envelope around the change: the document is decoded,
// the field inside it is replaced, and the result is encoded back into the shape the
// parameter had.
//
// Nothing about the envelope is guessed at. A value that is not the kind of document the
// parameter says it carries makes the rewrite report failure rather than send something
// the target will not recognise.
func RewriteWrapped(req *Request, param Param, payload string) (*Request, bool) {
	if req == nil || param.Outer == "" {
		return nil, false
	}
	out := req.Clone()

	var container string
	switch param.In {
	case LocQuery:
		if out.URL == nil {
			return nil, false
		}
		container = out.URL.RawQuery
	case LocBody:
		container = string(out.Body)
	default:
		return nil, false
	}

	rawValue, write, ok := findPairValue(container, param)
	if !ok {
		return nil, false
	}
	updated, ok := rewriteWrappedValue(rawValue, param, payload)
	if !ok {
		return nil, false
	}
	rewritten := write(updated)

	switch param.In {
	case LocQuery:
		out.URL.RawQuery = rewritten
	case LocBody:
		out.Body = []byte(rewritten)
		out.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	}
	return out, true
}

// findPairValue returns the raw value of the pair a parameter addresses, along with a
// function that writes a replacement back into the container it came from. The pair's
// neighbours are left exactly as they were.
func findPairValue(container string, param Param) (string, func(string) string, bool) {
	parts := strings.Split(container, "&")
	seen := 0
	for index, part := range parts {
		name, value, _ := strings.Cut(part, "=")
		if name != param.Outer {
			continue
		}
		if seen != param.OuterOccurrence {
			seen++
			continue
		}
		position := index
		return value, func(newValue string) string {
			parts[position] = name + "=" + newValue
			return strings.Join(parts, "&")
		}, true
	}
	return "", nil, false
}

// rewriteWrappedValue decodes the envelope a parameter's value carries, replaces the field
// inside it, and re-encodes the result.
func rewriteWrappedValue(rawValue string, param Param, payload string) (string, bool) {
	document := []byte(decodeComponent(rawValue))
	if param.Wrapper == WrapBase64JSON {
		decoded, ok := decodeBase64JSON(document)
		if !ok {
			return "", false
		}
		document = decoded
	}
	updated, ok := replaceJSONField(document, param.Path, param.Occurrence, payload)
	if !ok {
		return "", false
	}
	if param.Wrapper == WrapBase64JSON {
		updated = encodeBase64JSON(updated)
	}
	return url.QueryEscape(string(updated)), true
}
