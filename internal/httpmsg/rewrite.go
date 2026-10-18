package httpmsg

import (
	"encoding/base64"
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

// RewriteWrapped replaces a value that does not sit in the request itself but inside one
// of its parameters or fields, rebuilding the envelope around the change.
//
// Two shapes are addressed this way, and they are rebuilt differently:
//
//   - a JSON document carried as a parameter's value (WrapJSON, WrapBase64JSON): the
//     document is decoded, the field inside it is replaced, and the result is encoded back
//     into the shape the parameter had;
//   - a base64-encoded scalar (WrapBase64): the payload is written in the alphabet and
//     padding the value already used, in whichever location carried it — query, form body,
//     cookie, JSON field or multipart part.
//
// Nothing about the envelope is guessed at. A value that is not the kind of thing the
// parameter says it carries makes the rewrite report failure rather than send something
// the target will not recognise.
func RewriteWrapped(req *Request, param Param, payload string) (*Request, bool) {
	if req == nil || param.Outer == "" {
		return nil, false
	}
	out := req.Clone()

	// A base64 scalar sits inside a single value, and that value may be carried by any of
	// the locations a parameter has. Each one is edited where it lives, so the rest of the
	// request — the neighbouring pairs, the document's spacing, the multipart envelope —
	// is left exactly as it was.
	if param.Wrapper == WrapBase64 {
		return rewriteBase64Scalar(out, param, payload)
	}

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

// rewriteBase64Scalar writes payload into a base64-encoded value and puts it back where
// the value was found.
//
// The payload is encoded in the spelling the original value used, so the mutation differs
// from it in content and not in shape: a URL-safe token that arrived unpadded is sent back
// unpadded, and a standard one keeps its padding. Everything around the value — the other
// query pairs, the cookies beside it, the document's remaining fields, the multipart
// envelope — is left as it was.
func rewriteBase64Scalar(req *Request, param Param, payload string) (*Request, bool) {
	encoded := encodeBase64WithStyle(param.Base64Style, []byte(payload))

	switch param.In {
	case LocQuery:
		if req.URL == nil {
			return nil, false
		}
		_, write, ok := findPairValue(req.URL.RawQuery, param)
		if !ok {
			return nil, false
		}
		// A query value is percent-encoded on the wire, and base64 uses '=' and '+',
		// characters a query string may not carry literally.
		req.URL.RawQuery = write(url.QueryEscape(encoded))
		return req, true

	case LocBody:
		_, write, ok := findPairValue(string(req.Body), param)
		if !ok {
			return nil, false
		}
		rewritten := write(url.QueryEscape(encoded))
		req.Body = []byte(rewritten)
		req.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
		return req, true

	case LocCookie:
		// A cookie value is written as it stands: a Cookie field is not percent-encoded
		// by the transport, and every character of a base64 value is one it may carry.
		cookie, ok := replaceCookieValue(req.Header.Get("Cookie"), param, encoded)
		if !ok {
			return nil, false
		}
		req.Header.Set("Cookie", cookie)
		return req, true

	case LocJSON, LocJSONBase64:
		document := req.Body
		if param.In == LocJSONBase64 {
			decoded, ok := decodeBase64JSON(req.Body)
			if !ok {
				return nil, false
			}
			document = decoded
		}
		updated, ok := replaceJSONField(document, param.Path, param.Occurrence, encoded)
		if !ok {
			return nil, false
		}
		if param.In == LocJSONBase64 {
			updated = encodeBase64JSON(updated)
		}
		req.Body = updated
		req.Header.Set("Content-Length", strconv.Itoa(len(updated)))
		return req, true

	case LocMultipart, LocMultipartFilename:
		updated, ok := replaceMultipartField(req.Body, multipartBoundary(req.Header.Get("Content-Type")),
			param.RawName, param.Occurrence, encoded, param.In == LocMultipartFilename)
		if !ok {
			return nil, false
		}
		req.Body = updated
		req.Header.Set("Content-Length", strconv.Itoa(len(updated)))
		return req, true

	default:
		return nil, false
	}
}

// replaceCookieValue rewrites one cookie's value within a Cookie field, leaving the other
// cookies — their names, their order and their spacing — exactly as they were.
//
// The second result is false when the cookie the parameter addresses is no longer present,
// which happens when a request was rewritten in between and is reported rather than
// guessed at.
func replaceCookieValue(header string, param Param, newValue string) (string, bool) {
	segments := strings.Split(header, ";")
	seen := 0
	for index, segment := range segments {
		name, value, found := strings.Cut(segment, "=")
		if !found || strings.TrimSpace(name) != param.Outer {
			continue
		}
		if seen != param.OuterOccurrence {
			seen++
			continue
		}
		// Everything up to the value is kept as written, so the spacing around the name
		// survives the rewrite.
		segments[index] = segment[:len(segment)-len(value)] + newValue
		return strings.Join(segments, ";"), true
	}
	return "", false
}

// Base64 spellings a parameter can arrive in, recorded with the parameter so a mutation
// is written back the same way.
const (
	base64StyleStd    = "std"
	base64StyleStdRaw = "std-raw"
	base64StyleURL    = "url"
	base64StyleURLRaw = "url-raw"
)

// encodeBase64WithStyle writes a payload in the spelling the original value used.
func encodeBase64WithStyle(style string, payload []byte) string {
	var encoding *base64.Encoding
	switch style {
	case base64StyleStd:
		encoding = base64.StdEncoding
	case base64StyleURL:
		encoding = base64.URLEncoding
	case base64StyleURLRaw:
		encoding = base64.RawURLEncoding
	default:
		encoding = base64.RawStdEncoding
	}
	return encoding.EncodeToString(payload)
}
