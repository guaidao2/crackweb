package httpmsg

import (
	"bytes"
	"mime"
	"strings"
)

// A multipart body carries the same kind of parameters a form does, one part per field,
// and an upload endpoint is a place where a value routinely reaches a file name, a path
// or a command. Two injection points live here and they are not the same one:
//
//   - a text part's content, which is where a value sits in an ordinary field;
//   - a file part's file name, taken from its Content-Disposition, which is what an
//     upload endpoint decides the stored file will be called.
//
// Both are addressed by byte range, so only the targeted bytes change and the rest of
// the envelope — boundary lines and any binary sibling part — is left exactly as it was.

// maxMultipartParts bounds how many parts are addressed, so a body with thousands of
// parts cannot dominate a scan.
const maxMultipartParts = 64

// multipartPart is one addressable part.
type multipartPart struct {
	name string
	// start and end bracket the part's content.
	start int
	end   int
	// file records a part that carries an uploaded file. Its content is not a value to
	// replace — the file name is.
	file bool
	// nameStart and nameEnd bracket the file name in the part's Content-Disposition; both
	// are -1 when the part is not a file.
	nameStart int
	nameEnd   int
}

// multipartParams returns the addressable parts of a multipart/form-data body: the
// content of every text part, and the file name of every file part.
func (r *Request) multipartParams() []Param {
	boundary := multipartBoundary(r.Header.Get("Content-Type"))
	if boundary == "" {
		return nil
	}
	parts, ok := scanMultipart(r.Body, boundary)
	if !ok || len(parts) == 0 {
		return nil
	}
	var (
		params  []Param
		counter = map[string]int{}
	)
	for _, part := range parts {
		if part.name == "" {
			continue
		}
		location := LocMultipart
		start, end := part.start, part.end
		if part.file {
			location = LocMultipartFilename
			start, end = part.nameStart, part.nameEnd
		}
		if start < 0 || end > len(r.Body) || start >= end {
			continue
		}
		raw := string(r.Body[start:end])
		params = append(params, Param{
			Name:       part.name,
			Value:      raw,
			In:         location,
			RawName:    part.name,
			RawValue:   raw,
			Occurrence: counter[part.name],
		})
		counter[part.name]++
	}
	return params
}

// replaceMultipartField rewrites one part: its content when filename is false, the file
// name in its Content-Disposition when it is true. Every boundary line and every sibling
// part is left as it was. occurrence disambiguates a field name used more than once.
func replaceMultipartField(body []byte, boundary, name string, occurrence int, payload string, filename bool) ([]byte, bool) {
	parts, ok := scanMultipart(body, boundary)
	if !ok {
		return nil, false
	}
	seen := 0
	for _, part := range parts {
		if part.name != name {
			continue
		}
		if seen != occurrence {
			seen++
			continue
		}
		start, end := part.start, part.end
		if filename {
			start, end = part.nameStart, part.nameEnd
		}
		if start < 0 || end > len(body) || start > end {
			return nil, false
		}
		out := make([]byte, 0, len(body)+len(payload))
		out = append(out, body[:start]...)
		out = append(out, payload...)
		out = append(out, body[end:]...)
		return out, true
	}
	return nil, false
}

// multipartBoundary extracts the boundary parameter from a media type.
func multipartBoundary(contentType string) string {
	if contentType == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return params["boundary"]
}

// scanMultipart walks a multipart body and returns its parts. The second result reports
// whether the body ended with a closing boundary, which is what tells a complete envelope
// from a truncated one.
func scanMultipart(body []byte, boundary string) ([]multipartPart, bool) {
	delimiter := []byte("--" + boundary)
	pos := bytes.Index(body, delimiter)
	if pos < 0 {
		return nil, false
	}

	var parts []multipartPart
	for pos >= 0 && pos < len(body) {
		rest := body[pos+len(delimiter):]
		// A closing delimiter ends the body.
		if bytes.HasPrefix(rest, []byte("--")) {
			return parts, true
		}
		// The delimiter line ends at the next newline; anything else on it is a transport
		// artefact the part parser does not need.
		lineEnd := bytes.IndexByte(rest, '\n')
		if lineEnd < 0 {
			return nil, false
		}
		headerStart := pos + len(delimiter) + lineEnd + 1

		headerEnd, ok := endOfHeaders(body, headerStart)
		if !ok {
			return nil, false
		}
		headers := body[headerStart:headerEnd]
		name, filename, isFile := partDisposition(headers)

		part := multipartPart{name: name, file: isFile, nameStart: -1, nameEnd: -1}
		if isFile && filename != "" {
			if start, end, ok := filenameRange(headers, headerStart, filename); ok {
				part.nameStart, part.nameEnd = start, end
			}
		}

		next := bytes.Index(body[headerEnd:], delimiter)
		if next < 0 {
			return nil, false
		}
		part.start = headerEnd
		part.end = trimTrailingNewline(body, headerEnd, headerEnd+next)

		if name != "" && len(parts) < maxMultipartParts {
			parts = append(parts, part)
		}
		pos = headerEnd + next
	}
	return nil, false
}

// endOfHeaders finds where a part's header block ends, returning the offset just past the
// blank line that separates the headers from the content.
func endOfHeaders(body []byte, start int) (int, bool) {
	cursor := start
	for cursor < len(body) {
		lineEnd := bytes.IndexByte(body[cursor:], '\n')
		if lineEnd < 0 {
			return 0, false
		}
		line := body[cursor : cursor+lineEnd]
		if len(bytes.TrimRight(line, "\r")) == 0 {
			return cursor + lineEnd + 1, true
		}
		cursor += lineEnd + 1
	}
	return 0, false
}

// partDisposition reads the field name, the file name and whether the part is a file from
// its Content-Disposition header.
func partDisposition(headers []byte) (name, filename string, isFile bool) {
	for _, line := range strings.Split(string(headers), "\n") {
		trimmed := strings.TrimSpace(line)
		colon := strings.IndexByte(trimmed, ':')
		if colon < 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(trimmed[:colon]), "Content-Disposition") {
			continue
		}
		_, params, err := mime.ParseMediaType(strings.TrimSpace(trimmed[colon+1:]))
		if err != nil {
			return "", "", false
		}
		filename, isFile = params["filename"]
		return params["name"], filename, isFile
	}
	return "", "", false
}

// filenameRange locates the value of a part's file name parameter, returning absolute
// offsets into the body.
//
// It searches for the parameter rather than for the word, because a form is free to call
// a field `filename` — and upload forms routinely do. Matching a bare "filename" would
// find the field name inside `name="filename"` and rewrite that instead, so the search is
// anchored on the `filename=` spelling and confirmed against the value the header parser
// actually read. Both the quoted and the unquoted spelling are handled.
func filenameRange(headers []byte, base int, filename string) (int, int, bool) {
	lower := bytes.ToLower(headers)
	key := []byte("filename=")
	for search := 0; ; {
		index := bytes.Index(lower[search:], key)
		if index < 0 {
			return 0, 0, false
		}
		index += search
		valueStart := index + len(key)
		remainder := headers[valueStart:]

		if bytes.HasPrefix(remainder, []byte(`"`+filename+`"`)) {
			start := valueStart + 1
			return base + start, base + start + len(filename), true
		}
		if bytes.HasPrefix(remainder, []byte(filename)) {
			end := valueStart + len(filename)
			if end >= len(headers) || headers[end] == ';' || headers[end] == '\r' || headers[end] == '\n' {
				return base + valueStart, base + end, true
			}
		}
		search = index + len(key)
	}
}

// trimTrailingNewline drops the CRLF that precedes the next boundary line, which is
// envelope syntax rather than part content.
func trimTrailingNewline(body []byte, start, end int) int {
	for end > start && (body[end-1] == '\n' || body[end-1] == '\r') {
		end--
	}
	return end
}
