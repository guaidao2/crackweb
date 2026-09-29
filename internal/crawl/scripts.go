package crawl

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// scriptPathRe finds a request path written as a string literal in a page's own script.
//
// The calls a page makes at runtime are endpoints nothing links to: a search box that
// fetches when it is submitted, a delete button, a form whose submit handler assembles the
// request itself. The browser issues none of them on load, so link-following never sees
// them and the headless engine only sees the ones that fire by themselves. They are in the
// page's text the whole time.
//
// The match is deliberately narrow — a known API prefix rather than any string that starts
// with a slash — because scripts are full of paths that are not endpoints: images, styles,
// routes the page handles itself. Asking for those costs requests and finds nothing.
//
// The delimiters are the three quote characters, and the character class runs to the
// closing one rather than stopping at a fixed set: a path carrying an interpolated call —
// `?keyword=${encodeURIComponent(keyword)}` — contains parentheses, and a narrower class
// truncates it in the middle.
var scriptPathRe = regexp.MustCompile("[\"'\x60](/api/[^\"'\x60\n]{0,300})[\"'\x60]")

// scriptMethodRe finds the method named near a path. It is written two ways — in the
// options object of a fetch (`method: 'POST'`) and as the first argument of an
// XMLHttpRequest's open (`open('POST', url)`) — so the call's own name and arguments are
// searched and the first method keyword found decides.
var scriptMethodRe = regexp.MustCompile(`(?i)\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b`)

// templateValueRe matches the interpolated parts of a template literal, and of the
// encodeURIComponent calls that usually wrap them.
var templateValueRe = regexp.MustCompile(`\$\{[^}]{0,120}\}`)

// safeMethods are the methods that ask for something without changing it.
var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "TRACE": true}

// formDataFieldRe finds the names appended to a FormData: `fd.append('file', input.files[0])`.
var formDataFieldRe = regexp.MustCompile(`\.append\(\s*["'\x60]([^"'\x60]{1,60})["'\x60]`)

// jsonBodyRe finds a JSON.stringify call and captures its object literal.
var jsonBodyRe = regexp.MustCompile(`JSON\.stringify\s*\(\s*\{([^{}]{0,600})\}`)

// jsonKeyRe pulls the names out of that object literal. A shorthand property (`{title}`)
// and a keyed one (`{title: docTitle}`) both name a field.
var jsonKeyRe = regexp.MustCompile(`(?:^|[,{])\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:`)

// scriptBodyVarRe finds a body written as a variable: `body: formData`.
var scriptBodyVarRe = regexp.MustCompile(`body\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)`)

// variableRegionRe finds where a variable is declared.
var variableRegionRe = regexp.MustCompile(`(?:const|let|var)\s+%s\s*=`)

// scriptBody is the shape of a request body a script builds.
type scriptBody int

const (
	// bodyNone is a request with no body.
	bodyNone scriptBody = iota
	// bodyMultipart is a FormData, which goes out as multipart/form-data.
	bodyMultipart
	// bodyJSON is a JSON.stringify'd object.
	bodyJSON
)

// scriptCall is one request a page's script makes.
type scriptCall struct {
	// URL is the address, resolved and in scope.
	URL string
	// Method is what the script sends it with. A call that names none is a GET, which is
	// what a browser does.
	Method string
	// Body describes what the request carries, so the crawler can send the same shape.
	Body scriptBody
	// Fields are the names the body declares, in the order the script writes them.
	Fields []string
}

// scriptCalls returns the requests a page's script makes, resolved and in scope.
//
// The method matters because the crawler has to send the request the way the page does. A
// search endpoint reached with GET answers; an upload endpoint reached with GET does not
// exist, and its shape — multipart, with a file part — is the whole point of testing it.
// Reading the method and the body out of the call is what turns a discovered address into a
// request worth making.
func scriptCalls(body string, base *url.URL, allowStateChange bool) []scriptCall {
	var out []scriptCall
	seen := map[string]bool{}
	for _, match := range scriptPathRe.FindAllStringSubmatchIndex(body, -1) {
		path := strings.TrimSpace(templateValueRe.ReplaceAllString(body[match[2]:match[3]], "1"))
		if path == "" || path == "/api/" {
			continue
		}
		call := describeCall(body, match)
		if !allowStateChange && !safeMethods[call.Method] {
			continue
		}
		resolved, err := base.Parse(path)
		if err != nil || resolved.Host != base.Host {
			continue
		}
		call.URL = resolved.String()
		key := call.Method + " " + call.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, call)
	}
	return out
}

// scriptTargets returns the paths a page's script reads, in the form the crawler queues
// them as links. A write is not a link: it is replayed with the method the script uses, if
// it is queued at all.
func scriptTargets(body string, base *url.URL, allowStateChange bool) []string {
	var out []string
	for _, call := range scriptCalls(body, base, allowStateChange) {
		if safeMethods[call.Method] {
			out = append(out, call.URL)
		}
	}
	return out
}

// describeCall reads a call's method and body out of the text around its path.
func describeCall(body string, path []int) scriptCall {
	call := scriptCall{Method: "GET", Body: bodyNone}
	open := strings.LastIndex(body[:path[2]], "(")
	if open < 0 {
		return call
	}
	// The name sits immediately before the parenthesis: `fetch(`, `axios.delete(`,
	// `xhr.open(`. The method may be written there rather than in the arguments.
	name := open
	for name > 0 && isIdentifierByte(body[name-1]) {
		name--
	}
	text := body[name:open] + callArguments(body, open)

	// A body is usually built a few lines above the call that sends it — `const fd = new
	// FormData(); fd.append(...); fetch(url, { body: fd })` — so its shape is not in the
	// call at all. When the call names a variable, the text from that variable's
	// declaration onwards is what gets read.
	if named := scriptBodyVarRe.FindStringSubmatch(text); named != nil {
		if region := variableRegion(body, named[1]); region != "" {
			text += " " + region
		}
	}

	if method := scriptMethodRe.FindString(text); method != "" {
		call.Method = strings.ToUpper(method)
	}
	switch {
	case strings.Contains(text, "FormData"):
		call.Body = bodyMultipart
		for _, field := range formDataFieldRe.FindAllStringSubmatch(text, -1) {
			call.Fields = append(call.Fields, field[1])
		}
	case jsonBodyRe.MatchString(text):
		call.Body = bodyJSON
		object := jsonBodyRe.FindStringSubmatch(text)[1]
		for _, key := range jsonKeyRe.FindAllStringSubmatch(object, -1) {
			if field := strings.TrimSpace(key[1]); field != "" {
				call.Fields = append(call.Fields, field)
			}
		}
	}
	return call
}

// variableRegion returns the text from a variable's declaration to the end of the script.
//
// It deliberately runs to the end rather than to the next statement: a FormData is filled by
// several append() calls written after it, and stopping at the first `;` would read the
// declaration and none of the fields.
func variableRegion(body, name string) string {
	pattern := regexp.MustCompile(fmt.Sprintf(variableRegionRe.String(), regexp.QuoteMeta(name)))
	location := pattern.FindStringIndex(body)
	if location == nil || location[1] >= len(body) {
		return ""
	}
	end := location[1] + maxVariableRegion
	if end > len(body) {
		end = len(body)
	}
	return body[location[1]:end]
}

// maxVariableRegion bounds how much text after a declaration is read looking for the fields
// that fill it. A FormData is filled within a few lines of being declared.
const maxVariableRegion = 2000

// callArguments returns the text from an opening parenthesis to the one that closes it.
//
// The search has to stay inside one call. A window of characters around the path reads the
// neighbouring call's method and mislabels this one, which is how a plain `fetch('/api/x')`
// sitting next to a `{ method: 'POST' }` gets treated as a write.
func callArguments(body string, open int) string {
	depth := 0
	for index := open; index < len(body); index++ {
		switch body[index] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[open : index+1]
			}
		}
	}
	return body[open:]
}

// isIdentifierByte reports whether a byte can be part of a call's name.
func isIdentifierByte(c byte) bool {
	return c == '_' || c == '.' || c == '$' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// safeMethodNear reports whether the call carrying the path at path[2:3] names a method
// that changes nothing. A call that names no method at all is a GET, which is safe.
func safeMethodNear(body string, path []int) bool {
	return safeMethods[describeCall(body, path).Method]
}
