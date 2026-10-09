package template

import (
	"net/url"
	"path"
	"strings"
)

// maxVariablePasses bounds how many times the variables block is walked while
// it is being resolved. Two passes resolve a variable that references one
// written below it; the bound is what keeps a block that references itself
// (`a: "{{a}}b"`) from looping forever.
const maxVariablePasses = 3

// evaluateVariables resolves the template's variables block into vars.
//
// nuclei calls these variables non-linear: one may reference another, and the
// values each can see grow as the block is walked, so the block is re-evaluated
// until it settles. The walk happens in document order because that is the
// order nuclei uses, which is why the block is not a Go map — a map would
// resolve a reference to another variable differently on every run.
func (t *Template) evaluateVariables(vars map[string]Value) {
	if t.Variables.Len() == 0 {
		return
	}

	for pass := 0; pass < maxVariablePasses; pass++ {
		changed := false
		t.Variables.Each(func(name, raw string) {
			value := StringValue(Expand(raw, vars))
			if current, ok := vars[name]; !ok || current.String() != value.String() {
				vars[name] = value
				changed = true
			}
		})
		if !changed {
			return
		}
	}
}

// BuiltinVariables derives the helper variables nuclei templates expect from the
// target URL.
//
// The names, and what each holds, are nuclei's: RootURL and Hostname keep the
// host as the target was given — a port appears when the target had one, not
// because https implies 443 — Host is the hostname without a port, Path is the
// directory and File the last segment. The defaults matter more than they look.
// {{RootURL}} appears in most published templates, and inventing a port the
// target never had changes the Host header and every URL a template builds from
// it.
func BuiltinVariables(target *url.URL) map[string]Value {
	vars := map[string]Value{}
	if target == nil {
		return vars
	}

	port := target.Port()
	if port == "" {
		switch target.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}

	rootURL := target.Host
	if target.Scheme != "" {
		rootURL = target.Scheme + "://" + target.Host
	}

	// Path is the directory, File the last segment — the split nuclei uses,
	// both taken from the escaped path so an encoded segment stays encoded.
	escaped := target.EscapedPath()
	dir := path.Dir(escaped)
	if dir == "." {
		dir = ""
	}
	file := path.Base(escaped)
	if file == "." {
		file = ""
	}

	query := ""
	if encoded := target.Query().Encode(); encoded != "" {
		query = "?" + encoded
	}

	vars["BaseURL"] = StringValue(target.String())
	vars["RootURL"] = StringValue(rootURL)
	vars["Hostname"] = StringValue(target.Host)
	vars["Host"] = StringValue(target.Hostname())
	vars["Port"] = StringValue(port)
	vars["Scheme"] = StringValue(target.Scheme)
	vars["FQDN"] = StringValue(target.Hostname())
	vars["Path"] = StringValue(dir)
	vars["File"] = StringValue(file)
	vars["Query"] = StringValue(query)
	vars["Input"] = StringValue(target.String())

	return vars
}

// Expand substitutes {{Name}} placeholders in a template string.
//
// Unknown names are left in place rather than blanked: a template referring to
// something crackweb does not provide should produce a request that visibly
// failed to expand, not one that quietly targets the wrong URL.
func Expand(input string, vars map[string]Value) string {
	if !strings.Contains(input, "{{") {
		return input
	}
	var b strings.Builder
	b.Grow(len(input))

	for i := 0; i < len(input); {
		start := strings.Index(input[i:], "{{")
		if start < 0 {
			b.WriteString(input[i:])
			break
		}
		start += i
		b.WriteString(input[i:start])

		end := strings.Index(input[start:], "}}")
		if end < 0 {
			b.WriteString(input[start:])
			break
		}
		end += start

		name := strings.TrimSpace(input[start+2 : end])
		if value, ok := vars[name]; ok {
			b.WriteString(value.String())
		} else {
			b.WriteString(input[start : end+2])
		}
		i = end + 2
	}
	return b.String()
}

// HasPlaceholder reports whether a string references a variable.
func HasPlaceholder(input string) bool { return strings.Contains(input, "{{") }
