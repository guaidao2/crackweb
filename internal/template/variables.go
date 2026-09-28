package template

import (
	"net"
	"net/url"
	"path"
	"strings"
)

// BuiltinVariables derives the helper variables nuclei templates expect from
// the target URL.
//
// The names and their meanings match nuclei's, so a template written against a
// target of the form https://example.com:8443/app/page.php gets the same values
// it would there.
func BuiltinVariables(target *url.URL) map[string]Value {
	vars := map[string]Value{}
	if target == nil {
		return vars
	}

	hostname := target.Host
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
		hostname = net.JoinHostPort(host, port)
	}

	rootURL := target.Scheme + "://" + hostname

	vars["BaseURL"] = StringValue(target.String())
	vars["RootURL"] = StringValue(rootURL)
	vars["Hostname"] = StringValue(hostname)
	vars["Host"] = StringValue(host)
	vars["Port"] = StringValue(port)
	vars["Scheme"] = StringValue(target.Scheme)
	vars["FQDN"] = StringValue(host)

	// Path is the directory, File the last segment — the split nuclei uses.
	dir, file := path.Split(target.Path)
	vars["Path"] = StringValue(strings.TrimSuffix(dir, "/"))
	vars["File"] = StringValue(file)
	if file == "" {
		vars["File"] = StringValue("")
		vars["Path"] = StringValue(target.Path)
	}

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
