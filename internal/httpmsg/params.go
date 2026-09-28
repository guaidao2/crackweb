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
)

// Param is one addressable parameter, i.e. one place the scanner can inject
// into. Both the decoded and the on-the-wire form are kept: the decoded values
// are what a check reasons about, while the raw forms are what gets edited in
// place, so a mutation never disturbs the URL-encoding of its neighbours.
type Param struct {
	// Name is the decoded parameter name.
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
}

// IsEmpty reports whether the parameter carries no value, which is common for
// drop-down and checkbox style injection points.
func (p Param) IsEmpty() bool { return p.Value == "" }

// Key renders a stable identifier for the parameter, e.g. "query:id#0".
func (p Param) Key() string {
	return string(p.In) + ":" + p.Name + "#" + strconv.Itoa(p.Occurrence)
}

// Params returns every injectable parameter of the request: query string, form
// body and cookies, in that order.
//
// Parameters that cannot be addressed individually — a JSON body, a multipart
// upload, a path segment — are intentionally not reported yet rather than
// guessed at; each needs its own mutation strategy to be done without
// corrupting the request.
func (r *Request) Params() []Param {
	params := r.QueryParams()
	params = append(params, r.BodyParams()...)
	params = append(params, r.CookieParams()...)
	return params
}

// QueryParams returns the parameters in the URL query string.
func (r *Request) QueryParams() []Param {
	if r.URL == nil {
		return nil
	}
	return parseOrderedPairs(r.URL.RawQuery, LocQuery)
}

// BodyParams returns the parameters in the request body, currently only for
// form-encoded bodies. Anything else yields nil.
func (r *Request) BodyParams() []Param {
	if !r.HasBody() || r.ContentType() != "application/x-www-form-urlencoded" {
		return nil
	}
	return parseOrderedPairs(string(r.Body), LocBody)
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
