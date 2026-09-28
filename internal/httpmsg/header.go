// Package httpmsg is crackweb's single model for HTTP messages.
//
// Everything the tool touches — traffic pulled off the intercepting proxy,
// requests discovered by the crawler, raw requests pasted in from Burp, requests
// the active scanner builds while mutating a parameter — is a *Request. Keeping
// one model means the proxy, the crawler and the scanner interoperate for free:
// anything one of them sees can be replayed, mutated and reported by the others.
package httpmsg

import (
	"net/http"
	"sort"
)

// KV is one header field. Header fields are kept as an ordered list rather than
// a map because crackweb relays and replays raw traffic: field order and the
// original casing are part of what is on the wire, and normalising them would
// both corrupt captures and hand attackers a free fingerprint.
type KV struct {
	Name  string
	Value string
}

// Header is an ordered, case-preserving, multi-value set of header fields.
//
// The zero value is ready to use. Unlike http.Header it does not canonicalise
// field names and does not sort on write, so a request can be read, modified
// and written back out byte-for-byte identical apart from the intended change.
type Header struct {
	items []KV
}

// NewHeader returns a Header pre-loaded with fields, in order.
func NewHeader(fields ...KV) Header {
	h := Header{}
	h.items = append(h.items, fields...)
	return h
}

// Add appends a field, keeping any existing field with the same name.
func (h *Header) Add(name, value string) {
	h.items = append(h.items, KV{Name: name, Value: value})
}

// Set replaces the first field with this name, preserving its position, and
// drops any further fields with the same name. When no field matches, it
// appends.
func (h *Header) Set(name, value string) {
	for i := range h.items {
		if !equalFieldName(h.items[i].Name, name) {
			continue
		}
		h.items[i].Value = value
		h.removeAllAfter(i, name)
		return
	}
	h.Add(name, value)
}

// removeAllAfter deletes every field with the given name that appears after
// index keep.
func (h *Header) removeAllAfter(keep int, name string) {
	out := h.items[:keep+1]
	for _, field := range h.items[keep+1:] {
		if equalFieldName(field.Name, name) {
			continue
		}
		out = append(out, field)
	}
	// Zero the tail so the dropped values are not retained by the backing array.
	for i := len(out); i < len(h.items); i++ {
		h.items[i] = KV{}
	}
	h.items = out
}

// Del removes every field with this name.
func (h *Header) Del(name string) {
	out := h.items[:0]
	for _, field := range h.items {
		if equalFieldName(field.Name, name) {
			continue
		}
		out = append(out, field)
	}
	for i := len(out); i < len(h.items); i++ {
		h.items[i] = KV{}
	}
	h.items = out
}

// Get returns the first value for name, or "" when absent.
func (h Header) Get(name string) string {
	for _, field := range h.items {
		if equalFieldName(field.Name, name) {
			return field.Value
		}
	}
	return ""
}

// Values returns every value for name, in order.
func (h Header) Values(name string) []string {
	var out []string
	for _, field := range h.items {
		if equalFieldName(field.Name, name) {
			out = append(out, field.Value)
		}
	}
	return out
}

// Has reports whether at least one field with this name is present.
func (h Header) Has(name string) bool {
	for _, field := range h.items {
		if equalFieldName(field.Name, name) {
			return true
		}
	}
	return false
}

// Len returns the number of fields.
func (h Header) Len() int { return len(h.items) }

// IsEmpty reports whether there are no fields.
func (h Header) IsEmpty() bool { return len(h.items) == 0 }

// All returns the fields in wire order. The returned slice is a copy: mutating
// it does not affect the Header.
func (h Header) All() []KV {
	out := make([]KV, len(h.items))
	copy(out, h.items)
	return out
}

// Clone returns a deep copy.
func (h Header) Clone() Header {
	out := Header{}
	if len(h.items) > 0 {
		out.items = make([]KV, len(h.items))
		copy(out.items, h.items)
	}
	return out
}

// ToStd converts to net/http's representation. Duplicate field names are
// preserved through Add; ordering is lost, which is fine when the values are
// about to be handed to an http.Client.
func (h Header) ToStd() http.Header {
	out := make(http.Header, len(h.items))
	for _, field := range h.items {
		out.Add(field.Name, field.Value)
	}
	return out
}

// HeaderFromStd converts net/http's representation into an ordered Header.
// net/http does not preserve ordering, so fields are emitted in a stable,
// authorisation-first order that keeps captures readable: request-line
// essentials (Host, Content-Length) lead, then the rest alphabetically.
func HeaderFromStd(std http.Header) Header {
	out := Header{}
	names := make([]string, 0, len(std))
	for name := range std {
		names = append(names, name)
	}
	sortFieldNames(names)
	for _, name := range names {
		for _, value := range std[name] {
			out.Add(name, value)
		}
	}
	return out
}

// sortFieldNames orders field names with Host first, then Content-Length and
// Content-Type, then everything else alphabetically.
func sortFieldNames(names []string) {
	sort.SliceStable(names, func(i, j int) bool {
		pi, pj := fieldPriority(names[i]), fieldPriority(names[j])
		if pi != pj {
			return pi < pj
		}
		return names[i] < names[j]
	})
}

// fieldPriority ranks the fields worth leading with when a message is rendered
// for a human. Lower sorts first.
func fieldPriority(name string) int {
	switch http.CanonicalHeaderKey(name) {
	case "Host":
		return 0
	case "Content-Length":
		return 1
	case "Content-Type":
		return 2
	default:
		return 3
	}
}

// equalFieldName compares field names case-insensitively, as HTTP requires.
func equalFieldName(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
