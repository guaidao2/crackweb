package httpmsg

import (
	"net/http"
	"reflect"
	"testing"
)

// stdHeader builds a net/http header from name/value pairs.
func stdHeader(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

func TestHeaderPreservesOrderAndCase(t *testing.T) {
	h := Header{}
	h.Add("x-Lower", "1")
	h.Add("Accept", "*/*")
	h.Add("Host", "example.com")

	want := []KV{
		{Name: "x-Lower", Value: "1"},
		{Name: "Accept", Value: "*/*"},
		{Name: "Host", Value: "example.com"},
	}
	if got := h.All(); !reflect.DeepEqual(got, want) {
		t.Errorf("All() = %v, want %v", got, want)
	}
}

func TestHeaderLookupIsCaseInsensitive(t *testing.T) {
	h := NewHeader(KV{Name: "Content-Type", Value: "text/html"})

	if got := h.Get("content-type"); got != "text/html" {
		t.Errorf("Get(content-type) = %q, want %q", got, "text/html")
	}
	if !h.Has("CONTENT-TYPE") {
		t.Error("Has(CONTENT-TYPE) = false, want true")
	}
	if h.Has("Content-Length") {
		t.Error("Has(Content-Length) = true, want false")
	}
}

func TestHeaderSetKeepsPositionAndDropsDuplicates(t *testing.T) {
	h := NewHeader(
		KV{Name: "Host", Value: "example.com"},
		KV{Name: "Set-Cookie", Value: "a=1"},
		KV{Name: "Set-Cookie", Value: "b=2"},
		KV{Name: "Accept", Value: "*/*"},
	)

	h.Set("set-cookie", "c=3")

	want := []KV{
		{Name: "Host", Value: "example.com"},
		{Name: "Set-Cookie", Value: "c=3"},
		{Name: "Accept", Value: "*/*"},
	}
	if got := h.All(); !reflect.DeepEqual(got, want) {
		t.Errorf("after Set: All() = %v, want %v", got, want)
	}
}

func TestHeaderSetAppendsWhenAbsent(t *testing.T) {
	h := NewHeader(KV{Name: "Host", Value: "example.com"})
	h.Set("X-New", "1")

	want := []KV{
		{Name: "Host", Value: "example.com"},
		{Name: "X-New", Value: "1"},
	}
	if got := h.All(); !reflect.DeepEqual(got, want) {
		t.Errorf("All() = %v, want %v", got, want)
	}
}

func TestHeaderDelRemovesEveryMatch(t *testing.T) {
	h := NewHeader(
		KV{Name: "Accept", Value: "*/*"},
		KV{Name: "Cookie", Value: "a=1"},
		KV{Name: "Cookie", Value: "b=2"},
		KV{Name: "Host", Value: "example.com"},
	)

	h.Del("cookie")

	want := []KV{
		{Name: "Accept", Value: "*/*"},
		{Name: "Host", Value: "example.com"},
	}
	if got := h.All(); !reflect.DeepEqual(got, want) {
		t.Errorf("after Del: All() = %v, want %v", got, want)
	}
}

func TestHeaderValuesReturnsEveryMatchInOrder(t *testing.T) {
	h := NewHeader(
		KV{Name: "Set-Cookie", Value: "a=1"},
		KV{Name: "X-Other", Value: "x"},
		KV{Name: "Set-Cookie", Value: "b=2"},
	)

	if got, want := h.Values("Set-Cookie"), []string{"a=1", "b=2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Values() = %v, want %v", got, want)
	}
	if got := h.Values("set-cookie"); len(got) != 2 {
		t.Errorf("Values() with different casing = %v, want two entries", got)
	}
}

func TestHeaderCloneIsIndependent(t *testing.T) {
	h := NewHeader(KV{Name: "Host", Value: "example.com"})
	clone := h.Clone()
	clone.Set("Host", "evil.example")

	if got := h.Get("Host"); got != "example.com" {
		t.Errorf("original mutated through clone: Host = %q", got)
	}
}

func TestHeaderRoundTripsThroughStd(t *testing.T) {
	h := NewHeader(
		KV{Name: "Host", Value: "example.com"},
		KV{Name: "Content-Type", Value: "text/html"},
		KV{Name: "Accept", Value: "*/*"},
	)

	back := HeaderFromStd(h.ToStd())

	if got, want := back.Get("Host"), "example.com"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
	if got, want := back.Get("Content-Type"), "text/html"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	// Host must lead so captures stay readable.
	if first := back.All()[0].Name; first != "Host" {
		t.Errorf("first field = %q, want Host", first)
	}
}

func TestHeaderFromStdOrdersWellKnownFieldsFirst(t *testing.T) {
	h := HeaderFromStd(stdHeader(
		"Accept", "*/*",
		"Cookie", "a=1",
		"Content-Type", "text/html",
		"Host", "example.com",
	))

	got := make([]string, 0, h.Len())
	for _, field := range h.All() {
		got = append(got, field.Name)
	}
	want := []string{"Host", "Content-Type", "Accept", "Cookie"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("field order = %v, want %v", got, want)
	}
}
