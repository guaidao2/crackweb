package httpmsg

import (
	"reflect"
	"testing"
)

func TestQueryParamsPreserveOrderAndDecode(t *testing.T) {
	req, err := ParseRequest([]byte(
		"GET /search?q=hello+world&page=2&flag HTTP/1.1\r\nHost: example.com\r\n\r\n"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	params := req.QueryParams()
	want := []Param{
		{Name: "q", Value: "hello world", In: LocQuery, RawName: "q", RawValue: "hello+world"},
		{Name: "page", Value: "2", In: LocQuery, RawName: "page", RawValue: "2"},
		{Name: "flag", Value: "", In: LocQuery, RawName: "flag", RawValue: ""},
	}
	if !reflect.DeepEqual(params, want) {
		t.Errorf("QueryParams()\n got: %+v\nwant: %+v", params, want)
	}
}

func TestQueryParamsKeepPercentEncodingSeparateFromDecodedValue(t *testing.T) {
	req, err := ParseRequest([]byte(
		"GET /?redirect=http%3A%2F%2Fevil.example%2F%3Fa%3D1 HTTP/1.1\r\nHost: example.com\r\n\r\n"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	param := req.QueryParams()[0]
	if got, want := param.Value, "http://evil.example/?a=1"; got != want {
		t.Errorf("decoded value = %q, want %q", got, want)
	}
	if got, want := param.RawValue, "http%3A%2F%2Fevil.example%2F%3Fa%3D1"; got != want {
		t.Errorf("raw value = %q, want %q", got, want)
	}
}

func TestDuplicateParamsGetOccurrenceCounters(t *testing.T) {
	req, err := ParseRequest([]byte(
		"GET /?id=1&id=2&id=3 HTTP/1.1\r\nHost: example.com\r\n\r\n"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	params := req.QueryParams()
	if len(params) != 3 {
		t.Fatalf("got %d parameters, want 3", len(params))
	}
	for i, param := range params {
		if param.Occurrence != i {
			t.Errorf("param %d Occurrence = %d, want %d", i, param.Occurrence, i)
		}
	}
	if params[0].Key() != "query:id#0" || params[1].Key() != "query:id#1" {
		t.Errorf("unexpected keys: %q, %q", params[0].Key(), params[1].Key())
	}
}

func TestBodyParamsOnlyForFormEncoding(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{
			name: "urlencoded form",
			raw: "POST /login HTTP/1.1\r\nHost: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
				"user=admin&pass=s3cret",
			want: 2,
		},
		{
			name: "content type with charset",
			raw: "POST /login HTTP/1.1\r\nHost: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n\r\n" +
				"user=admin",
			want: 1,
		},
		{
			name: "json body yields json fields, not form parameters",
			raw: "POST /api HTTP/1.1\r\nHost: example.com\r\n" +
				"Content-Type: application/json\r\n\r\n" +
				`{"user":"admin","pass":"s3cret"}`,
			want: 2,
		},
		{
			name: "missing content type is not guessed at",
			raw:  "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin",
			want: 0,
		},
		{
			name: "method with no body",
			raw: "POST /login HTTP/1.1\r\nHost: example.com\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n\r\n",
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := ParseRequest([]byte(tc.raw), ParseOptions{})
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if got := len(req.BodyParams()); got != tc.want {
				t.Errorf("BodyParams() returned %d parameters, want %d", got, tc.want)
			}
		})
	}
}

func TestCookieParams(t *testing.T) {
	req, err := ParseRequest([]byte(
		"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123; theme=dark; empty=\r\n\r\n"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	params := req.CookieParams()
	want := []Param{
		{Name: "session", Value: "abc123", In: LocCookie, RawName: "session", RawValue: "abc123"},
		{Name: "theme", Value: "dark", In: LocCookie, RawName: "theme", RawValue: "dark"},
		{Name: "empty", Value: "", In: LocCookie, RawName: "empty", RawValue: ""},
	}
	if !reflect.DeepEqual(params, want) {
		t.Errorf("CookieParams()\n got: %+v\nwant: %+v", params, want)
	}
}

func TestNoCookieHeaderYieldsNoParams(t *testing.T) {
	req := &Request{Method: "GET", Header: NewHeader(KV{Name: "Host", Value: "example.com"})}
	if got := req.CookieParams(); got != nil {
		t.Errorf("CookieParams() = %v, want nil", got)
	}
}

func TestParamsCombinesEveryLocationInOrder(t *testing.T) {
	req, err := ParseRequest([]byte(
		"POST /submit?stage=1 HTTP/1.1\r\n"+
			"Host: example.com\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Cookie: sid=xyz\r\n\r\n"+
			"field=value"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	params := req.Params()
	if len(params) != 3 {
		t.Fatalf("got %d parameters, want 3: %+v", len(params), params)
	}
	wantOrder := []ParamLocation{LocQuery, LocBody, LocCookie}
	for i, loc := range wantOrder {
		if params[i].In != loc {
			t.Errorf("param %d is in %q, want %q", i, params[i].In, loc)
		}
	}
}

func TestMalformedEncodingFallsBackToRawText(t *testing.T) {
	req, err := ParseRequest([]byte(
		"GET /?bad=%zz HTTP/1.1\r\nHost: example.com\r\n\r\n"), ParseOptions{})
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}

	param := req.QueryParams()[0]
	if got, want := param.Value, "%zz"; got != want {
		t.Errorf("Value = %q, want %q", got, want)
	}
}

func TestParamIsEmpty(t *testing.T) {
	if !(Param{Name: "flag"}).IsEmpty() {
		t.Error("IsEmpty() = false for a value-less parameter")
	}
	if (Param{Name: "id", Value: "1"}).IsEmpty() {
		t.Error("IsEmpty() = true for a parameter with a value")
	}
}
