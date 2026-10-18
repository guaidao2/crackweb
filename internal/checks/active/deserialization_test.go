package active

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// deserializingSite behaves like a page that unserializes what it is given and prints the
// result — the debug endpoint this class of probe is for. The incomplete-class name comes out
// only for an object whose class does not exist, which is what makes it evidence rather than
// a coincidence.
func deserializingSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := r.URL.Query().Get("data")
		if data == "" {
			data = r.FormValue("data")
		}
		switch {
		case strings.Contains(data, "NoSuchCls"):
			fmt.Fprint(w, `<pre>__PHP_Incomplete_Class::__set_state(array(
   '__PHP_Incomplete_Class_Name' =&gt; 'NoSuchCls',
))</pre>`)
		case strings.Contains(data, "stdClass"):
			fmt.Fprint(w, "<pre>(object) array('test' =&gt; 'test')</pre>")
		default:
			fmt.Fprint(w, "<pre>NULL</pre>")
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestDeserializationFiresOnAnUnknownClass: the deserialiser built an object of a class that
// does not exist, and said so.
func TestDeserializationFiresOnAnUnknownClass(t *testing.T) {
	server := deserializingSite(t)
	h := newHarness(t)
	findings := withParameter(t, h, deserialization{}, server.URL+"/parse?data=hello")
	if len(findings) == 0 {
		t.Fatal("a page that unserialized an unknown class was not reported")
	}
	if findings[0].CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "NoSuchCls") {
		t.Errorf("payload = %q, want the unknown-class probe", findings[0].Payload)
	}
}

// TestDeserializationStaysQuietWhenNothingIsDeserialized: a page that reads the value as a
// string does not produce the incomplete-class name, and is not reported.
func TestDeserializationStaysQuietWhenNothingIsDeserialized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body><p>nothing to see</p></body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, deserialization{}, server.URL+"/parse?data=hello"); len(findings) != 0 {
		t.Errorf("a page that deserializes nothing was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestDeserializationFiresOnAnUnknownPickleModule: a page that unpickles and reports the
// failure names the module the probe asked for — evidence that the value reached
// `pickle.loads`, in a form that does not depend on the page showing a whole traceback.
func TestDeserializationFiresOnAnUnknownPickleModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := r.URL.Query().Get("data")
		// The probe's payload carries the module name, base64-encoded; anything that is
		// not that payload gets an ordinary page, so only this seed can be reported.
		if strings.Contains(data, "Y2NyYWNrd2VicGlja2xl") {
			fmt.Fprint(w, "<p>ModuleNotFoundError: No module named 'crackwebpickle'</p>")
			return
		}
		fmt.Fprint(w, "<html><body><p>ok</p></body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, deserialization{}, server.URL+"/parse?data=hello")
	if len(findings) == 0 {
		t.Fatal("a page that named the probe's module was not reported")
	}
	if !strings.Contains(findings[0].Payload, "Y2NyYWNrd2VicGlja2xl") {
		t.Errorf("payload = %q, want the pickle probe", findings[0].Payload)
	}
}

// The auto-type probes below are asked of a JSON document, because that is the only place an
// @type member can be a member: a query value is a string, and to fastjson and Jackson a
// string that contains an object is still a string.

// autoTypeJSONTarget builds a POST target whose body is a JSON document and selects its first
// field, which is the shape the scanner hands a check for a JSON API.
func autoTypeJSONTarget(t *testing.T, h *harness, server *httptest.Server, body string) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("POST", server.URL+"/api")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Body = []byte(body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Length", strconv.Itoa(len(body)))
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	if len(params) == 0 {
		t.Fatal("the JSON body has no parameters")
	}
	return &checks.Target{Request: request, Response: baseline, Param: &params[0]}
}

// TestDeserializationAutoTypeFiresOnAParserError: the parser answered the @type member the
// request carried with its own complaint, which it can only do if the object arrived as an
// object and it read the type id out of it.
func TestDeserializationAutoTypeFiresOnAParserError(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), `{"@type"`) {
			fmt.Fprint(w, `{"error":"Could not resolve type id '`+deserializationAutoTypeMiss+
				`' as a subtype of java.lang.Object"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	findings := runRequestLevel(t, h, deserialization{}, target)
	if len(findings) == 0 {
		t.Fatalf("a parser that answered the @type member was not reported")
	}
	// The probe has to have gone out for this to be about the parser: a request that never
	// carried the object would make the finding say something the scan did not do.
	mu.Lock()
	sent := false
	for _, recorded := range bodies {
		if strings.Contains(recorded, `{"@type"`) {
			sent = true
			break
		}
	}
	mu.Unlock()
	if !sent {
		t.Fatal("the @type object was never sent")
	}
	if findings[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
	if findings[0].CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", findings[0].CWE)
	}
	if !strings.Contains(findings[0].Payload, "@type") {
		t.Errorf("payload = %q, want the auto-type object", findings[0].Payload)
	}
	// The probe replaces the value of the field it addresses and leaves the rest of the
	// document as it was: a request rebuilt from scratch would reach a handler that reads the
	// other fields as empty.
	request := string(findings[0].Evidence.Request)
	if !strings.Contains(request, `"name":{"@type"`) {
		t.Errorf("the field was not replaced by the object:\n%s", request)
	}
	if !strings.Contains(request, `"count":1`) {
		t.Errorf("the document lost a field it already carried:\n%s", request)
	}
	if !strings.Contains(request, findings[0].Payload) {
		t.Errorf("the evidence request does not carry the payload it names:\n%s", request)
	}
}

// autoTypeOOB answers a callback only for a token that arrived inside an @type object.
//
// That is what tells this probe apart from the check's older JSON payloads, which carry the
// whole document as a string: a callback for one of those would prove nothing about an
// object the parser reads a type id from.
type autoTypeOOB struct {
	mu      sync.Mutex
	issued  []string
	objects map[string]bool
}

func newAutoTypeOOB() *autoTypeOOB {
	return &autoTypeOOB{objects: map[string]bool{}}
}

func (s *autoTypeOOB) NewURL(string) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := fmt.Sprintf("tok%d", len(s.issued)+1)
	s.issued = append(s.issued, token)
	return "http://" + token + ".crackweb-oob.example/", token
}

func (s *autoTypeOOB) Poll(token string) []checks.Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.objects[token] {
		return nil
	}
	return []checks.Interaction{{
		Protocol:   "dns",
		RemoteAddr: "192.0.2.9:53000",
		Detail:     token + ".crackweb-oob.example",
	}}
}

// note records the tokens that arrived as the value of a JSON field, rather than inside a
// string that was sent as its value.
func (s *autoTypeOOB) note(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, token := range s.issued {
		if !strings.Contains(body, token+".") {
			continue
		}
		// The object form puts the name in a JSON string the parser reads as a value; the
		// string form puts it behind an escaped quote.
		if strings.Contains(body, `"val":"`+token+`.`) || strings.Contains(body, `","`+token+`.`) {
			s.objects[token] = true
		}
	}
}

// TestDeserializationAutoTypeFiresOnACallback: the parser built an address from the name the
// request carried and resolved it, which came back to the scan on another connection.
func TestDeserializationAutoTypeFiresOnACallback(t *testing.T) {
	oob := newAutoTypeOOB()
	var (
		mu     sync.Mutex
		bodies []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		oob.note(string(body))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.OOB = oob
	h.ctx.OOBWait = 50 * time.Millisecond
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	findings := runRequestLevel(t, h, deserialization{}, target)
	if len(findings) == 0 {
		t.Fatal("a parser that resolved the name in the @type member was not reported")
	}
	if !strings.Contains(findings[0].Payload, "Inet4Address") {
		t.Errorf("payload = %q, want the payload that made the parser resolve a name", findings[0].Payload)
	}
	// The object has to have arrived as an object: the value-form seeds send the same text
	// inside a string, and this asserts the form that was actually judged.
	request := string(findings[0].Evidence.Request)
	if !strings.Contains(request, `:{"@type":"java.net.Inet4Address"`) {
		t.Errorf("the auto-type object was not sent as an object:\n%s", request)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "crackweb-oob.example") {
		t.Errorf("the evidence does not name the callback: %v", findings[0].Evidence.Matches)
	}
}

// TestDeserializationAutoTypeStaysQuietOnATargetThatIgnoresIt: the document parsed and the
// @type member meant nothing to the application, which is not a finding.
func TestDeserializationAutoTypeStaysQuietOnATargetThatIgnoresIt(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	findings := runRequestLevel(t, h, deserialization{}, target)
	if len(findings) != 0 {
		t.Fatalf("a target that ignored the @type member was reported: %v", findings[0].Evidence.Matches)
	}

	// "No findings" is a claim about the tool as much as about the target: the probe has to
	// have been sent for the silence to mean anything.
	mu.Lock()
	defer mu.Unlock()
	sent := false
	for _, body := range bodies {
		if strings.Contains(body, `{"@type"`) {
			sent = true
			break
		}
	}
	if !sent {
		t.Errorf("the @type probe was never sent; the check made %d request(s)", len(bodies))
	}
}

// TestDeserializationAutoTypeStaysQuietOnAnEcho is the control the signature rule rests on: a
// page that repeats what it received carries the object and the type id, and none of that is
// the parser having read them.
func TestDeserializationAutoTypeStaysQuietOnAnEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"received":%s}`, body)
	}))
	defer server.Close()

	h := newHarness(t)
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	if findings := runRequestLevel(t, h, deserialization{}, target); len(findings) != 0 {
		t.Errorf("a page that echoed the request was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestDeserializationAutoTypeIgnoresATypeMismatch is the false positive this probe is built to
// avoid: a handler whose field is a string rejects an object with a full Jackson stack trace.
// That is the application's own data binding objecting to a shape it did not expect — it is not
// a parser having read a type id, and reporting it would flag every JSON API there is.
func TestDeserializationAutoTypeIgnoresATypeMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), `{"@type"`) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"status":500,"error":"Internal Server Error","message":"JSON parse `+
				`error: Cannot deserialize value of type java.lang.String from Object value `+
				`(token JsonToken.START_OBJECT); nested exception is `+
				`com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot deserialize `+
				`value of type java.lang.String from Object value"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	if findings := runRequestLevel(t, h, deserialization{}, target); len(findings) != 0 {
		t.Errorf("a handler rejecting an object it did not expect was reported: %v",
			findings[0].Evidence.Matches)
	}
}

// TestDeserializationAutoTypeIgnoresAPhraseTheBaselineAlreadyCarries: the complaint has to be
// new. A console that prints the same text whatever it is sent is evidence of nothing.
func TestDeserializationAutoTypeIgnoresAPhraseTheBaselineAlreadyCarries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<pre>Could not resolve type id &#39;example&#39; as a subtype of "+
			"java.lang.Object: known type ids = []</pre>")
	}))
	defer server.Close()

	h := newHarness(t)
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	if findings := runRequestLevel(t, h, deserialization{}, target); len(findings) != 0 {
		t.Errorf("a phrase the baseline already carried was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestDeserializationAutoTypeSendsNoCallbackPayloadWithoutADomain keeps the bound the check's
// older callback payloads already have: an address is never resolved, so with no delegated
// domain there is nothing to wait for and the payloads that wait are not sent.
func TestDeserializationAutoTypeSendsNoCallbackPayloadWithoutADomain(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.OOB = &stubOOB{shape: "http://10.0.0.5:8080/", responds: true}
	h.ctx.OOBWait = 20 * time.Millisecond
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	if findings := runRequestLevel(t, h, deserialization{}, target); len(findings) != 0 {
		t.Errorf("a numeric callback was reported: %v", findings[0].Evidence.Matches)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, body := range bodies {
		if strings.Contains(body, "Inet4Address") || strings.Contains(body, "InetSocketAddress") {
			t.Errorf("a payload asking for a name to be resolved was sent with an address: %s", body)
		}
	}
}

// TestDeserializationAutoTypeRequiresARealCallback: the payloads alone are not evidence. With
// a delegated domain that answers nothing, the probe has not proved anything.
func TestDeserializationAutoTypeRequiresARealCallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	h.ctx.OOB = &stubOOB{shape: "http://{token}.crackweb-oob.example/", responds: false}
	h.ctx.OOBWait = 20 * time.Millisecond
	target := autoTypeJSONTarget(t, h, server, `{"name":"hello","count":1}`)
	if findings := runRequestLevel(t, h, deserialization{}, target); len(findings) != 0 {
		t.Errorf("a payload that was never resolved was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestDeserializationAutoTypeLeavesAQueryParameterAlone: an @type object is only meaningful
// inside a JSON document, and a query value is not one. The generic seeds keep covering it.
func TestDeserializationAutoTypeLeavesAQueryParameterAlone(t *testing.T) {
	var (
		mu      sync.Mutex
		queries []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query().Get("data"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, deserialization{}, server.URL+"/api?data=c29tZXRoaW5n"); len(findings) != 0 {
		t.Errorf("an ordinary string parameter was reported: %v", findings[0].Evidence.Matches)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, query := range queries {
		if strings.Contains(query, "@type") {
			t.Errorf("a query value was sent an @type object: %s", query)
		}
	}
}

// TestDeserializationAutoTypeReachesAJSONValuedParameter: the value sits inside a document
// carried as a query parameter, so the envelope has to be rebuilt around the change.
func TestDeserializationAutoTypeReachesAJSONValuedParameter(t *testing.T) {
	var (
		mu     sync.Mutex
		values []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		mu.Lock()
		values = append(values, value)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(value, `{"@type"`) {
			fmt.Fprint(w, `{"error":"autoType is not support. `+deserializationAutoTypeMiss+`"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/api?id=%7B%22uid%22%3A1%7D")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	var wrapped *httpmsg.Param
	for index := range params {
		if params[index].Wrapper == httpmsg.WrapJSON {
			wrapped = &params[index]
			break
		}
	}
	if wrapped == nil {
		t.Fatalf("the JSON-valued parameter was not addressed: %+v", params)
	}

	findings := runRequestLevel(t, h, deserialization{},
		&checks.Target{Request: request, Response: baseline, Param: wrapped})
	if len(findings) == 0 {
		t.Fatalf("a parser that answered the field inside a JSON value was not reported; values sent: %v", values)
	}
	if !strings.Contains(findings[0].Payload, "@type") {
		t.Errorf("payload = %q, want the auto-type object", findings[0].Payload)
	}

	mu.Lock()
	defer mu.Unlock()
	rewritten := false
	for _, value := range values {
		if strings.Contains(value, `"uid":{"@type"`) {
			rewritten = true
			break
		}
	}
	if !rewritten {
		t.Errorf("the document was not rewritten around its field: %v", values)
	}
}

// TestDeserializationAutoTypeReachesABase64JSONBody: a body that arrives base64-encoded is
// edited as a document and re-encoded the way it came.
func TestDeserializationAutoTypeReachesABase64JSONBody(t *testing.T) {
	var (
		mu        sync.Mutex
		documents []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		document := ""
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil {
			document = string(decoded)
		}
		mu.Lock()
		documents = append(documents, document)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(document, `{"@type"`) {
			fmt.Fprint(w, `{"error":"Could not resolve type id '`+deserializationAutoTypeMiss+
				`' as a subtype of java.lang.Object"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	h := newHarness(t)
	body := base64.StdEncoding.EncodeToString([]byte(`{"name":"hello","count":1}`))
	target := autoTypeJSONTarget(t, h, server, body)
	if target.Param.In != httpmsg.LocJSONBase64 {
		t.Fatalf("the body was addressed as %q, want %q", target.Param.In, httpmsg.LocJSONBase64)
	}
	findings := runRequestLevel(t, h, deserialization{}, target)
	if len(findings) == 0 {
		t.Fatalf("a base64 body carrying an @type object was not reported; documents sent: %v", documents)
	}

	mu.Lock()
	defer mu.Unlock()
	rewritten := false
	for _, document := range documents {
		if strings.Contains(document, `"name":{"@type"`) {
			rewritten = true
			break
		}
	}
	if !rewritten {
		t.Errorf("the document inside the base64 body was not rewritten: %v", documents)
	}
}

// TestSpliceJSONValueReplacesOnlyTheAddressedField pins the rewrite the probe depends on: the
// value becomes the object, and every other byte of the document survives.
func TestSpliceJSONValueReplacesOnlyTheAddressedField(t *testing.T) {
	const object = `{"@type":"java.net.Inet4Address","val":"probe.example"}`
	cases := []struct {
		name       string
		document   string
		key        string
		occurrence int
		want       string
	}{
		{
			name:     "first field",
			document: `{"name":"hello","count":1}`,
			key:      "name",
			want:     `{"name":` + object + `,"count":1}`,
		},
		{
			name:     "a field in the middle",
			document: `{"name":"hello","count":1,"tail":true}`,
			key:      "count",
			want:     `{"name":"hello","count":` + object + `,"tail":true}`,
		},
		{
			name:       "the second member of that name",
			document:   `{"name":"hello","nested":{"name":"inner"}}`,
			key:        "name",
			occurrence: 1,
			want:       `{"name":"hello","nested":{"name":` + object + `}}`,
		},
		{
			name:     "a value that reads like the key",
			document: `{"name":"name"}`,
			key:      "name",
			want:     `{"name":` + object + `}`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := spliceJSONValue([]byte(testCase.document), testCase.key, testCase.occurrence, object)
			if !ok {
				t.Fatalf("spliceJSONValue(%s) failed", testCase.document)
			}
			if string(got) != testCase.want {
				t.Errorf("spliceJSONValue(%s) =\n%s\nwant\n%s", testCase.document, got, testCase.want)
			}
		})
	}
}

// TestSpliceJSONValueAddsAFieldTheDocumentDoesNotCarry: a key that is not in the document is
// added to the object, rather than the request being rewritten into one the application never
// receives.
func TestSpliceJSONValueAddsAFieldTheDocumentDoesNotCarry(t *testing.T) {
	const object = `{"@type":"java.net.Inet4Address"}`
	cases := []struct{ document, want string }{
		{`{"count":1}`, `{"count":1,"name":` + object + `}`},
		{`{}`, `{"name":` + object + `}`},
	}
	for _, testCase := range cases {
		got, ok := spliceJSONValue([]byte(testCase.document), "name", 0, object)
		if !ok {
			t.Fatalf("spliceJSONValue(%s) failed", testCase.document)
		}
		if string(got) != testCase.want {
			t.Errorf("spliceJSONValue(%s) = %s, want %s", testCase.document, got, testCase.want)
		}
	}
}

// TestAutoTypeCarrierCoversTheJSONLocations keeps the probe off the locations where an @type
// member cannot exist: a query, form, cookie or multipart value is a string.
func TestAutoTypeCarrierCoversTheJSONLocations(t *testing.T) {
	cases := []struct {
		param httpmsg.Param
		want  bool
	}{
		{httpmsg.Param{In: httpmsg.LocJSON}, true},
		{httpmsg.Param{In: httpmsg.LocJSONBase64}, true},
		{httpmsg.Param{In: httpmsg.LocQuery, Wrapper: httpmsg.WrapJSON, Outer: "id"}, true},
		{httpmsg.Param{In: httpmsg.LocBody, Wrapper: httpmsg.WrapBase64JSON, Outer: "id"}, true},
		{httpmsg.Param{In: httpmsg.LocQuery}, false},
		{httpmsg.Param{In: httpmsg.LocBody}, false},
		{httpmsg.Param{In: httpmsg.LocCookie}, false},
		{httpmsg.Param{In: httpmsg.LocMultipart}, false},
		// A base64 scalar that sits in a JSON body is still a field of that document, and
		// an @type object planted there is addressed by the field's name: the wrapper of
		// the value does not change what encloses it.
		{httpmsg.Param{In: httpmsg.LocJSON, Wrapper: httpmsg.WrapBase64}, true},
	}
	for _, testCase := range cases {
		param := testCase.param
		if got := autoTypeCarrier(&param); got != testCase.want {
			t.Errorf("autoTypeCarrier(%s/%v) = %v, want %v",
				param.In, param.Wrapper, got, testCase.want)
		}
	}
	if autoTypeCarrier(nil) {
		t.Error("a nil parameter was treated as a JSON carrier")
	}
}
