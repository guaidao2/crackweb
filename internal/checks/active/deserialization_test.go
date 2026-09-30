package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
