package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

const typeBypassPage = `<html><body><h1>User profile</h1><p>Name: bob</p><p>Email: bob@example.com</p></body></html>`

// arrayForm picks up whichever array spelling the request used.
func arrayForm(r *http.Request) string {
	query := r.URL.Query()
	if value := query.Get("id[]"); value != "" {
		return value
	}
	return query.Get("id[0]")
}

// TestTypeBypassFiresWhenAnArraySpellingSkipsTheCheck is the case the check exists for: a
// value refused on its own, accepted once the framework hands the validator something
// else.
func TestTypeBypassFiresWhenAnArraySpellingSkipsTheCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if arrayForm(r) != "" {
			// The validator was written for a string, so it never runs on this shape.
			fmt.Fprint(w, typeBypassPage)
			return
		}
		if r.URL.Query().Get("id") == typeBypassProbe {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "<html><body>invalid id</body></html>")
			return
		}
		fmt.Fprint(w, typeBypassPage)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, parameterTypeBypass{}, server.URL+"/user?id=42")
	if len(findings) == 0 {
		t.Fatal("a validation that an array spelling stepped around was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-1287" {
		t.Errorf("CWE = %q, want CWE-1287", f.CWE)
	}
	if !strings.Contains(f.Payload, "[]") {
		t.Errorf("the payload does not name the array spelling: %q", f.Payload)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "refused") {
		t.Errorf("the refusal has to be in the evidence: %v", f.Evidence.Matches)
	}
}

// TestTypeBypassIgnoresUnvalidatedParameters: a parameter that accepts anything has no
// validation to step around.
func TestTypeBypassIgnoresUnvalidatedParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, typeBypassPage)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, parameterTypeBypass{}, server.URL+"/user?id=42"); len(findings) != 0 {
		t.Errorf("a parameter with no validation was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestTypeBypassIgnoresAConsistentRefusal: a validator that also covers the array spelling
// is doing its job.
func TestTypeBypassIgnoresAConsistentRefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("id")
		if arrayForm(r) != "" {
			value = typeBypassProbe
		}
		if value == typeBypassProbe {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "<html><body>invalid id</body></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, typeBypassPage)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, parameterTypeBypass{}, server.URL+"/user?id=42"); len(findings) != 0 {
		t.Errorf("a refusal that covered both spellings was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestTypeBypassIgnoresAnErrorPageThatWasAccepted: a 200 that is not the ordinary page is
// not the application having served the request; it is a differently-worded rejection.
func TestTypeBypassIgnoresAnErrorPageThatWasAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if arrayForm(r) != "" {
			fmt.Fprint(w, "<html><body>A parameter arrived in an unsupported form, so this "+
				"request could not be processed at all. Please submit a single value.</body></html>")
			return
		}
		if r.URL.Query().Get("id") == typeBypassProbe {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "<html><body>invalid id</body></html>")
			return
		}
		fmt.Fprint(w, typeBypassPage)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, parameterTypeBypass{}, server.URL+"/user?id=42"); len(findings) != 0 {
		t.Errorf("a differently-worded rejection was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestTypeBypassSkipsValuesInsideEncodedDocuments: those are addressed by a different
// mechanism, and rebuilding the envelope to ask this question is a separate piece of work.
func TestTypeBypassSkipsValuesInsideEncodedDocuments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<html><body>invalid</body></html>")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/user?id=42")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := newHarness(t).client.Do(t.Context(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	h := newHarness(t)
	wrapped := httpmsg.Param{
		Name: "id.uid", Value: "1", In: httpmsg.LocQuery,
		RawName: "uid", Path: []string{"uid"},
		Wrapper: httpmsg.WrapJSON, Outer: "id",
	}
	target := &checks.Target{Request: request, Response: baseline, Param: &wrapped}
	if findings := runRequestLevel(t, h, parameterTypeBypass{}, target); len(findings) != 0 {
		t.Errorf("a value inside an encoded document was tested: %v", findings[0].Evidence.Matches)
	}
}
