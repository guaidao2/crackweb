package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// paramNamed builds a query parameter for the name-matching tests.
func paramNamed(name, value string) httpmsg.Param {
	return httpmsg.Param{Name: name, Value: value, In: httpmsg.LocQuery}
}

// records writes count records, each large enough that the total is well clear of the
// check's noise floor.
func records(w http.ResponseWriter, count int) {
	for i := 0; i < count; i++ {
		fmt.Fprintf(w, "<p>record %d: %s</p>\n", i, strings.Repeat("x", 80))
	}
}

// TestPaginationBypassFiresWhenTheLimitIsNotEnforced is the case the check exists for: one
// record asked for, a whole collection returned.
func TestPaginationBypassFiresWhenTheLimitIsNotEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Query().Get("limit") {
		case "1":
			records(w, 1)
		case "-1", "0", "999999999":
			records(w, 40)
		default:
			records(w, 1)
		}
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, paginationBypass{}, server.URL+"/items?limit=10")
	if len(findings) == 0 {
		t.Fatal("a page size that did not bound the response was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-770" {
		t.Errorf("CWE = %q, want CWE-770", f.CWE)
	}
	if string(f.Severity) != "medium" {
		t.Errorf("severity = %q, want medium", f.Severity)
	}
	if len(f.Evidence.Baseline) == 0 {
		t.Error("the bounded response has to be in the evidence, or the growth cannot be checked")
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "bytes") {
		t.Errorf("the sizes are missing from the evidence: %v", f.Evidence.Matches)
	}
}

// TestPaginationBypassIgnoresAnEnforcedLimit: a target that honours the parameter is doing
// its job, whatever the value.
func TestPaginationBypassIgnoresAnEnforcedLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil || limit < 0 {
			limit = 0
		}
		if limit > 2 {
			limit = 2
		}
		records(w, limit)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, paginationBypass{}, server.URL+"/items?limit=10"); len(findings) != 0 {
		t.Errorf("an enforced limit was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestPaginationBypassIgnoresOutOfRangeRejections: refusing the value is the correct
// response, and there is nothing to compare against.
func TestPaginationBypassIgnoresOutOfRangeRejections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value := r.URL.Query().Get("limit"); value == "-1" || value == "0" || value == "999999999" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "<html><body>limit must be between 1 and 100</body></html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		records(w, 1)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, paginationBypass{}, server.URL+"/items?limit=10"); len(findings) != 0 {
		t.Errorf("a rejected value was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestPaginationBypassIgnoresOtherParameters: a numeric parameter that is not a page size
// is a different question, and asking it would cost traffic for nothing.
func TestPaginationBypassIgnoresOtherParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		records(w, 40)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, paginationBypass{}, server.URL+"/search?q=10"); len(findings) != 0 {
		t.Errorf("a parameter that is not a page size was tested: %v", findings[0].Evidence.Matches)
	}
}

// TestPageSizeParameterNamesAreMatchedExactly: `limit` counts, `unlimited` does not.
func TestPageSizeParameterNamesAreMatchedExactly(t *testing.T) {
	cases := map[string]bool{
		"limit": true, "LIMIT": true, "per_page": true, "page_size": true,
		"size": true, "offset_extra": false, "unlimited": false, "limitless": false,
		"q": false, "id": false,
	}
	for name, want := range cases {
		param := paramNamed(name, "10")
		if got := isPageSizeParam(param); got != want {
			t.Errorf("isPageSizeParam(%q) = %v, want %v", name, got, want)
		}
	}
}
