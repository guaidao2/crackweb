package crawl

import (
	"net/url"
	"testing"
)

// TestFormRequestsKeepAnExistingQueryString: a form action may already carry a query —
// a language switch, a route parameter — and appending another "?" folds the submitted
// fields into the last value instead of adding them to the query.
func TestFormRequestsKeepAnExistingQueryString(t *testing.T) {
	baseURL, err := url.Parse("http://example.test/search?lang=en")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	form := Form{
		Action: "/search?lang=en",
		Method: "GET",
		Fields: []Field{{Name: "q", Value: "x"}},
	}

	requests := FormRequests(form, baseURL)
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if got, want := requests[0].URLString(), "http://example.test/search?lang=en&q=x"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

// TestFormRequestsDoNotAddAnEmptyQuestionMark keeps a bodyless GET on the address the
// action named.
func TestFormRequestsDoNotAddAnEmptyQuestionMark(t *testing.T) {
	baseURL, err := url.Parse("http://example.test/search")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	requests := FormRequests(Form{Action: "/search", Method: "GET"}, baseURL)
	if len(requests) != 1 {
		t.Fatalf("got %d requests, want one", len(requests))
	}
	if got, want := requests[0].URLString(), "http://example.test/search"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}
