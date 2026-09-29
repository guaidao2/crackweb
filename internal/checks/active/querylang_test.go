package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// parserServer answers with the complaint a parser makes when the value it was handed no
// longer parses, and answers normally otherwise.
func parserServer(t *testing.T, trigger func(string) bool, complaint string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if trigger(r.URL.Query().Get("user")) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "<html><body>%s</body></html>", complaint)
			return
		}
		fmt.Fprint(w, "<html><body>signed in as alice</body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

func TestLDAPInjectionFiresOnTheDirectorysComplaint(t *testing.T) {
	server := parserServer(t, func(value string) bool {
		return strings.ContainsAny(value, "*)(")
	}, "javax.naming.directory.InvalidSearchFilterException: Bad search filter")

	findings := withParameter(t, newHarness(t), ldapInjection{}, server.URL+"/login?user=alice")
	if len(findings) == 0 {
		t.Fatal("a filter the directory refused was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-90" {
		t.Errorf("CWE = %q, want CWE-90", f.CWE)
	}
	if !strings.Contains(strings.Join(f.Evidence.Matches, " "), "javax.naming.directory") {
		t.Errorf("the parser's own words are missing from the evidence: %v", f.Evidence.Matches)
	}
}

func TestXPathInjectionFiresOnTheParsersComplaint(t *testing.T) {
	server := parserServer(t, func(value string) bool {
		return strings.ContainsAny(value, "'\"")
	}, "System.Xml.XPath.XPathException: Invalid XPath expression")

	findings := withParameter(t, newHarness(t), xpathInjection{}, server.URL+"/search?user=alice")
	if len(findings) == 0 {
		t.Fatal("an expression the parser refused was not reported")
	}
	if findings[0].CWE != "CWE-643" {
		t.Errorf("CWE = %q, want CWE-643", findings[0].CWE)
	}
}

func TestODataInjectionFiresOnTheLibrarysComplaint(t *testing.T) {
	server := parserServer(t, func(value string) bool {
		return strings.Contains(value, "eq")
	}, "Microsoft.OData.ODataException: The query specified in the URI is not valid.")

	findings := withParameter(t, newHarness(t), odataInjection{}, server.URL+"/api/items?user=alice")
	if len(findings) == 0 {
		t.Fatal("a query the library refused was not reported")
	}
	if findings[0].CWE != "CWE-943" {
		t.Errorf("CWE = %q, want CWE-943", findings[0].CWE)
	}
}

// TestSignatureChecksIgnoreAPageThatAlreadyContainsTheString: a page that documents the
// library, or serves a trace it already carried, is not a page whose parameter reached it.
func TestSignatureChecksIgnoreAPageThatAlreadyContainsTheString(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>Troubleshooting</h1>"+
			"<p>A Bad search filter means javax.naming.directory refused the query.</p></body></html>")
	}))
	defer server.Close()

	for name, check := range map[string]checks.Check{
		"ldap":  ldapInjection{},
		"xpath": xpathInjection{},
		"odata": odataInjection{},
	} {
		findings := withParameter(t, newHarness(t), check, server.URL+"/docs?user=alice")
		if len(findings) != 0 {
			t.Errorf("%s: a page that already said it was reported: %v", name, findings[0].Evidence.Matches)
		}
	}
}

func TestSignatureChecksIgnoreCleanResponses(t *testing.T) {
	server := parserServer(t, func(string) bool { return false }, "unused")

	for name, check := range map[string]checks.Check{
		"ldap":  ldapInjection{},
		"xpath": xpathInjection{},
		"odata": odataInjection{},
	} {
		if findings := withParameter(t, newHarness(t), check, server.URL+"/login?user=alice"); len(findings) != 0 {
			t.Errorf("%s: a clean response was reported: %v", name, findings[0].Evidence.Matches)
		}
	}
}

func TestGraphQLIntrospectionFiresOnASchemaAnswer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer server.Close()

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/graphql")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	findings := runRequestLevel(t, h, graphqlIntrospection{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint that answered a schema query was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-200" {
		t.Errorf("CWE = %q, want CWE-200", f.CWE)
	}
	if string(f.Severity) != "low" {
		t.Errorf("severity = %q, want low: a schema is a map, not a way in", f.Severity)
	}
}

func TestGraphQLIntrospectionIgnoresDisabledIntrospection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"errors":[{"message":"Introspection is disabled"}]}`)
	}))
	defer server.Close()

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/graphql")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := runRequestLevel(t, h, graphqlIntrospection{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a disabled endpoint was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestGraphQLIntrospectionOnlyAsksNamedEndpoints: sending a schema query to every page
// would be a lot of traffic spent on the ones that are not GraphQL.
func TestGraphQLIntrospectionOnlyAsksNamedEndpoints(t *testing.T) {
	asked := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
	}))
	defer server.Close()

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/articles/42")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	before := asked
	if findings := runRequestLevel(t, h, graphqlIntrospection{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a page that is not GraphQL was reported: %v", findings[0].Evidence.Matches)
	}
	if asked != before {
		t.Error("a schema query was sent to a page whose path does not name a GraphQL service")
	}
}
