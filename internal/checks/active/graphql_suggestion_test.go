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

// graphqlSite answers a schema query only when `introspect` is set, and answers
// an unknown field with a suggestion only when `suggest` is set — the two
// switches a deployment actually has.
func graphqlSite(t *testing.T, introspect, suggest bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		query := string(body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(query, "__schema"):
			if introspect {
				fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)
				return
			}
			fmt.Fprint(w, `{"errors":[{"message":"GraphQL introspection is not allowed"}]}`)
		case strings.Contains(query, "crackwebNonexistentField"):
			if suggest {
				fmt.Fprint(w, `{"errors":[{"message":"Cannot query field \"crackwebNonexistentField\" on type \"Query\". Did you mean \"products\"?"}]}`)
				return
			}
			fmt.Fprint(w, `{"errors":[{"message":"Syntax Error: Unexpected Name."}]}`)
		default:
			fmt.Fprint(w, `{"data":null}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestGraphQLFiresOnFieldSuggestions: introspection is off, and the endpoint
// still names a real field in its error message.
func TestGraphQLFiresOnFieldSuggestions(t *testing.T) {
	server := graphqlSite(t, false, true)
	request, _ := httpmsg.NewRequest("POST", server.URL+"/graphql")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	findings := runRequestLevel(t, h, graphqlIntrospection{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint that answers with a field suggestion was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "suggestion") {
		t.Errorf("evidence does not describe the suggestion: %v", findings[0].Evidence.Matches)
	}
}

// TestGraphQLStaysQuietWhenBothAreOff: nothing leaks the schema, so nothing is
// reported — the state a hardened deployment is in.
func TestGraphQLStaysQuietWhenBothAreOff(t *testing.T) {
	server := graphqlSite(t, false, false)
	request, _ := httpmsg.NewRequest("POST", server.URL+"/graphql")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if findings := runRequestLevel(t, h, graphqlIntrospection{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("an endpoint that leaks nothing was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestGraphQLIntrospectionStillFires keeps the original behaviour intact: an open
// schema query is reported without asking for a suggestion.
func TestGraphQLIntrospectionStillFires(t *testing.T) {
	server := graphqlSite(t, true, false)
	request, _ := httpmsg.NewRequest("POST", server.URL+"/graphql")
	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)
	findings := runRequestLevel(t, h, graphqlIntrospection{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint with introspection enabled was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "schema query") {
		t.Errorf("the introspection finding changed shape: %v", findings[0].Evidence.Matches)
	}
}
