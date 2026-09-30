package active

import (
	"context"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// graphqlIntrospection reports an endpoint that answers a schema query.
//
// A schema is not a vulnerability by itself. What it is, is every operation the service
// offers, with their argument types — including the ones no client calls, the ones added
// for an internal tool, and the ones whose names alone suggest what they do. An attacker
// who can read it does not have to guess, and a service that answers the query in
// production is handing that map to anyone who asks.
//
// The endpoint has to look like one before it is asked. Sending a schema query to every
// page would be a lot of traffic spent on the ones that are not GraphQL at all.
type graphqlIntrospection struct{}

func (graphqlIntrospection) ID() string                 { return "graphql-introspection" }
func (graphqlIntrospection) TitleKey() i18n.Key         { return i18n.KeyCheckGraphQLTitle }
func (graphqlIntrospection) DescriptionKey() i18n.Key   { return i18n.KeyCheckGraphQLDesc }
func (graphqlIntrospection) RemediationKey() i18n.Key   { return i18n.KeyCheckGraphQLFix }
func (graphqlIntrospection) Severity() finding.Severity { return finding.SeverityLow }
func (graphqlIntrospection) Tags() []string {
	return []string{"active", "disclosure", "graphql", "api"}
}
func (graphqlIntrospection) Passive() bool { return false }

// IsRequestLevel marks this as a check about the endpoint rather than about a parameter:
// the question is what the service answers, not what one field holds.
func (graphqlIntrospection) IsRequestLevel() bool { return true }

// introspectionQuery asks for the smallest part of the schema that only an endpoint with
// introspection enabled can answer. It is deliberately not the full query — the point is to
// learn whether the door is open, not to pull the schema through it.
const introspectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}`

func (graphqlIntrospection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Request.URL == nil {
		return nil
	}
	if !looksLikeGraphQL(t.Request) {
		return nil
	}

	probe := t.Request.Clone()
	probe.Method = "POST"
	probe.Body = []byte(introspectionQuery)
	probe.Header.Set("Content-Type", "application/json")
	probe.Header.Set("Content-Length", strconv.Itoa(len(probe.Body)))

	response, err := c.Do(ctx, probe)
	if err != nil || response == nil || response.Status >= 400 {
		return nil
	}
	body := strings.ToLower(scanText(response.Body))
	if !strings.Contains(body, "__schema") && !strings.Contains(body, "querytype") {
		// Introspection is off. The same information is often still reachable one
		// field name at a time, through the error path.
		return graphqlSuggestions(ctx, c, t)
	}

	f := checks.NewFinding(graphqlIntrospection{}, t,
		i18n.KeyCheckGraphQLTitle, i18n.KeyCheckGraphQLDesc, i18n.KeyCheckGraphQLFix)
	f.Severity = finding.SeverityLow
	f.Confidence = finding.ConfidenceCertain
	f.Method = "POST"
	f.URL = t.Request.URLString()
	f.Payload = introspectionQuery
	f.DedupHostOnly = true
	f.CWE = "CWE-200"
	f.References = []string{
		"https://graphql.org/learn/introspection/",
		"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
	}
	f.Evidence.Request = probe.Raw()
	f.Evidence.Response = truncate(response.Raw(), 8192)
	f.Evidence.Matches = []string{"the endpoint answered a schema query"}
	return []*finding.Finding{f}
}

// graphqlSuggestionQuery asks for a field that cannot exist.
const graphqlSuggestionQuery = `{"query":"query { crackwebNonexistentField }"}`

// graphqlSuggestionSignatures are the ways an implementation gives a field name
// away in its answer. They are lower case because the comparison lower-cases the
// body.
var graphqlSuggestionSignatures = []string{"did you mean", "suggestions"}

// graphqlSuggestions reports an endpoint that answers an unknown field with a
// suggestion.
//
// Introspection is the documented way to read a schema and the first thing a
// deployment turns off; the suggestion is the by-product of the query planner and
// usually stays on. It leaks the same information — the answer names fields the
// schema really has — so a filter written to block `__schema` does not cover it.
func graphqlSuggestions(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	probe := t.Request.Clone()
	probe.Method = "POST"
	probe.Body = []byte(graphqlSuggestionQuery)
	probe.Header.Set("Content-Type", "application/json")
	probe.Header.Set("Content-Length", strconv.Itoa(len(probe.Body)))

	response, err := c.Do(ctx, probe)
	if err != nil || response == nil {
		return nil
	}
	// A 4xx is the ordinary answer to an invalid query, so the status is not a
	// filter here: what matters is whether the message names a field.
	baseline := strings.ToLower(scanText(t.Response.Body))
	body := strings.ToLower(scanText(response.Body))
	for _, signature := range graphqlSuggestionSignatures {
		if !strings.Contains(body, signature) || strings.Contains(baseline, signature) {
			continue
		}
		f := checks.NewFinding(graphqlIntrospection{}, t,
			i18n.KeyCheckGraphQLTitle, i18n.KeyCheckGraphQLDesc, i18n.KeyCheckGraphQLFix)
		f.Severity = finding.SeverityLow
		f.Confidence = finding.ConfidenceFirm
		f.Method = "POST"
		f.URL = t.Request.URLString()
		f.Payload = graphqlSuggestionQuery
		f.DedupHostOnly = true
		f.CWE = "CWE-200"
		f.References = []string{
			"https://graphql.org/learn/introspection/",
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
		}
		f.Evidence.Request = probe.Raw()
		f.Evidence.Response = truncate(response.Raw(), 8192)
		f.Evidence.Baseline = truncate(t.Response.Raw(), 4096)
		f.Evidence.Matches = []string{
			"an unknown field was answered with a suggestion (" + signature +
				"), and a suggestion names a field the schema has",
			"introspection is disabled, so the schema is enumerable one suggestion at a time",
		}
		return []*finding.Finding{f}
	}
	return nil
}

// looksLikeGraphQL reports whether an endpoint is worth asking. The name is the signal: a
// GraphQL service is almost always served from a path that says so, and a check that
// instead guessed from response shapes would send schema queries to ordinary JSON APIs.
func looksLikeGraphQL(req *httpmsg.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	path := strings.ToLower(req.URL.Path)
	if strings.Contains(path, "graphql") || strings.Contains(path, "/gql") {
		return true
	}
	return strings.HasSuffix(path, "/query") && strings.Contains(path, "api")
}
