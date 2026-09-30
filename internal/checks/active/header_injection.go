package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// sqlErrorHeaderInjection looks for the error-based injection that does not go through a
// parameter at all.
//
// An application that records a visitor — the address in `X-Forwarded-For`, the agent string,
// the referring page — has a query built from a header, and a header is a value the caller
// writes freely. None of the parameter checks can reach it: there is no parameter. The
// payloads are the plain ones, because the point is to break the syntax and read the database's
// own complaint, and a complaint that was not in the baseline is evidence.
//
// The first request carries the payload in every candidate header at once, so the common case —
// a target that builds no query from a header — costs one request rather than one per header.
// When that request does produce a new error, the headers are tried one at a time to say which
// one it was, because "some header" is not a finding a reader can act on.
var sqliHeaderNames = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Client-IP",
	"User-Agent",
	"Referer",
}

// sqliHeaderPayloads break a quoted string and leave the rest of the statement intact, which is
// what produces the database's own error rather than a refusal.
var sqliHeaderPayloads = []string{"'", "')-- -", "' AND 1=CONVERT(int, @@version)-- -"}

func sqlErrorHeaderInjection(ctx context.Context, c *checks.Context, t *checks.Target,
	baselineLower string) *finding.Finding {
	for _, payloadText := range sqliHeaderPayloads {
		request := withHeaderPayload(t.Request, sqliHeaderNames, payloadText)
		response, err := c.Do(ctx, request)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		matched := firstNewSignature(strings.ToLower(string(response.Body)), baselineLower, sqlErrorSignatures)
		if matched == "" {
			continue
		}

		// Which header it was, asked one at a time. Only reached once the answer is already
		// known to change, so the cost is paid for a finding rather than for every target.
		culprit, located := "", withHeaderPayload(t.Request, sqliHeaderNames[:1], payloadText)
		var locatedResponse *httpmsg.Response
		for _, name := range sqliHeaderNames {
			one := withHeaderPayload(t.Request, []string{name}, payloadText)
			resp, err := c.Do(ctx, one)
			if err != nil || resp == nil {
				continue
			}
			if firstNewSignature(strings.ToLower(string(resp.Body)), baselineLower, sqlErrorSignatures) != "" {
				culprit, located, locatedResponse = name, one, resp
				break
			}
		}
		if culprit == "" {
			// The error followed the combined request but not any single header: the target
			// reacted to the set rather than to one of them, which is not an injection to name.
			continue
		}
		if locatedResponse != nil {
			response = locatedResponse
		}

		f := checks.NewFinding(sqliError{}, t,
			i18n.KeyCheckSQLiErrorTitle, i18n.KeyCheckSQLiErrorDesc, i18n.KeyCheckSQLiErrorFix)
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceCertain
		f.Method = request.Method
		f.Payload = culprit + ": " + payloadText
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = located.Raw()
		f.Evidence.Response = truncate(response.Body, 4096)
		f.Evidence.Baseline = truncate(t.Response.Body, 2048)
		f.Evidence.Matches = []string{
			"the database reported an error that was not in the baseline: " + matched,
			"the request that produced it carried the payload in the " + culprit + " header, and " +
				"nothing else changed",
			"the query is built from a header, which the caller writes freely and no parameter " +
				"of this endpoint reaches",
		}
		f.Evidence.Diff = extractAround(string(response.Body), matched, 240)
		return f
	}
	return nil
}

// withHeaderPayload returns a copy of the request with the payload value in each of the named
// headers. The rest of the request — method, body, parameters — is left exactly as it was, so
// the difference the response shows is the header and nothing else.
func withHeaderPayload(request *httpmsg.Request, names []string, value string) *httpmsg.Request {
	out := request.Clone()
	for _, name := range names {
		out.Header.Set(name, value)
	}
	return out
}

// sqliPathPayloads break a quoted string as it would sit in a path segment.
var sqliPathPayloads = []string{"'", "')-- -", "' AND 1=CONVERT(int, @@version)-- -"}

// sqlErrorPathInjection tries the payload as a path segment, which is the third place a value
// can enter a query and the one no parameter reaches.
//
// A route that reads `/user/<name>` has a value the caller writes just as freely as a query
// parameter, and frameworks make it the ordinary way to address a resource. The segment is
// tried both ways round — in place of the last one and appended after it — because a route may
// take the value as the last segment or leave room for one after it.
//
// A segment that simply does not exist is not evidence of anything: the page for a missing
// resource is served with the same status and contains no error, which is why this is worth
// doing with the error-based judgement rather than by comparing bodies. Reached only when no
// parameter and no header produced a complaint, so a target that answers through either pays
// nothing for it.
func sqlErrorPathInjection(ctx context.Context, c *checks.Context, t *checks.Target,
	baselineLower string) *finding.Finding {
	for _, payloadText := range sqliPathPayloads {
		for _, inPlace := range []bool{true, false} {
			request, ok := withPathPayload(t.Request, payloadText, inPlace)
			if !ok {
				continue
			}
			response, err := c.Do(ctx, request)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			matched := firstNewSignature(strings.ToLower(string(response.Body)), baselineLower, sqlErrorSignatures)
			if matched == "" {
				continue
			}

			where := "appended to the path"
			if inPlace {
				where = "in place of the last path segment"
			}
			f := checks.NewFinding(sqliError{}, t,
				i18n.KeyCheckSQLiErrorTitle, i18n.KeyCheckSQLiErrorDesc, i18n.KeyCheckSQLiErrorFix)
			f.Severity = finding.SeverityCritical
			f.Confidence = finding.ConfidenceCertain
			f.Method = request.Method
			f.Payload = payloadText + " (" + where + ")"
			f.CWE = "CWE-89"
			f.References = sqlReferences
			f.Evidence.Request = request.Raw()
			f.Evidence.Response = truncate(response.Body, 4096)
			f.Evidence.Baseline = truncate(t.Response.Body, 2048)
			f.Evidence.Matches = []string{
				"the database reported an error that was not in the baseline: " + matched,
				"the request that produced it carried the payload as part of the path, with no " +
					"parameter changed",
				"the route reads the value from the path, where the caller writes it just as " +
					"freely as a query parameter",
			}
			f.Evidence.Diff = extractAround(string(response.Body), matched, 240)
			return f
		}
	}
	return nil
}

// withPathPayload returns a copy of the request with the payload added to its path: in place of
// the last segment when inPlace is set, and appended after it otherwise. RawPath is cleared
// because the Go URL keeps the escaped form alongside the decoded one, and a stale one would be
// sent instead of what is built here.
func withPathPayload(request *httpmsg.Request, payloadText string, inPlace bool) (*httpmsg.Request, bool) {
	if request.URL == nil || request.URL.Path == "" || request.URL.Path == "/" {
		return nil, false
	}
	out := request.Clone()
	address := *request.URL
	segments := strings.Split(strings.TrimSuffix(address.Path, "/"), "/")
	// The payload goes in as it stands: the URL escapes Path when the request is written, and
	// escaping it here as well would put the escapes themselves on the wire.
	if inPlace && len(segments) > 1 {
		segments[len(segments)-1] = payloadText
	} else {
		segments = append(segments, payloadText)
	}
	address.Path = strings.Join(segments, "/")
	address.RawPath = ""
	out.URL = &address
	return out, true
}
