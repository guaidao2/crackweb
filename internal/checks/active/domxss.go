package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// domXSS reports a value the page's own script turns into markup.
//
// The flaw and the test are both about a browser. A page that writes a URL value into the
// document returns exactly the same response whether it escapes the value first or not, so
// no amount of reading responses finds this. What finds it is loading the page and asking
// whether the element the planted markup creates is there: if it is, the page handed the
// value to something that parses markup, and an attacker who controls that value controls
// the document.
//
// It is request-level because the carrier is the request's own address, not a parameter
// the scanner picked: the fragment never reaches the server at all, which is exactly why
// nothing server-side can filter it.
type domXSS struct{}

func (domXSS) ID() string                 { return "dom-xss" }
func (domXSS) TitleKey() i18n.Key         { return i18n.KeyCheckDOMXSSTitle }
func (domXSS) DescriptionKey() i18n.Key   { return i18n.KeyCheckDOMXSSDesc }
func (domXSS) RemediationKey() i18n.Key   { return i18n.KeyCheckDOMXSSFix }
func (domXSS) Severity() finding.Severity { return finding.SeverityHigh }
func (domXSS) Tags() []string {
	return []string{"active", "injection", "xss", "dom", "owasp-top10"}
}
func (domXSS) Passive() bool { return false }

// IsRequestLevel marks this as a check about the page rather than about one parameter.
func (domXSS) IsRequestLevel() bool { return true }

// NeedsBrowser marks this as a check that a response cannot answer.
func (domXSS) NeedsBrowser() bool { return true }

// IsUnsafe marks this as more than a request. Loading a page in a real browser runs every
// script it carries — including the ones that fetch further data and the ones that write
// it — so on a target whose pages have side effects this does more than test the request
// it was given. It is never selected by default, and naming it is the consent.
func (domXSS) IsUnsafe() bool { return true }

// maxDOMCandidates bounds how many addresses one page is loaded with. Each candidate is a
// browser load, and the fragment plus the first few parameters is where a value reaches a
// page's script in practice.
const maxDOMCandidates = 8

func (domXSS) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	// Without a browser there is nothing to ask. Saying so by doing nothing is the only
	// honest answer: the response cannot tell either way.
	if c.Browser == nil || t.Request == nil || t.Request.URL == nil {
		return nil
	}

	// The plain shape first, because it is what an ordinary page renders. Only when nothing
	// came of it is the nested shape worth a browser load each: it finds the same page
	// twice, and the second pass costs as much as the first.
	for _, shape := range domProbeShapes {
		for _, candidate := range domCandidates(t.Request, shape.probe) {
			embedded, detail, err := c.Browser.Probe(ctx, candidate.url, candidate.marker)
			if err != nil || !embedded {
				continue
			}

			f := checks.NewFinding(domXSS{}, t,
				i18n.KeyCheckDOMXSSTitle, i18n.KeyCheckDOMXSSDesc, i18n.KeyCheckDOMXSSFix)
			f.Severity = finding.SeverityHigh
			// Firm rather than certain: the element is in the document, which means the value
			// was parsed as markup. Whether a policy then stopped the script it carried is a
			// question this check does not ask.
			f.Confidence = finding.ConfidenceFirm
			f.Method = "GET"
			f.URL = candidate.url
			f.Payload = shape.probe(candidate.marker)
			f.DedupExtra = candidate.name
			f.CWE = "CWE-79"
			f.References = []string{
				"https://owasp.org/www-community/attacks/DOM_Based_XSS",
				"https://cwe.mitre.org/data/definitions/79.html",
			}
			// The finding rests on what the browser built, so the evidence is the request that
			// carried the value and the element it produced.
			f.Evidence.Request = []byte("GET " + candidate.url + " HTTP/1.1\r\nHost: " +
				t.Request.Host() + "\r\n\r\n")
			f.Evidence.Matches = []string{
				candidate.name + ": the planted element is part of the document",
				detail,
			}
			f.Evidence.Diff = detail
			return []*finding.Finding{f}
		}
	}
	return nil
}

// pathCandidate puts the probe at the end of the address's path, which is where a
// page that routes on its own path reads it from.
//
// The address is assembled by hand rather than through `url.URL`: its String method
// escapes the path, and an escaped probe is a string no page parses as markup, so
// the candidate would test nothing.
func pathCandidate(req *httpmsg.Request, probe string) string {
	if req == nil || req.URL == nil {
		return ""
	}
	address := req.URL.Scheme + "://" + req.URL.Host + strings.TrimSuffix(req.URL.Path, "/") + "/" + probe
	if req.URL.RawQuery != "" {
		address += "?" + req.URL.RawQuery
	}
	return address
}

// domCandidate is one way a value can reach a page's script, and the marker that says
// whether it arrived.
type domCandidate struct {
	name   string
	url    string
	marker string
}

// domCandidates returns the addresses worth loading: the fragment, which the browser keeps
// to itself, and each query parameter, which a page reads back out of location.search.
func domCandidates(req *httpmsg.Request, probe func(string) string) []domCandidate {
	fragmentMarker, hashbangMarker, pathMarker := domMarker(), domMarker(), domMarker()
	out := []domCandidate{{
		name: "url fragment",
		// The fragment is appended as it is written. Encoding it would deliver a string
		// that no longer parses as markup, and the point is to find out whether the page
		// parses it.
		url:    req.URLString() + "#" + probe(fragmentMarker),
		marker: fragmentMarker,
	}, {
		// `#!` is the fragment an older client-side router reserved for its own
		// routes, and the value after it is read with `slice(2)` rather than
		// `slice(1)`. A page that reads the one and not the other is telling.
		name:   "hashbang fragment",
		url:    req.URLString() + "#!" + probe(hashbangMarker),
		marker: hashbangMarker,
	}, {
		// The path is a different reader from the fragment, and one the server does
		// see: a page that filters the query string may still hand its route on to
		// the document.
		name:   "url path",
		url:    pathCandidate(req, probe(pathMarker)),
		marker: pathMarker,
	}}

	for _, param := range req.QueryParams() {
		if len(out) >= maxDOMCandidates {
			break
		}
		marker := domMarker()
		mutated, err := checks.Mutate(req, param, probe(marker), checks.EncodeURL)
		if err != nil || mutated == nil || mutated.URL == nil {
			continue
		}
		out = append(out, domCandidate{
			name:   string(param.In) + ":" + param.Name,
			url:    mutated.URLString(),
			marker: marker,
		})
	}
	return out
}

// domProbeShapes are the two spellings of the probe, tried in order.
//
// The second is for a filter that removes complete tags rather than refusing input. A
// filter written as "match and delete" changes the *structure* of what it cleans, so an
// input can be built that has the tag reassembled by the deletion itself: the rule sees
// `<img>` in the middle and removes it, and what is left on either side joins into the tag
// it was meant to remove. It holds for every re.sub / replace / strip_tags style filter,
// which is why it is worth a second pass.
var domProbeShapes = []struct {
	name  string
	probe func(string) string
}{
	{"plain", domProbe},
	{"nested", domProbeNested},
}

// domProbeNested is the probe for a filter that deletes complete tags.
func domProbeNested(marker string) string {
	return `<i<img>mg src=x id=` + marker + `>`
}

// domProbe is markup whose only effect is to exist. Parsed as markup it creates an element
// that carries the marker; displayed as text it creates nothing, and the check finds
// nothing. Nothing is loaded or executed to make it appear, so a page that merely fails to
// reach a resource is not mistaken for a vulnerable one.
//
// The tag is closed. Leaving it open looks like it would slip past a filter that matches
// complete tags, and it does — but the parser then reads whatever follows as part of the
// attribute value, the element never takes the name the check looks for, and every page
// that *is* vulnerable stops being found. Measured, not assumed: the open form broke both
// test targets that the closed form finds.
func domProbe(marker string) string {
	return `<img src=x id=` + marker + `>`
}

// domMarker returns an element name that is valid as an id and cannot collide with
// anything already on a page.
func domMarker() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "crackwebprobe"
	}
	return "crackwebprobe" + hex.EncodeToString(raw[:])
}
