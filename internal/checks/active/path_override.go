package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// pathOverride reports a server that lets a request header decide which path it handles.
//
// The headers come from a deployment where a proxy sits in front: it routes on the URL and
// passes the intended path along in `X-Original-URL` (or its relatives) for the backend to
// use. That is only safe while the backend also insists the request arrived through the
// proxy — and when it does not, the access control the proxy performs is about one path
// while the application serves another. A request for a path that does not exist, carrying a
// header that names one that does, is the whole test.
//
// The baseline has to be a genuine miss: on a site that answers everything with its home
// page — a single-page application, most often — the header changes nothing and a finding
// would be about the router rather than about the header.
type pathOverride struct{}

func (pathOverride) ID() string                 { return "path-override" }
func (pathOverride) TitleKey() i18n.Key         { return i18n.KeyCheckPathOverrideTitle }
func (pathOverride) DescriptionKey() i18n.Key   { return i18n.KeyCheckPathOverrideDesc }
func (pathOverride) RemediationKey() i18n.Key   { return i18n.KeyCheckPathOverrideFix }
func (pathOverride) Severity() finding.Severity { return finding.SeverityHigh }
func (pathOverride) Tags() []string {
	return []string{"active", "access-control", "proxy", "owasp-top10"}
}
func (pathOverride) Passive() bool { return false }

// IsRequestLevel marks this as a check about the address rather than about one parameter.
func (pathOverride) IsRequestLevel() bool { return true }

// pathOverrideHeaders are the header names a front end uses to tell a backend which path it
// meant.
var pathOverrideHeaders = []string{"X-Original-URL", "X-Rewrite-URL", "X-Original-URI"}

// pathOverrideProbe is the path the header is asked for: the root, which exists everywhere
// and is recognisable without knowing anything about the site.
const pathOverrideProbe = "/"

func (pathOverride) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Request.URL == nil || t.Response == nil {
		return nil
	}

	// The address of a path that cannot exist, so a 404 is the only honest answer.
	missing := "/crackweb-override-" + overrideSuffix()
	_, missed, err := requestPath(ctx, c, t, missing, "", "")
	if err != nil || missed == nil || missed.Status != 404 {
		return nil
	}
	missedFingerprint := c.Fingerprint(missed)

	// The root, as a reference for what "handled" looks like on this site.
	_, root, err := requestPath(ctx, c, t, pathOverrideProbe, "", "")
	if err != nil || root == nil || root.Status >= 400 {
		return nil
	}
	rootFingerprint := c.Fingerprint(root)

	for _, header := range pathOverrideHeaders {
		mutated, response, err := requestPath(ctx, c, t, missing, header, pathOverrideProbe)
		if err != nil || response == nil {
			continue
		}
		if response.Status == 404 {
			continue
		}
		// It has to be the reference page, not merely something that is not a 404: a target
		// that answers an unknown path with a redirect to the home page is doing its job, and
		// would look the same either way.
		if diff.CompareFingerprints(rootFingerprint, c.Fingerprint(response)).Score < uploadSimilarity {
			continue
		}
		if diff.CompareFingerprints(missedFingerprint, c.Fingerprint(response)).Score >= uploadSimilarity {
			continue
		}

		f := checks.NewFinding(pathOverride{}, t,
			i18n.KeyCheckPathOverrideTitle, i18n.KeyCheckPathOverrideDesc, i18n.KeyCheckPathOverrideFix)
		f.Severity = finding.SeverityHigh
		// Firm: the header decided the path, which is the flaw. Whether the path it reaches is
		// one the front end would have refused is a question about that deployment.
		f.Confidence = finding.ConfidenceFirm
		f.Method = mutated.Method
		f.URL = mutated.URLString()
		f.Payload = header + ": " + pathOverrideProbe + " (requested " + missing + ")"
		f.CWE = "CWE-863"
		f.References = []string{
			"https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
			"https://cwe.mitre.org/data/definitions/863.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(missed.Body, 4096)
		f.Evidence.Matches = []string{
			"a request for " + missing + " was answered with the response for " + pathOverrideProbe +
				" once the " + header + " header was added",
			"the header decides which path is handled, so any access control performed on the " +
				"request's own path is being applied to a different path than the one served",
		}
		f.Evidence.Diff = extractAround(string(response.Body), "", 200)
		return []*finding.Finding{f}
	}
	return nil
}

// requestPath sends a GET for one path, optionally carrying a header.
func requestPath(ctx context.Context, c *checks.Context, t *checks.Target, path, header, value string) (*httpmsg.Request, *httpmsg.Response, error) {
	request := t.Request.Clone()
	request.Method = "GET"
	request.Body = nil
	request.Header.Del("Content-Type")
	request.Header.Del("Content-Length")
	address := *t.Request.URL
	address.Path = path
	address.RawPath = ""
	address.RawQuery = ""
	address.Fragment = ""
	request.URL = &address
	if header != "" {
		request.Header.Set(header, value)
	}
	response, err := c.Do(ctx, request)
	return request, response, err
}

// overrideSuffix returns a short random string, so the path asked for cannot exist.
func overrideSuffix() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "probe"
	}
	return hex.EncodeToString(raw[:])
}
