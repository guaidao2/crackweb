package active

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// httpPut reports a server that stores the body of a PUT under the request's own path.
//
// A PUT that writes is an upload endpoint nobody configured on purpose: static hosts, build
// artefact directories and half-configured WebDAV all end up here, and the file lands where
// the server serves from. Nothing else is needed to turn it into execution — the extension is
// the caller's to choose.
//
// The proof is the same shape as the archive probe's: write a file, read it back, and check
// first that a path nothing was written to is genuinely missing — otherwise a server that
// answers every path with something would look like a server that stored what it was given.
type httpPut struct{}

func (httpPut) ID() string                 { return "http-put" }
func (httpPut) TitleKey() i18n.Key         { return i18n.KeyCheckHTTPPutTitle }
func (httpPut) DescriptionKey() i18n.Key   { return i18n.KeyCheckHTTPPutDesc }
func (httpPut) RemediationKey() i18n.Key   { return i18n.KeyCheckHTTPPutFix }
func (httpPut) Severity() finding.Severity { return finding.SeverityHigh }
func (httpPut) Tags() []string {
	return []string{"active", "upload", "misconfiguration", "owasp-top10"}
}
func (httpPut) Passive() bool { return false }

// IsUnsafe marks this as a check that must be opted into: it stores a file on the target, and
// the file it stores is a change to a system nobody asked to change. The other probes in the
// tool send payloads and read the answers; this one leaves something behind.
func (httpPut) IsUnsafe() bool { return true }

// IsRequestLevel marks this as a check about the address rather than about one parameter.
func (httpPut) IsRequestLevel() bool { return true }

func (httpPut) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Request.URL == nil || t.Response == nil {
		return nil
	}
	// This check writes a file, and what it writes is a property of the host rather than of the
	// page: whichever URL it was dispatched against, it tests the same kind of absent path and
	// writes the same kind of name. A crawl dispatches it once per discovered URL, so without
	// this the host receives one write per page — each of them a change to a system nobody
	// asked to change.
	if !c.HostOnce(t.Request.Hostname(), "http-put") {
		return nil
	}

	// A path nothing was written to must be missing, or "the file is there" means nothing.
	absent := "/crackweb-put-absent-" + putSuffix() + ".txt"
	if _, response, err := requestPath(ctx, c, t, absent, "", ""); err != nil ||
		response == nil || response.Status != 404 {
		return nil
	}

	marker := "crackwebput" + putSuffix()
	target := "/crackweb-put-" + marker + ".txt"

	write := t.Request.Clone()
	write.Method = "PUT"
	write.Body = []byte(marker)
	write.Header.Set("Content-Type", "text/plain")
	write.Header.Set("Content-Length", strconv.Itoa(len(marker)))
	address := *t.Request.URL
	address.Path = target
	address.RawPath = ""
	address.RawQuery = ""
	address.Fragment = ""
	write.URL = &address

	written, err := c.Do(ctx, write)
	if err != nil || written == nil || written.Status >= 300 {
		return nil
	}

	// Read it back: the file, in the server's own response.
	_, retrieved, err := requestPath(ctx, c, t, target, "", "")
	if err != nil || retrieved == nil || retrieved.Status != 200 {
		return nil
	}
	body := string(retrieved.Body)
	if !strings.Contains(body, marker) {
		return nil
	}

	f := checks.NewFinding(httpPut{}, t,
		i18n.KeyCheckHTTPPutTitle, i18n.KeyCheckHTTPPutDesc, i18n.KeyCheckHTTPPutFix)
	f.Severity = finding.SeverityHigh
	// Certain: the bytes this check wrote came back from the path it wrote them to.
	f.Confidence = finding.ConfidenceCertain
	f.Method = "PUT"
	f.URL = write.URLString()
	f.Payload = "PUT " + target
	f.CWE = "CWE-434"
	f.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
		"https://cwe.mitre.org/data/definitions/434.html",
	}
	f.Evidence.Request = write.Raw()
	f.Evidence.Response = truncate(retrieved.Body, 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"a PUT to " + target + " was stored and served back from the same address",
		"the server accepts writes over the request's own path, so the caller chooses the " +
			"name — and with it the extension the server will run",
	}
	f.Evidence.Diff = body[:min(len(body), 200)]
	return []*finding.Finding{f}
}

// putSuffix returns a short random string, so the file written cannot collide with anything.
func putSuffix() string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "probe"
	}
	return hex.EncodeToString(raw[:])
}
