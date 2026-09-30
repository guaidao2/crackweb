package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// exposedPath reports files a web server is serving that it was never meant to.
//
// These are the addresses an operator lists by hand after an incident: the environment file
// with the database password in it, the git directory with the whole history, a schema dump,
// a configuration backup, the status page. None of them is linked from anywhere, which is why
// they are asked for by name — and each is recognised by something only that file contains,
// so a server that answers every unknown path with its home page cannot produce a finding.
//
// The list is short on purpose. Every entry costs a request against every host, and a name
// without a signature that only its own file carries would be a request that can never be
// reported — the same rule the file-read probes follow.
type exposedPath struct{}

func (exposedPath) ID() string                 { return "exposed-path" }
func (exposedPath) TitleKey() i18n.Key         { return i18n.KeyCheckExposedPathTitle }
func (exposedPath) DescriptionKey() i18n.Key   { return i18n.KeyCheckExposedPathDesc }
func (exposedPath) RemediationKey() i18n.Key   { return i18n.KeyCheckExposedPathFix }
func (exposedPath) Severity() finding.Severity { return finding.SeverityHigh }
func (exposedPath) Tags() []string {
	return []string{"active", "disclosure", "misconfiguration", "owasp-top10"}
}
func (exposedPath) Passive() bool { return false }

// IsRequestLevel marks this as a check about the host rather than about one parameter.
func (exposedPath) IsRequestLevel() bool { return true }

// exposedPathSignatures are lower case because the comparison lower-cases the body, and they
// carry no character a page would escape.
// exposedPathEntry is one file worth asking for, and the technology it belongs to.
type exposedPathEntry struct {
	path      string
	signature string
	what      string
	// hint names the technology this file belongs to. An empty hint means the file is worth
	// asking for anywhere; otherwise it is tried only when the response mentioned the
	// technology, so a stack-specific name does not cost every host a request. The list is
	// what a scan pays for on every target, and most targets are not running any one of these.
	hint string
}

// exposedPathHints are the strings in a response that suggest a technology, keyed by the hint
// the entries carry. They are matched against the headers and the body, lower-cased.
var exposedPathHints = map[string][]string{
	"nginx":     {"nginx"},
	"apache":    {"apache"},
	"php":       {"php", "phpsessid"},
	"wordpress": {"wp-content", "wp-includes", "wordpress"},
	"spring":    {"jsessionid", "x-application-context", "spring"},
	"django":    {"csrfmiddlewaretoken", "csrftoken", "django"},
}

// suggestedTechnologies returns the hints a response's own headers and body support.
//
// The point is to keep a stack-specific name from costing every host a request: the list is
// what a scan pays on every target, and most targets are running none of these. The evidence
// is whatever the server volunteered — a Server header, a session cookie name, a framework's
// markup — so a target that says nothing loses nothing that mattered: the entries with no hint
// are asked in every case.
func suggestedTechnologies(response *httpmsg.Response) map[string]bool {
	if response == nil {
		return nil
	}
	haystack := strings.ToLower(string(response.Body))
	for _, header := range response.Header.All() {
		haystack += "\n" + strings.ToLower(header.Name) + ": " + strings.ToLower(header.Value)
	}
	out := map[string]bool{}
	for hint, markers := range exposedPathHints {
		for _, marker := range markers {
			if strings.Contains(haystack, marker) {
				out[hint] = true
				break
			}
		}
	}
	return out
}

var exposedPathSignatures = []exposedPathEntry{
	{"/.env", "app_key", "application environment file", ""},
	{"/.env.local", "db_password", "application environment file", ""},
	{"/.git/config", "[core]", "git repository metadata", ""},
	{"/.git/HEAD", "ref: refs/", "git repository metadata", ""},
	{"/.DS_Store", "bud1", "macOS directory metadata", ""},
	{"/backup.sql", "insert into", "database dump", ""},
	{"/dump.sql", "create table", "database dump", ""},
	{"/.htpasswd", "$apr1$", "password file", ""},
	{"/phpinfo.php", "php version", "phpinfo output", "php"},
	{"/server-status", "apache server status", "server status page", ""},
	{"/web.config", "system.webserver", "IIS configuration file", ""},
	{"/WEB-INF/web.xml", "web-app", "Java web application descriptor", ""},
	{"/config.php.bak", "<?php", "editor backup of a script", ""},
	{"/.htaccess", "rewriteengine", "Apache configuration file", ""},
	{"/actuator/env", "activeprofiles", "Spring Boot environment endpoint", "spring"},
	// API descriptions: unlinked by design, and a map of everything else the application does.
	{"/swagger.json", "swagger", "API description", ""},
	{"/openapi.json", "openapi", "API description", ""},
	{"/v2/api-docs", "swagger", "API description", "spring"},
	// The same description under the path a version segment puts it on, which is what a
	// framework with more than one API version serves — and what a search for the bare name
	// does not reach.
	{"/swagger/v1/swagger.json", "swagger", "API description", ""},
	{"/swagger/v2/swagger.json", "swagger", "API description", ""},
	{"/v3/api-docs", "openapi", "API description", ""},
	// Framework configuration, which carries the credentials the framework signs and connects
	// with.
	{"/settings.py", "secret_key", "Django settings", "django"},
	{"/application.properties", "spring.datasource", "Spring configuration", "spring"},
	{"/.env.production", "app_key", "application environment file", ""},
	{"/wp-config.php.bak", "db_password", "WordPress configuration backup", "wordpress"},
	// Deployment and repository metadata.
	{"/docker-compose.yml", "services:", "container composition file", ""},
	{"/.svn/wc.db", "sqlite format 3", "Subversion working copy database", ""},
	{"/id_rsa", "private key-----", "private key", ""},
	// Operational endpoints, which describe the server and its traffic.
	{"/server-info", "server information", "Apache server information", "apache"},
	{"/nginx_status", "active connections", "nginx status page", "nginx"},
	{"/debug/pprof/", "types of profiles", "Go profiling endpoint", ""},
}

func (exposedPath) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Request.URL == nil || t.Response == nil {
		return nil
	}
	// The question this check asks is the host's — which of these paths it publishes — and the
	// answer does not depend on which page it was dispatched against. A crawl dispatches it once
	// per discovered URL, so without this the same thirty-odd requests go out for every page of
	// the site, and the answer cannot have changed between two of them.
	if !c.HostOnce(t.Request.Hostname(), "exposed-path") {
		return nil
	}

	// What a missing path looks like here. Everything else is compared against it, so a site
	// that answers every address with the same page — a single-page application, or a
	// framework with a catch-all route — cannot be mistaken for one that serves these files.
	absent := "/crackweb-absent-" + overrideSuffix() + ".txt"
	_, missing, err := requestPath(ctx, c, t, absent, "", "")
	if err != nil || missing == nil {
		return nil
	}
	missingFingerprint := c.Fingerprint(missing)

	// Only the names this target has given a reason for, plus the ones that need no reason.
	suggested := suggestedTechnologies(t.Response)
	for _, entry := range exposedPathSignatures {
		if entry.hint != "" && !suggested[entry.hint] {
			continue
		}
		_, response, err := requestPath(ctx, c, t, entry.path, "", "")
		if err != nil || response == nil || response.Status != 200 {
			continue
		}
		body := strings.ToLower(string(response.Body))
		if !strings.Contains(body, entry.signature) {
			continue
		}
		// The page has to be about this file rather than the site's own answer to everything.
		if diff.CompareFingerprints(missingFingerprint, c.Fingerprint(response)).Score >= uploadSimilarity {
			continue
		}
		// Some signatures are words the requested path is built from — "swagger" in
		// "/swagger.json", "openapi" in "/openapi.json" — and a site that echoes whatever
		// address it is given then matches them without publishing anything: the answer is the
		// name it was asked for, wrapped in whatever the site wraps everything in. A control
		// cannot separate the two, because the only difference is the name. What does separate
		// them is the shape of an API description: every one of them is an object, and a page
		// that merely repeats a name is not.
		if strings.Contains(entry.path, entry.signature) &&
			!strings.ContainsRune(string(response.Body), '{') {
			continue
		}

		f := checks.NewFinding(exposedPath{}, t,
			i18n.KeyCheckExposedPathTitle, i18n.KeyCheckExposedPathDesc, i18n.KeyCheckExposedPathFix)
		f.Severity = finding.SeverityHigh
		// Certain: the file answered, and its contents carry a string only that file carries.
		f.Confidence = finding.ConfidenceCertain
		f.Method = "GET"
		f.URL = t.Request.URLString() + entry.path
		f.Payload = entry.path
		f.DedupHostOnly = true
		f.DedupExtra = entry.path
		f.CWE = "CWE-538"
		f.References = []string{
			"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
			"https://cwe.mitre.org/data/definitions/538.html",
		}
		f.Evidence.Request = []byte("GET " + entry.path + " HTTP/1.1\r\nHost: " + t.Request.Host() + "\r\n\r\n")
		f.Evidence.Response = truncate(response.Body, 6144)
		f.Evidence.Baseline = truncate(missing.Body, 2048)
		f.Evidence.Matches = []string{
			entry.path + " is served and carries the contents of " + entry.what + " (" +
				entry.signature + ")",
			"the file is reachable by anyone who asks for it by name, and is not meant to be " +
				"served at all",
		}
		f.Evidence.Diff = extractAround(string(response.Body), entry.signature, 200)
		return []*finding.Finding{f}
	}
	return nil
}
