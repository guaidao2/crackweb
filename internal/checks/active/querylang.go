package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// Three query languages are tested the same way here, because they fail the same way. LDAP,
// XPath and OData are all expressions a value gets spliced into, and each of their parsers
// complains in its own words when the result no longer parses. Those words are the
// evidence: a library naming itself in an error message is not something an application
// produces by accident, and no ordinary page contains the phrase.
//
// The baseline is always part of the test. A page that documents LDAP filters, or serves a
// stack trace it already carried, would otherwise look like a finding on every parameter.

// maxSignatureScanBytes bounds how much of a response these checks read. A response larger
// than this is a download, and a parser's complaint lives in a page.
const maxSignatureScanBytes = 256 << 10

// ldapSeeds break the filter structure. A value carrying a parenthesis stops being a term
// and becomes syntax, which is the whole of the technique.
var ldapSeeds = []string{
	"*)(uid=*",
	"*)(objectClass=*",
	"admin)(|(1=1",
	"*))(|(cn=*",
}

// ldapSignatures are the complaints directory libraries make about a filter they could not
// parse. Each names the library, which is what makes it usable as evidence.
var ldapSignatures = []string{
	"javax.naming.directory",
	"com.sun.jndi.ldap",
	"ldapexception",
	"bad search filter",
	"invalid dn syntax",
	"unable to parse the search filter",
}

// xpathSeeds close the string literal a value was placed inside.
var xpathSeeds = []string{
	"'",
	"\"",
	"' or '1'='1",
	"']|//*|//*['",
	"') or ('1'='1",
}

// xpathSignatures are the XPath parsers' complaints.
var xpathSignatures = []string{
	"xpathexception",
	"xpath syntax error",
	"invalid xpath expression",
	"system.xml.xpath",
	"org.jaxen",
	"xmlxpathcompopexpr",
}

// odataSeeds carry query syntax into a system query option, where a value is expected to be
// a literal.
var odataSeeds = []string{
	"' or 1 eq 1",
	"') or ('1' eq '1",
	"1 eq 1 or '1' eq '1",
	"') or 1 eq 1 or ('",
}

// odataSignatures are the OData libraries' complaints. The generic ones name the library or
// the error code, because the sentence alone is produced by too many things.
var odataSignatures = []string{
	"microsoft.odata",
	"system.web.odata",
	"odataerror",
	"odata.exception",
	"the query specified in the uri is not valid",
}

// runSignatureCheck sends each seed into the target's parameter and reports the first one
// whose response carries a signature the named parser produces, provided the baseline did
// not carry it too.
func runSignatureCheck(ctx context.Context, c *checks.Context, t *checks.Target,
	check checks.Check, seeds, signatures []string, technology, cwe string) []*finding.Finding {
	if t == nil || t.Param == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	baseline := strings.ToLower(scanText(t.Response.Body))

	for _, seed := range seeds {
		mutated, response, err := c.Inject(ctx, t, seed)
		if err != nil || response == nil {
			continue
		}
		body := strings.ToLower(scanText(response.Body))
		for _, signature := range signatures {
			if !strings.Contains(body, signature) || strings.Contains(baseline, signature) {
				continue
			}
			f := checks.NewFinding(check, t,
				check.TitleKey(), check.DescriptionKey(), check.RemediationKey())
			f.Severity = finding.SeverityHigh
			// Firm rather than certain: the parser named itself, which is conclusive about
			// where the value arrived, and the check does not go on to prove what could be
			// read out of the directory or the document.
			f.Confidence = finding.ConfidenceFirm
			f.Payload = seed
			f.CWE = cwe
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Raw(), 8192)
			f.Evidence.Baseline = truncate(t.Response.Raw(), 4096)
			f.Evidence.Matches = []string{c.Bundle.T(i18n.KeyEvidenceParser, signature, technology)}
			return []*finding.Finding{f}
		}
	}
	return nil
}

// scanText bounds how much of a body a signature check reads.
func scanText(body []byte) string {
	if len(body) > maxSignatureScanBytes {
		body = body[:maxSignatureScanBytes]
	}
	return string(body)
}

// ldapInjection detects a value reaching an LDAP filter.
type ldapInjection struct{}

func (ldapInjection) ID() string                 { return "ldap-injection" }
func (ldapInjection) TitleKey() i18n.Key         { return i18n.KeyCheckLDAPTitle }
func (ldapInjection) DescriptionKey() i18n.Key   { return i18n.KeyCheckLDAPDesc }
func (ldapInjection) RemediationKey() i18n.Key   { return i18n.KeyCheckLDAPFix }
func (ldapInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (ldapInjection) Tags() []string {
	return []string{"active", "injection", "ldap", "owasp-top10"}
}
func (ldapInjection) Passive() bool { return false }

func (ldapInjection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	return runSignatureCheck(ctx, c, t, ldapInjection{}, ldapSeeds, ldapSignatures,
		"an LDAP directory", "CWE-90")
}

// xpathInjection detects a value reaching an XPath expression.
type xpathInjection struct{}

func (xpathInjection) ID() string                 { return "xpath-injection" }
func (xpathInjection) TitleKey() i18n.Key         { return i18n.KeyCheckXPathTitle }
func (xpathInjection) DescriptionKey() i18n.Key   { return i18n.KeyCheckXPathDesc }
func (xpathInjection) RemediationKey() i18n.Key   { return i18n.KeyCheckXPathFix }
func (xpathInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (xpathInjection) Tags() []string {
	return []string{"active", "injection", "xpath", "owasp-top10"}
}
func (xpathInjection) Passive() bool { return false }

func (xpathInjection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	return runSignatureCheck(ctx, c, t, xpathInjection{}, xpathSeeds, xpathSignatures,
		"an XPath parser", "CWE-643")
}

// odataInjection detects a value reaching an OData system query option.
type odataInjection struct{}

func (odataInjection) ID() string                 { return "odata-injection" }
func (odataInjection) TitleKey() i18n.Key         { return i18n.KeyCheckODataTitle }
func (odataInjection) DescriptionKey() i18n.Key   { return i18n.KeyCheckODataDesc }
func (odataInjection) RemediationKey() i18n.Key   { return i18n.KeyCheckODataFix }
func (odataInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (odataInjection) Tags() []string {
	return []string{"active", "injection", "odata", "owasp-top10"}
}
func (odataInjection) Passive() bool { return false }

func (odataInjection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	return runSignatureCheck(ctx, c, t, odataInjection{}, odataSeeds, odataSignatures,
		"an OData library", "CWE-943")
}
