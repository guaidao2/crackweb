package passive

import (
	"context"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// Elements and attributes the subresource integrity check reads. A regular expression is
// enough here: the question is only whether an element that loads from another origin
// carries an integrity attribute, and that is a property of the tag itself rather than of
// the document tree.
var (
	assetTagRe       = regexp.MustCompile(`(?is)<(script|link)\b([^>]*)>`)
	tagURLRe         = regexp.MustCompile(`(?i)\b(?:src|href)\s*=\s*["']?([^"'\s>]+)`)
	relAttrRe        = regexp.MustCompile(`(?i)\brel\s*=\s*["']?([^"'\s>]+)`)
	integrityValueRe = regexp.MustCompile(`(?i)\bintegrity\s*=\s*["']([^"']*)["']`)
	crossoriginRe    = regexp.MustCompile(`(?i)\bcrossorigin\b`)
	passwordInputRe  = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?password`)
	maxAssetsScanned = 200
)

// sriDigestLengths maps the algorithms Subresource Integrity defines to the length of
// their base64 digest. Anything outside this set is not checked by a browser at all.
var sriDigestLengths = map[string]int{"sha256": 44, "sha384": 64, "sha512": 88}

// sriIsVerifiable reports whether an integrity value is one a browser will act on.
//
// The attribute's presence is not the question. The specification defines three
// algorithms, and a value using any other — `sha1`, a bare digest, an empty string after a
// deployment mistake — is ignored, which leaves the resource running unverified while the
// page looks like it is protected. At least one usable hash makes the element verified,
// since the browser accepts any of them.
func sriIsVerifiable(value string) bool {
	for _, token := range strings.Fields(value) {
		algorithm, digest, ok := strings.Cut(token, "-")
		if !ok {
			continue
		}
		length, known := sriDigestLengths[strings.ToLower(strings.TrimSpace(algorithm))]
		if !known {
			continue
		}
		digest = strings.TrimSpace(digest)
		if len(digest) != length {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(digest); err != nil {
			continue
		}
		return true
	}
	return false
}

// subresourceIntegrity reports a page that loads code or styling from another origin
// without a hash to check it against.
//
// The element is fetched from a host the site does not control. With an integrity
// attribute the browser refuses a file whose bytes changed; without one it runs whatever
// arrives, so a compromise at that origin, or a takeover of a lapsed domain, becomes
// script execution on this site.
type subresourceIntegrity struct{}

func (subresourceIntegrity) ID() string { return "passive-sri" }
func (subresourceIntegrity) TitleKey() i18n.Key {
	return i18n.KeyCheckSRITitle
}
func (subresourceIntegrity) DescriptionKey() i18n.Key { return i18n.KeyCheckSRIDesc }
func (subresourceIntegrity) RemediationKey() i18n.Key { return i18n.KeyCheckSRIFix }
func (subresourceIntegrity) Severity() finding.Severity {
	return finding.SeverityInfo
}
func (subresourceIntegrity) Tags() []string { return []string{"passive", "assets", "supply-chain"} }
func (subresourceIntegrity) Passive() bool  { return true }

func (subresourceIntegrity) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if !isHTML(t.Response) || t.Request == nil {
		return nil
	}
	pageHost := t.Request.Hostname()
	if pageHost == "" {
		return nil
	}

	var unprotected []string
	for _, match := range assetTagRe.FindAllStringSubmatch(bodyForScan(t.Response.Body), maxAssetsScanned) {
		element, attrs := strings.ToLower(match[1]), match[2]
		if element == "link" && !strings.Contains(strings.ToLower(relAttr(attrs)), "stylesheet") {
			// Icons, preloads and canonical links are not code; an integrity hash on them
			// buys nothing.
			continue
		}
		host, ok := externalHost(tagURL(attrs), pageHost)
		if !ok {
			continue
		}
		value := integrityValue(attrs)
		switch {
		case value == "" && integrityValueRe.MatchString(attrs):
			// The attribute is there and empty: a deployment mistake that reads as
			// protection and provides none.
			unprotected = append(unprotected, element+" from "+host+" carries an empty integrity value")
		case value != "" && !sriIsVerifiable(value):
			unprotected = append(unprotected, element+" from "+host+
				" carries an integrity value no browser checks ("+firstField(value)+")")
		case value != "" && !crossoriginRe.MatchString(attrs):
			// Without `crossorigin` a cross-origin response is opaque to the check, and
			// the browser refuses the load rather than verifying it: the hash does not
			// protect the resource, it stops the page.
			unprotected = append(unprotected, element+" from "+host+
				" has an integrity value but no crossorigin attribute")
		case value == "":
			unprotected = append(unprotected, element+" from "+host)
		}
	}
	if len(unprotected) == 0 {
		return nil
	}

	f := checks.NewFinding(subresourceIntegrity{}, t,
		i18n.KeyCheckSRITitle, i18n.KeyCheckSRIDesc, i18n.KeyCheckSRIFix)
	f.Confidence = finding.ConfidenceCertain
	f.DedupHostOnly = true
	f.DedupExtra = strings.Join(unprotected, ",")
	f.CWE = "CWE-353"
	f.References = []string{"https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"}
	f.Evidence.Matches = unprotected
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}

// integrityValue returns the integrity attribute's value, or an empty string.
func integrityValue(attrs string) string {
	match := integrityValueRe.FindStringSubmatch(attrs)
	if match == nil {
		return ""
	}
	return strings.TrimSpace(match[1])
}

// firstField returns the first whitespace-separated word, for quoting a value in evidence.
func firstField(value string) string {
	if fields := strings.Fields(value); len(fields) > 0 {
		return fields[0]
	}
	return value
}

// tagURL returns the address a script or link element loads.
func tagURL(attrs string) string {
	match := tagURLRe.FindStringSubmatch(attrs)
	if match == nil {
		return ""
	}
	return match[1]
}

// relAttr returns an element's rel attribute.
func relAttr(attrs string) string {
	match := relAttrRe.FindStringSubmatch(attrs)
	if match == nil {
		return ""
	}
	return match[1]
}

// externalHost reports the host a URL points at, when it is not the page's own.
func externalHost(raw, pageHost string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		// A relative address is served from the same origin, which is the one case where
		// the fetching host is not in question.
		return "", false
	}
	host := parsed.Hostname()
	if host == "" || strings.EqualFold(host, pageHost) {
		return "", false
	}
	return host, true
}

// insecureTransport reports a password field served over plain HTTP.
//
// The credential is not the only thing at stake: the session cookie handed back after the
// login travels the same way, so anyone able to read the connection can take the session
// over afterwards. The page is the thing being reported because it is what the visitor is
// looking at when they decide to trust it.
type insecureTransport struct{}

func (insecureTransport) ID() string { return "passive-insecure-transport" }
func (insecureTransport) TitleKey() i18n.Key {
	return i18n.KeyCheckInsecureTransportTitle
}
func (insecureTransport) DescriptionKey() i18n.Key {
	return i18n.KeyCheckInsecureTransportDesc
}
func (insecureTransport) RemediationKey() i18n.Key {
	return i18n.KeyCheckInsecureTransportFix
}
func (insecureTransport) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (insecureTransport) Tags() []string { return []string{"passive", "tls", "authentication"} }
func (insecureTransport) Passive() bool  { return true }

func (insecureTransport) Run(_ context.Context, _ *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Request == nil || !isHTML(t.Response) || isHTTPS(t.Request) {
		return nil
	}
	if !passwordInputRe.MatchString(bodyForScan(t.Response.Body)) {
		return nil
	}

	f := checks.NewFinding(insecureTransport{}, t,
		i18n.KeyCheckInsecureTransportTitle, i18n.KeyCheckInsecureTransportDesc,
		i18n.KeyCheckInsecureTransportFix)
	f.Confidence = finding.ConfidenceCertain
	f.DedupHostOnly = true
	// A password input is the page's own markup, so where it appears is not quoted back:
	// what matters is which host serves it this way.
	f.Evidence.Matches = []string{t.Request.Scheme() + "://" + t.Request.Host()}
	f.Evidence.Response = headBytes(t.Response, 4096)
	return []*finding.Finding{f}
}
