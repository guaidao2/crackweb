package active

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// shiroRememberMe reports an Apache Shiro installation whose rememberMe cookie is
// encrypted with a key that has been published — the flaw behind CVE-2016-4437.
//
// Shiro keeps a visitor's remembered identity in that cookie: a Java-serialised
// object, AES-encrypted with a key that is configuration. For years Shiro's own
// samples, its tutorials and the applications built from them have used a small
// set of keys that are written down in public, so the key on a given installation
// is one of a handful of guesses rather than a secret.
//
// The cookie is two things at once. It is evidence of which key the installation
// uses, because a value that decrypts under a published key can only have been
// produced by someone holding that key. And it is the input to Shiro's
// deserialisation, which happens before any authorisation decision — so whoever
// can encrypt with that key can put a serialised object of their own in the
// cookie, which is where a gadget chain leads to command execution.
//
// The judgement here is deliberately offline, and it never builds, sends or
// deserialises a serialised object. It decrypts the value the application itself
// already shipped and asks whether the plaintext is a Java serialisation stream:
// STREAM_MAGIC, version 5, a TC_OBJECT, and a class descriptor naming a printable
// fully-qualified class. Recognising that header is enough to tell a published key
// from a wrong one, because a wrong key does not produce a structure that is
// nearly valid — it produces bytes that are not a stream at all. Nothing is
// executed and no type is loaded: the bytes are read as text, and the only thing
// built out of them is a string to print.
//
// The live half only re-seals the object the site stored, under the key that
// opened it, and offers it back. Nothing about the request changes but the
// ciphertext, and the object inside is the identity the site already trusted, so
// the only question being asked is whether the key that opened that value is the
// key this server decrypts with.
type shiroRememberMe struct{}

// shiroTitleKey, shiroDescKey and shiroFixKey are the catalogue keys behind this
// check's title, description and remediation.
const shiroTitleKey i18n.Key = i18n.KeyCheckShiroTitle
const shiroDescKey i18n.Key = i18n.KeyCheckShiroDesc
const shiroFixKey i18n.Key = i18n.KeyCheckShiroFix

func (shiroRememberMe) ID() string                 { return "shiro-default-key" }
func (shiroRememberMe) TitleKey() i18n.Key         { return shiroTitleKey }
func (shiroRememberMe) DescriptionKey() i18n.Key   { return shiroDescKey }
func (shiroRememberMe) RemediationKey() i18n.Key   { return shiroFixKey }
func (shiroRememberMe) Severity() finding.Severity { return finding.SeverityCritical }

func (shiroRememberMe) Tags() []string {
	return []string{"active", "deserialization", "shiro", "default-key"}
}

func (shiroRememberMe) Passive() bool { return false }

// IsRequestLevel marks this as a check about a cookie the request carries rather
// than about one of its parameters.
func (shiroRememberMe) IsRequestLevel() bool { return true }

// shiroCookieName is the cookie Shiro's CookieRememberMeManager reads and writes.
const shiroCookieName = "rememberMe"

// shiroCookieDeleted is what Shiro writes into the cookie when it could not make
// sense of the one it was given.
//
// It is a marker and never a ciphertext, so it is skipped where a value is looked
// for. It is also the only signal a target gives that it treats this cookie as a
// decryption input at all, which is why the live half reads it — and, equally, why
// no finding is ever built on it: a server saying "I could not decrypt this" says
// nothing about which key it would have accepted.
const shiroCookieDeleted = "deleteMe"

// shiroDefaultKeys are AES keys that have shipped as Apache Shiro's example
// configuration and that turn up, unchanged, in deployed applications: the key
// from the project's own samples, the one from the sample web application, and
// the ones published in the write-ups of CVE-2016-4437.
//
// A key that is wrong costs one decryption and is discarded; a key that is right
// is the finding. Every entry is decoded before it is used and skipped when it is
// not a legal AES key, so a mistyped string here can never make a wrong key
// unlock a cookie.
var shiroDefaultKeys = []string{
	"kPH+bIxk5D2deZiIxcaaaA==",
	"2AvVhdsgUs0FSA3SDFAdag==",
	"3AvVhmFLUs0KTA3Kprsdag==",
	"4AvVhmFLUs0KTA3Kprsdag==",
	"6ZmI6I2j5Y+R5aSn5ZOlAA==",
	"Z3VucwAAAAAAAAAAAAAAAA==",
	"wGiHplamyXlVB11UXWol8g==",
	"fCq+/xW488hMTCD+cmJ3aQ==",
	"1QWLxg+NYmxrayiptUGrZQ==",
	"L7RioUULEFhRxpUJ2a8Z+g==",
	"MTIzNDU2Nzg5MGFiY2RlZg==",
	"YWJjZGVmZ2hpamtsbW5vcA==",
	"5aaC5qKm5oqA5pyvAAAAAA==",
	"bWljcm9zAAAAAAAAAAAAAA==",
	"a2VlcE9uR29pbmdBbmRGaQ==",
	"WcfHGU25gNnTxTlmJMeSpw==",
	"kPv59vyqzj00x11LXJZTjA==",
}

// shiroEnvelope is one shape a rememberMe value can be written in: a cipher mode
// and the length of the initialization vector it was used with.
//
// Shiro prepends that vector to the ciphertext, which is what makes an offline
// decryption possible without anything but the key. CBC/PKCS5 is Shiro's default;
// GCM is the mode newer configurations select, and the JCE appends its
// authentication tag, so a GCM value is vector, ciphertext, tag.
type shiroEnvelope struct {
	mode string
	iv   int
}

var shiroEnvelopes = []shiroEnvelope{
	{mode: "CBC", iv: aes.BlockSize},
	{mode: "GCM", iv: 16},
	// A GCM vector of 96 bits is the size the mode is defined for, and a
	// configuration that set it explicitly writes one.
	{mode: "GCM", iv: 12},
}

// shiroHit is a published key that opened the cookie, with the plaintext it
// produced and the shape it was written in.
type shiroHit struct {
	key      []byte
	keyText  string
	envelope shiroEnvelope
	plain    []byte
	class    string
}

// shiroReferences point at the advisory and at the two classes of mistake: a key
// baked into the deployment, and data from a request being deserialised.
var shiroReferences = []string{
	"https://nvd.nist.gov/vuln/detail/CVE-2016-4437",
	"https://cwe.mitre.org/data/definitions/321.html",
	"https://cwe.mitre.org/data/definitions/502.html",
}

func (shiroRememberMe) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	// An answer that was already a refusal is not a comparison point: a cookie the
	// site itself rejected says nothing about the key it accepts.
	if t.Response.Status >= 400 {
		return nil
	}

	value, fromRequest := shiroRememberedCookie(t)
	if value == "" {
		return nil
	}
	data, ok := shiroCiphertext(value)
	if !ok {
		// Not a Base64 blob of at least two AES blocks: some other application's
		// cookie, or a token. There is nothing to decrypt.
		return nil
	}
	hit, ok := shiroOpen(data)
	if !ok {
		return nil
	}

	// The control the whole judgement rests on. The same ciphertext, decrypted with
	// a key one bit away from the one that opened it, must not produce a valid
	// structure. If it does, the structure test is not discriminating — the bytes
	// are the kind that parse under anything — and neither is the finding.
	if decoy, ok := shiroDecrypt(data, shiroDecoyKey(hit.key), hit.envelope); ok {
		if _, valid := shiroSerializedHead(decoy); valid {
			return nil
		}
	}

	// One rememberMe cookie is one answer, and that cookie travels with every request the
	// crawl makes. Asking the host to decrypt a re-sealed copy of it is asked once: the
	// same cookie cannot answer differently on a second page, and the finding is
	// deduplicated to the host in any case. A page that does not ask returns here rather
	// than reporting without the live half, because otherwise a later page would restate a
	// finding the asking page had already withdrawn.
	if !c.HostOnce(t.Request.Hostname(), "shiro-default-key") {
		return nil
	}
	answer := shiroConfirm(ctx, c, t, hit)
	if answer.live == shiroLiveContradicted {
		// The site refused a cookie re-sealed under the key that opened the value it
		// issued. Whatever the offline test recovered, that key is not the one this
		// installation decrypts with — the value did not come from here, or the
		// envelope is not the one it writes — and reporting it would be reporting a
		// key this target does not use.
		return nil
	}

	f := checks.NewFinding(shiroRememberMe{}, t, shiroTitleKey, shiroDescKey, shiroFixKey)
	f.Severity = finding.SeverityCritical
	f.Confidence = finding.ConfidenceFirm
	f.Param = "cookie:" + shiroCookieName
	f.CWE = "CWE-321"
	f.References = shiroReferences
	// One cookie, one finding: the crawl hands the same cookie over with every page.
	f.DedupHostOnly = true
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)

	// The evidence request has to be the one that carried the bytes the finding
	// names. The value the site issued is in the request when the site sent it
	// there; the re-sealed probe carries its own.
	f.Evidence.Request = t.Request.Raw()
	if fromRequest {
		f.Payload = value
	}
	if answer.request != nil {
		f.Evidence.Request = answer.request.Raw()
		f.Payload = answer.value
	}

	f.Evidence.Matches = []string{
		"the " + shiroCookieName + " cookie decrypted under the published key " + hit.keyText +
			" (" + shiroCipherLabel(hit) + ")",
		"the plaintext is a Java serialisation stream: STREAM_MAGIC 0xaced, version 5, a " +
			"serialised object of " + shiroClassName(hit.class),
		"every other key in the list, and a key one bit away from the one that opened it, " +
			"produced no valid structure from the same bytes",
	}
	switch answer.live {
	case shiroLiveConfirmed:
		f.Confidence = finding.ConfidenceCertain
		f.Evidence.Matches = append(f.Evidence.Matches,
			"re-sealed under that key the site answered as it did for the cookie it issued, and "+
				"refused the same bytes under a key one bit off")
	case shiroLiveInert:
		f.Evidence.Matches = append(f.Evidence.Matches,
			"the site answered the re-sealed cookie and a wrongly-keyed one alike, so this address "+
				"does not consult it; the key comes from the cookie the site itself issued")
	}
	f.Evidence.Diff = "decrypted plaintext, first bytes: " +
		hex.EncodeToString(hit.plain[:min(len(hit.plain), 32)])

	return []*finding.Finding{f}
}

// shiroClassName renders the class the stream names, for a reader who wants to
// see that it is a remembered identity rather than any serialised object.
func shiroClassName(class string) string {
	if class == "" {
		return "a class the stream does not name"
	}
	return class
}

// shiroCipherLabel names the cipher that opened the cookie, e.g. "AES-128-CBC".
func shiroCipherLabel(hit shiroHit) string {
	return "AES-" + strconv.Itoa(len(hit.key)*8) + "-" + hit.envelope.mode
}

// shiroRememberedCookie returns the rememberMe value the traffic carries and
// whether the request itself sent it.
//
// The request comes first because it is what the site was actually given. A
// response that sets the cookie is the other place a run learns it: an
// application issues rememberMe at login, and the page behind the login is where
// the crawl first sees it.
func shiroRememberedCookie(t *checks.Target) (value string, fromRequest bool) {
	if t.Request != nil {
		if v, ok := shiroCookiePair(t.Request.Header.Get("Cookie")); ok && !shiroCookieCleared(v) {
			return v, true
		}
	}
	if t.Response != nil {
		for _, field := range t.Response.Header.Values("Set-Cookie") {
			name, v, ok := shiroSetCookiePair(field)
			if ok && strings.EqualFold(name, shiroCookieName) && !shiroCookieCleared(v) {
				return v, false
			}
		}
	}
	return "", false
}

// shiroCookieCleared reports whether a value is one there is nothing to decrypt in.
func shiroCookieCleared(value string) bool {
	return value == "" || strings.EqualFold(value, shiroCookieDeleted)
}

// shiroCookiePair finds the rememberMe pair inside a Cookie header.
func shiroCookiePair(header string) (string, bool) {
	for _, part := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), shiroCookieName) {
			return strings.Trim(strings.TrimSpace(value), `"`), true
		}
	}
	return "", false
}

// shiroSetCookiePair splits a Set-Cookie field into its name and value.
func shiroSetCookiePair(field string) (name, value string, ok bool) {
	first, _, _ := strings.Cut(field, ";")
	rawName, rawValue, found := strings.Cut(strings.TrimSpace(first), "=")
	if !found {
		return "", "", false
	}
	return strings.TrimSpace(rawName), strings.Trim(strings.TrimSpace(rawValue), `"`), true
}

// shiroCiphertext turns a cookie value into the bytes Shiro would decrypt.
//
// The value is Base64 in the standard alphabet. Two other spellings reach a
// scanner and are tried here: a percent-escaped value, which is how a value that
// travelled through a cookie-header rewriter arrives, and one with the padding
// stripped, which is what some containers do to a Set-Cookie value.
func shiroCiphertext(value string) ([]byte, bool) {
	candidates := []string{value}
	if unescaped, err := url.QueryUnescape(value); err == nil && unescaped != value {
		candidates = append(candidates, unescaped)
	}
	for _, candidate := range candidates {
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
		} {
			// Two AES blocks is the shortest value that can carry a vector and a
			// ciphertext; anything shorter is a different kind of cookie.
			if data, err := encoding.DecodeString(candidate); err == nil && len(data) >= 2*aes.BlockSize {
				return data, true
			}
		}
	}
	return nil, false
}

// shiroOpen tries every published key against the cookie, in each envelope shape,
// and returns the first that decrypts into something that is genuinely a Java
// serialisation stream.
func shiroOpen(data []byte) (shiroHit, bool) {
	for _, encoded := range shiroDefaultKeys {
		key, ok := shiroKeyBytes(encoded)
		if !ok {
			continue
		}
		for _, envelope := range shiroEnvelopes {
			plain, ok := shiroDecrypt(data, key, envelope)
			if !ok {
				continue
			}
			class, ok := shiroSerializedHead(plain)
			if !ok {
				continue
			}
			return shiroHit{
				key:      key,
				keyText:  encoded,
				envelope: envelope,
				plain:    plain,
				class:    class,
			}, true
		}
	}
	return shiroHit{}, false
}

// shiroKeyBytes decodes one published key, refusing anything that is not a legal
// AES key length.
func shiroKeyBytes(encoded string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		key, err := encoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		switch len(key) {
		case 16, 24, 32:
			return key, true
		}
		return nil, false
	}
	return nil, false
}

// shiroDecrypt opens one envelope with one key.
func shiroDecrypt(data, key []byte, envelope shiroEnvelope) ([]byte, bool) {
	if envelope.iv <= 0 || len(data) <= envelope.iv+aes.BlockSize {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	iv, body := data[:envelope.iv], data[envelope.iv:]

	if envelope.mode == "GCM" {
		aead, err := cipher.NewGCMWithNonceSize(block, envelope.iv)
		if err != nil {
			return nil, false
		}
		// The tag is the last sixteen bytes and Open checks it, so a wrong key or a
		// wrong shape fails here rather than producing bytes to reason about.
		plain, err := aead.Open(nil, iv, body, nil)
		if err != nil {
			return nil, false
		}
		return plain, true
	}

	if len(body)%aes.BlockSize != 0 {
		return nil, false
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
	return shiroUnpad(plain)
}

// shiroUnpad removes PKCS#7 padding, refusing any padding that does not describe
// the buffer exactly.
//
// The strictness is the point. A lenient unpad — take the last byte, cut that many
// bytes off — accepts roughly one wrong key in 256, because a random final byte
// lands on a plausible length that often. Combined with the header test below it
// would still be rare, but rare is not the same as impossible, and this check has
// exactly one way to be wrong.
func shiroUnpad(plain []byte) ([]byte, bool) {
	if len(plain) == 0 || len(plain)%aes.BlockSize != 0 {
		return nil, false
	}
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(plain) {
		return nil, false
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, false
		}
	}
	return plain[:len(plain)-pad], true
}

// Type codes from the Java object serialisation stream format, which is what
// ObjectOutputStream writes and what a rememberMe cookie carries.
const shiroTCObject = 0x73
const shiroTCClassDesc = 0x72
const shiroTCProxyClassDesc = 0x7D

// shiroSerializedHead reports whether plain begins a Java serialisation stream
// holding an object, and names the class its descriptor gives.
//
// This is where the check decides that the key it holds really opened the cookie,
// so it is written to recognise a structure rather than to guess at one: the four
// magic bytes, a version, an object, and a class descriptor whose name is a
// printable fully-qualified class followed by its serial version UID. A wrong key
// produces random bytes, and random bytes are not a stream — they miss on the
// first of the five fixed values long before the name is read.
//
// What it does not do is the whole stream. Reading the rest means following
// references and class descriptors into an object graph, and doing that to bytes
// from a request is exactly the mistake this check exists to report. The head is
// all that is needed to name the key, and it is all that is read.
func shiroSerializedHead(plain []byte) (string, bool) {
	// STREAM_MAGIC 0xaced and STREAM_VERSION 5, big-endian, then the object that was
	// written.
	if len(plain) < 12 {
		return "", false
	}
	if plain[0] != 0xAC || plain[1] != 0xED || plain[2] != 0x00 || plain[3] != 0x05 {
		return "", false
	}
	if plain[4] != shiroTCObject {
		return "", false
	}
	switch plain[5] {
	case shiroTCClassDesc:
		return shiroClassDescName(plain[6:])
	case shiroTCProxyClassDesc:
		// A dynamic proxy names no class of its own: the interface count follows and,
		// after it, interface names. A body that begins this way is a serialised
		// object either way, and the count is the only field worth checking.
		if len(plain[6:]) < 4 {
			return "", false
		}
		return "", true
	}
	return "", false
}

// shiroClassDescName reads the class name out of the class descriptor at the start
// of b: a two-byte length, the name in modified UTF-8, then the eight-byte serial
// version UID.
func shiroClassDescName(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	size := int(binary.BigEndian.Uint16(b[:2]))
	if size == 0 || size > 255 || len(b) < 2+size+8 {
		return "", false
	}
	name := b[2 : 2+size]
	dotted := false
	for _, c := range name {
		// A Java class name is a dotted identifier: printable ASCII with no spaces.
		if c < 0x21 || c > 0x7E {
			return "", false
		}
		if c == '.' {
			dotted = true
		}
	}
	if !dotted {
		return "", false
	}
	return string(name), true
}

// shiroDecoyKey returns a key that differs from one that opened the cookie by a
// single bit, as the control's key.
//
// Changing one bit is the smallest change that makes it a different AES key, so
// the control differs from the probe in exactly one thing — the key — and the
// comparison is about nothing else.
func shiroDecoyKey(key []byte) []byte {
	out := make([]byte, len(key))
	copy(out, key)
	if len(out) > 0 {
		out[len(out)-1] ^= 0x01
	}
	return out
}

// shiroAnswer is the live half's verdict together with the probe that produced it,
// so the finding can carry the request it is talking about.
type shiroAnswer struct {
	live    shiroLive
	request *httpmsg.Request
	value   string
}

// shiroLive is what the live half learned, if it was asked at all.
type shiroLive int

const (
	// shiroLiveNotAsked: the confirmation could not be sent — a request failed or the
	// value could not be re-sealed — so the offline half is all there is.
	shiroLiveNotAsked shiroLive = iota
	// shiroLiveConfirmed: the cookie re-sealed under the recovered key was answered
	// like the original, and the same bytes under a different key were refused.
	shiroLiveConfirmed
	// shiroLiveInert: the site answered the re-sealed cookie and the wrongly-keyed
	// one alike, so this address does not consult the cookie at all.
	shiroLiveInert
	// shiroLiveContradicted: the site refused the cookie re-sealed under the key that
	// opened the value it issued.
	shiroLiveContradicted
)

// shiroConfirm asks the target whether the recovered key is the one it decrypts
// with, by putting the object the site itself stored back in the cookie.
//
// Two requests answer it. The first is a faithful re-seal — the same plaintext, the
// same envelope, a fresh initialization vector — which is the bytes the application
// itself would have written, so a target that reads this cookie as a decryption
// input answers it exactly as it answered the original. The second is the same
// ciphertext under a key one bit off.
//
// The three outcomes are kept apart because they mean different things. Accepted
// and then refused is the key, confirmed. Answered alike both times is a site that
// never looks at the cookie, so the live request proved nothing and the offline
// result stands on its own. Refused the first time is a site that does not accept
// cookies under the recovered key, and then no finding is warranted at all.
func shiroConfirm(ctx context.Context, c *checks.Context, t *checks.Target, hit shiroHit) shiroAnswer {
	probe, ok := shiroSeal(hit.plain, hit.key, hit.envelope)
	if !ok {
		return shiroAnswer{}
	}
	probeRequest := shiroWithCookie(t.Request, probe)
	response, err := c.Do(ctx, probeRequest)
	if err != nil || response == nil {
		return shiroAnswer{}
	}
	answer := shiroAnswer{request: probeRequest, value: probe}
	if shiroRefusedCookie(response, t.Response) {
		answer.live = shiroLiveContradicted
		return answer
	}

	decoy, ok := shiroSeal(hit.plain, shiroDecoyKey(hit.key), hit.envelope)
	if !ok {
		return answer
	}
	control, err := c.Do(ctx, shiroWithCookie(t.Request, decoy))
	if err != nil || control == nil {
		return answer
	}
	if shiroRefusedCookie(control, t.Response) {
		answer.live = shiroLiveConfirmed
		return answer
	}
	answer.live = shiroLiveInert
	return answer
}

// shiroRefusedCookie reports whether a response says the cookie was not accepted:
// the deletion marker Shiro writes when it cannot decrypt or deserialise what it
// was given, or an answer that is not the page the original cookie produced.
func shiroRefusedCookie(response, baseline *httpmsg.Response) bool {
	if response == nil {
		return true
	}
	for _, field := range response.Header.Values("Set-Cookie") {
		name, value, ok := shiroSetCookiePair(field)
		if ok && strings.EqualFold(name, shiroCookieName) &&
			strings.EqualFold(value, shiroCookieDeleted) {
			return true
		}
	}
	return !shiroSamePage(response, baseline)
}

// shiroSamePage reports whether two responses are the same answer: the same status
// and bodies of comparable size.
//
// No meaning is read into either body. A remembered page and an anonymous one
// differ in what they say and not in how much they say, so size is the wrong
// instrument for that difference — which is why the deletion marker, and not the
// body, is what the confirmation rests on. This is only here to catch the case the
// marker cannot: a refusal that is a redirect or an error page rather than Shiro's
// own cookie.
func shiroSamePage(response, baseline *httpmsg.Response) bool {
	if response == nil || baseline == nil {
		return false
	}
	if response.Status != baseline.Status {
		return false
	}
	want, got := len(baseline.Body), len(response.Body)
	if want == 0 {
		return got == 0
	}
	ratio := float64(got) / float64(want)
	return ratio >= 0.5 && ratio <= 2.0
}

// shiroWithCookie returns the request with its rememberMe cookie set to value,
// keeping every other cookie it carried.
func shiroWithCookie(req *httpmsg.Request, value string) *httpmsg.Request {
	out := req.Clone()
	header := out.Header.Get("Cookie")
	if header == "" {
		out.Header.Set("Cookie", shiroCookieName+"="+value)
		return out
	}
	parts := strings.Split(header, ";")
	for i, part := range parts {
		name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), shiroCookieName) {
			continue
		}
		parts[i] = " " + shiroCookieName + "=" + value
		out.Header.Set("Cookie", strings.TrimSpace(strings.Join(parts, ";")))
		return out
	}
	out.Header.Set("Cookie", header+"; "+shiroCookieName+"="+value)
	return out
}

// shiroSeal puts plain back inside the envelope it came out of, under key, with a
// fresh initialization vector.
func shiroSeal(plain, key []byte, envelope shiroEnvelope) (string, bool) {
	if envelope.iv <= 0 {
		return "", false
	}
	iv := make([]byte, envelope.iv)
	if _, err := rand.Read(iv); err != nil {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	if envelope.mode == "GCM" {
		aead, err := cipher.NewGCMWithNonceSize(block, envelope.iv)
		if err != nil {
			return "", false
		}
		// dst is the vector itself: Seal appends the ciphertext and the tag to it,
		// which is the order Shiro writes.
		return base64.StdEncoding.EncodeToString(aead.Seal(iv, iv, plain, nil)), true
	}
	padded := shiroPad(plain)
	sealed := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(sealed, padded)
	return base64.StdEncoding.EncodeToString(append(iv, sealed...)), true
}

// shiroPad adds PKCS#7 padding, the inverse of shiroUnpad.
func shiroPad(plain []byte) []byte {
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	out := make([]byte, len(plain)+pad)
	copy(out, plain)
	for i := len(plain); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}
