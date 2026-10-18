package active

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// shiroByteCase is one named input for the table tests below.
type shiroByteCase struct {
	name  string
	input []byte
}

// shiroStringCase is one named value for the table tests below.
type shiroStringCase struct {
	name  string
	value string
}

// shiroFixtureClass is what a Shiro rememberMe cookie holds: the identities the
// subject was remembered by, per realm.
const shiroFixtureClass = "org.apache.shiro.subject.SimplePrincipalCollection"

// shiroFixture writes the head of that stream out byte by byte.
//
// It is built here rather than captured from a deployment, because what a test needs
// is the shape of a cookie and not someone's: STREAM_MAGIC, the version, a TC_OBJECT
// and the class descriptor of the remembered principals. A captured value would also
// carry whatever chain its author put in it, which is the one thing this check must
// never need.
func shiroFixture(class string) []byte {
	// STREAM_MAGIC and STREAM_VERSION, then a TC_OBJECT carrying a TC_CLASSDESC.
	out := []byte{0xAC, 0xED, 0x00, 0x05, shiroTCObject, shiroTCClassDesc}
	// The class name, its length first, then the eight-byte serial version UID.
	out = append(out, shiroShort(len(class))...)
	out = append(out, class...)
	out = append(out, 0xD3, 0x7C, 0x6C, 0x0D, 0x1A, 0x5E, 0xA1, 0x62)
	// SC_SERIALIZABLE, one field of object type named realmPrincipals, that field's
	// type as TC_NULL, the class annotation end and a null superclass.
	out = append(out, 0x02)
	out = append(out, shiroShort(1)...)
	out = append(out, 'L')
	out = append(out, shiroShort(len("realmPrincipals"))...)
	out = append(out, "realmPrincipals"...)
	out = append(out, 0x70, 0x78, 0x70)
	// The field's data, which the check never reads.
	return append(out, bytes.Repeat([]byte{'p'}, 32)...)
}

// shiroShort writes a big-endian two-byte length.
func shiroShort(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

// shiroSite stands in for an application running Apache Shiro: it decrypts the
// rememberMe cookie with the key it was configured with, the way
// CookieRememberMeManager does, and answers either the page behind the remembered
// identity or the refusal Shiro produces when it cannot read the cookie.
type shiroSite struct {
	key      []byte
	envelope shiroEnvelope
	// blind answers every request with the remembered page without looking at the
	// cookie, which is what a site that never consults it looks like from outside.
	blind bool
	// deaf refuses every cookie, which is what an installation whose key is not one of
	// the published ones says to a cookie that was written with one.
	deaf bool
}

func (s *shiroSite) remembered(w http.ResponseWriter) {
	fmt.Fprint(w, "<html><body><h1>Welcome back, alice</h1><p>"+
		strings.Repeat("orders ", 40)+"</p></body></html>")
}

func (s *shiroSite) refuse(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: shiroCookieName, Value: shiroCookieDeleted, Path: "/"})
	fmt.Fprint(w, "<html><body>Please sign in</body></html>")
}

func (s *shiroSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.blind {
		s.remembered(w)
		return
	}
	cookie, err := r.Cookie(shiroCookieName)
	if err != nil || s.deaf {
		s.refuse(w)
		return
	}
	plain, ok := shiroTestOpen(cookie.Value, s.key, s.envelope)
	if !ok || len(plain) < 4 || !bytes.HasPrefix(plain, []byte{0xAC, 0xED}) {
		s.refuse(w)
		return
	}
	s.remembered(w)
}

// shiroTestKey decodes one of the published keys, failing the test when the entry is
// not a 16-byte AES key — which is a defect in the list, not in the target.
func shiroTestKey(t *testing.T, encoded string) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 16 {
		t.Fatalf("published key %q is not a 16-byte AES key: %v", encoded, err)
	}
	return key
}

// shiroTestRandomKey returns a key that is deliberately not on the published list.
func shiroTestRandomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random key: %v", err)
	}
	return key
}

// shiroTestSeal writes plain into an envelope the way the JVM behind Shiro would.
//
// It is a second implementation of the protocol on purpose: the check's own
// decryption is then measured against something that is not itself.
func shiroTestSeal(t *testing.T, plain, key []byte, envelope shiroEnvelope) string {
	t.Helper()
	iv := make([]byte, envelope.iv)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("random iv: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	if envelope.mode == "GCM" {
		aead, err := cipher.NewGCMWithNonceSize(block, envelope.iv)
		if err != nil {
			t.Fatalf("gcm: %v", err)
		}
		return base64.StdEncoding.EncodeToString(aead.Seal(iv, iv, plain, nil))
	}
	padded := append([]byte(nil), plain...)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < pad; i++ {
		padded = append(padded, byte(pad))
	}
	sealed := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(sealed, padded)
	return base64.StdEncoding.EncodeToString(append(iv, sealed...))
}

// shiroTestOpen decrypts a rememberMe value the way the JVM behind Shiro would.
func shiroTestOpen(value string, key []byte, envelope shiroEnvelope) ([]byte, bool) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) <= envelope.iv {
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
		plain, err := aead.Open(nil, iv, body, nil)
		if err != nil {
			return nil, false
		}
		return plain, true
	}
	if len(body) == 0 || len(body)%aes.BlockSize != 0 {
		return nil, false
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
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

// shiroRun fetches the target as a browser holding cookie would, then runs the check
// against that exchange the way the scanner does.
func shiroRun(t *testing.T, server *httptest.Server, cookie string) ([]*finding.Finding, *checks.Target) {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/account")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if cookie != "" {
		request.Header.Set("Cookie", "JSESSIONID=abc123; "+shiroCookieName+"="+cookie)
	}
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	target := &checks.Target{Request: request, Response: baseline}
	findings := runRequestLevel(t, h, shiroRememberMe{}, target)
	checkEvidenceCarriesPayload(t, findings)
	return findings, target
}

// TestShiroFiresOnACookieUnderADefaultKey is the whole finding: the site issued a
// cookie, a published key opens it, and offering it back re-sealed under that key is
// answered while the same bytes under a key one bit off are refused.
func TestShiroFiresOnACookieUnderADefaultKey(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[0])
	site := &shiroSite{key: key, envelope: shiroEnvelopes[0]}
	server := httptest.NewServer(site)
	defer server.Close()

	cookie := shiroTestSeal(t, shiroFixture(shiroFixtureClass), key, site.envelope)
	findings, _ := shiroRun(t, server, cookie)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.CheckID != "shiro-default-key" {
		t.Errorf("CheckID = %q", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain: the site answered the re-sealed cookie and "+
			"refused the wrongly-keyed one", f.Confidence)
	}
	if f.CWE != "CWE-321" {
		t.Errorf("CWE = %q, want CWE-321", f.CWE)
	}
	evidence := strings.Join(f.Evidence.Matches, " ")
	if !strings.Contains(evidence, shiroDefaultKeys[0]) {
		t.Errorf("the evidence does not name the key that opened the cookie: %v", f.Evidence.Matches)
	}
	if !strings.Contains(evidence, shiroFixtureClass) {
		t.Errorf("the evidence does not name the class it decrypted: %v", f.Evidence.Matches)
	}
	if !strings.Contains(evidence, "AES-128-CBC") {
		t.Errorf("the evidence does not name the envelope: %v", f.Evidence.Matches)
	}
}

// TestShiroFiresOnTheGCMEnvelope covers a configuration that selects GCM, where the
// value is vector, ciphertext and authentication tag rather than padded blocks.
func TestShiroFiresOnTheGCMEnvelope(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[4])
	site := &shiroSite{key: key, envelope: shiroEnvelopes[1]}
	server := httptest.NewServer(site)
	defer server.Close()

	cookie := shiroTestSeal(t, shiroFixture(shiroFixtureClass), key, site.envelope)
	findings, _ := shiroRun(t, server, cookie)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one: %+v", len(findings), findings)
	}
	if findings[0].Confidence != finding.ConfidenceCertain {
		t.Errorf("confidence = %q, want certain", findings[0].Confidence)
	}
}

// TestShiroStaysQuietWhenTheKeyIsNotPublished is the case the check exists to leave
// alone: the site uses a key of its own, so no published key opens the cookie. The
// site still refuses cookies it cannot read, and that refusal is not a finding.
func TestShiroStaysQuietWhenTheKeyIsNotPublished(t *testing.T) {
	key := shiroTestRandomKey(t)
	site := &shiroSite{key: key, envelope: shiroEnvelopes[0]}
	server := httptest.NewServer(site)
	defer server.Close()

	cookie := shiroTestSeal(t, shiroFixture(shiroFixtureClass), key, site.envelope)
	findings, _ := shiroRun(t, server, cookie)

	if len(findings) != 0 {
		t.Errorf("a cookie no published key opens was reported: %+v", findings)
	}
}

// TestShiroDropsTheOfflineHitWhenTheTargetRefusesTheKey covers the cookie that came
// from somewhere else: it was written with a published key, but this installation
// answers the re-seal with its deletion marker, which says the key is not the one in
// use here. The offline decrypt alone would have reported it.
func TestShiroDropsTheOfflineHitWhenTheTargetRefusesTheKey(t *testing.T) {
	site := &shiroSite{key: shiroTestRandomKey(t), envelope: shiroEnvelopes[0], deaf: true}
	server := httptest.NewServer(site)
	defer server.Close()

	cookie := shiroTestSeal(t, shiroFixture(shiroFixtureClass),
		shiroTestKey(t, shiroDefaultKeys[1]), shiroEnvelopes[0])
	findings, _ := shiroRun(t, server, cookie)

	if len(findings) != 0 {
		t.Errorf("a key the target refused was reported: %+v", findings)
	}
}

// TestShiroReportsTheCookieAQuietSiteNeverReads covers the site that answers every
// request alike: it may consult the cookie elsewhere, and here it said nothing. The
// offline proof still stands, and the confidence says which half of the check it
// rests on.
func TestShiroReportsTheCookieAQuietSiteNeverReads(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[2])
	site := &shiroSite{key: key, envelope: shiroEnvelopes[0], blind: true}
	server := httptest.NewServer(site)
	defer server.Close()

	cookie := shiroTestSeal(t, shiroFixture(shiroFixtureClass), key, site.envelope)
	findings, _ := shiroRun(t, server, cookie)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one: %+v", len(findings), findings)
	}
	if findings[0].Confidence != finding.ConfidenceFirm {
		t.Errorf("confidence = %q, want firm: the live half could not separate the keys",
			findings[0].Confidence)
	}
}

// TestShiroIgnoresRequestsWithoutTheCookie: the check is about a cookie, and a
// request that carries none has nothing to decrypt.
func TestShiroIgnoresRequestsWithoutTheCookie(t *testing.T) {
	server := httptest.NewServer(&shiroSite{blind: true})
	defer server.Close()

	findings, _ := shiroRun(t, server, "")
	if len(findings) != 0 {
		t.Errorf("a request without a rememberMe cookie was reported: %+v", findings)
	}
}

// TestShiroReadsACookieTheResponseIssued covers the other place a run learns the
// value: an application sets rememberMe at login, and the page behind the login is
// where the crawl first sees it.
func TestShiroReadsACookieTheResponseIssued(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[5])
	envelope := shiroEnvelopes[0]
	cookie := shiroTestSeal(t, shiroFixture(shiroFixtureClass), key, envelope)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: shiroCookieName, Value: cookie, Path: "/"})
		fmt.Fprint(w, "<html><body><h1>Sign in</h1><p>"+strings.Repeat("login ", 40)+"</p></body></html>")
	}))
	defer server.Close()

	findings, _ := shiroRun(t, server, "")
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one: %+v", len(findings), findings)
	}
}

// TestShiroSerializedHeadAcceptsAStream pins the recognition the whole judgement
// rests on.
func TestShiroSerializedHeadAcceptsAStream(t *testing.T) {
	class, ok := shiroSerializedHead(shiroFixture(shiroFixtureClass))
	if !ok {
		t.Fatal("a Shiro stream was not recognised")
	}
	if class != shiroFixtureClass {
		t.Errorf("class = %q, want %q", class, shiroFixtureClass)
	}
}

// TestShiroSerializedHeadRejectsWhatIsNotAStream: each case is a way a wrong key
// could look like a right one if the test were looser.
func TestShiroSerializedHeadRejectsWhatIsNotAStream(t *testing.T) {
	stream := shiroFixture(shiroFixtureClass)
	withName := func(name string) []byte {
		out := []byte{0xAC, 0xED, 0x00, 0x05, shiroTCObject, shiroTCClassDesc}
		out = append(out, shiroShort(len(name))...)
		out = append(out, name...)
		return append(out, 0, 0, 0, 0, 0, 0, 0, 0)
	}

	for _, tc := range []shiroByteCase{
		{"nothing", nil},
		{"prose", []byte("hello world, this is not a stream")},
		{"json", []byte(`{"rememberMe":"nothing"}`)},
		{"wrong magic", append([]byte{0xAC, 0xEE}, stream[2:]...)},
		{"wrong version", append([]byte{0xAC, 0xED, 0x00, 0x04}, stream[4:]...)},
		{"a string, not an object", append([]byte{0xAC, 0xED, 0x00, 0x05, 0x74}, stream[5:]...)},
		{"truncated", stream[:7]},
		{"class without a dot", withName("SimplePrincipalCollection")},
		{"class with a space", withName("org.apache shiro")},
	} {
		if _, ok := shiroSerializedHead(tc.input); ok {
			t.Errorf("%s was read as a serialisation stream", tc.name)
		}
	}

	if _, ok := shiroSerializedHead(withName("a.B")); !ok {
		t.Error("a stream naming a dotted class was not recognised")
	}
}

// TestShiroUnpadRefusesHalfHeartedPadding: a lenient unpad accepts a random final
// byte as a length, which is exactly the luck a wrong key needs.
func TestShiroUnpadRefusesHalfHeartedPadding(t *testing.T) {
	block := func(pad ...byte) []byte {
		out := bytes.Repeat([]byte{'x'}, aes.BlockSize-len(pad))
		return append(out, pad...)
	}

	if out, ok := shiroUnpad(block(1)); !ok || len(out) != aes.BlockSize-1 {
		t.Errorf("padding of one byte was refused: %v %v", out, ok)
	}
	if out, ok := shiroUnpad(bytes.Repeat([]byte{0x10}, aes.BlockSize)); !ok || len(out) != 0 {
		t.Errorf("a full block of padding was refused: %v %v", out, ok)
	}
	for _, tc := range []shiroByteCase{
		{"a zero length", block(0)},
		{"longer than a block", block(0x11)},
		{"a disagreeing length", block(3, 3, 4)},
		{"not a whole block", bytes.Repeat([]byte{'x'}, aes.BlockSize-1)},
		{"empty", nil},
	} {
		if _, ok := shiroUnpad(tc.input); ok {
			t.Errorf("%s was accepted as padding", tc.name)
		}
	}
}

// TestShiroDecoyKeyChangesOneThing: the control has to differ from the probe in the
// key and in nothing else.
func TestShiroDecoyKeyChangesOneThing(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[0])
	decoy := shiroDecoyKey(key)

	if bytes.Equal(key, decoy) {
		t.Fatal("the control key is the probe key")
	}
	if len(decoy) != len(key) {
		t.Fatalf("the control key is %d bytes, the probe key %d", len(decoy), len(key))
	}
	changed := 0
	for i := range key {
		if key[i] != decoy[i] {
			changed++
		}
	}
	if changed != 1 {
		t.Errorf("the control key differs in %d bytes, want one", changed)
	}
}

// TestShiroCiphertextAcceptsTheSpellingsOfABase64Value: a value that travelled
// through a cookie rewriter or a container is the same value.
func TestShiroCiphertextAcceptsTheSpellingsOfABase64Value(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[0])
	sealed := shiroTestSeal(t, shiroFixture(shiroFixtureClass), key, shiroEnvelopes[0])

	for _, tc := range []shiroStringCase{
		{"standard", sealed},
		{"no padding", strings.TrimRight(sealed, "=")},
		{"escaped", url.QueryEscape(sealed)},
		{"url alphabet", strings.NewReplacer("+", "-", "/", "_").Replace(sealed)},
	} {
		if _, ok := shiroCiphertext(tc.value); !ok {
			t.Errorf("the %s spelling of a cookie value was not read", tc.name)
		}
	}
	for _, tc := range []shiroStringCase{
		{"empty", ""},
		{"deletion", shiroCookieDeleted},
		{"a token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"},
		{"one block only", "MDEyMzQ1Njc4OWFiY2RlZg=="},
	} {
		if _, ok := shiroCiphertext(tc.value); ok {
			t.Errorf("%s was read as a ciphertext", tc.name)
		}
	}
}

// TestShiroRememberedCookie covers where the value is looked for and the one value
// that is never a ciphertext.
func TestShiroRememberedCookie(t *testing.T) {
	sent := &checks.Target{
		Request: &httpmsg.Request{Header: httpmsg.NewHeader(
			httpmsg.KV{Name: "Cookie", Value: "a=1; rememberMe=cipher; b=2"})},
		Response: &httpmsg.Response{},
	}
	if value, fromRequest := shiroRememberedCookie(sent); value != "cipher" || !fromRequest {
		t.Errorf("the request's own cookie was read as (%q, %v)", value, fromRequest)
	}

	cleared := &checks.Target{
		Request: &httpmsg.Request{Header: httpmsg.NewHeader(
			httpmsg.KV{Name: "Cookie", Value: "rememberMe=" + shiroCookieDeleted})},
	}
	if value, _ := shiroRememberedCookie(cleared); value != "" {
		t.Errorf("the deletion marker was taken for a ciphertext: %q", value)
	}

	issued := &checks.Target{
		Request: &httpmsg.Request{},
		Response: &httpmsg.Response{Header: httpmsg.NewHeader(
			httpmsg.KV{Name: "Set-Cookie", Value: "rememberMe=" + shiroCookieDeleted + "; Path=/"},
			httpmsg.KV{Name: "Set-Cookie", Value: "rememberMe=cipher2; Path=/; HttpOnly"},
		)},
	}
	if value, fromRequest := shiroRememberedCookie(issued); value != "cipher2" || fromRequest {
		t.Errorf("the cookie the response issued was read as (%q, %v)", value, fromRequest)
	}
}

// TestShiroSealRoundTripsEveryEnvelope keeps the two directions of the envelope in
// step: what the live half seals, the offline half has to be able to open.
func TestShiroSealRoundTripsEveryEnvelope(t *testing.T) {
	key := shiroTestKey(t, shiroDefaultKeys[3])
	plain := shiroFixture(shiroFixtureClass)

	for _, envelope := range shiroEnvelopes {
		sealed, ok := shiroSeal(plain, key, envelope)
		if !ok {
			t.Fatalf("%s/%d: sealing failed", envelope.mode, envelope.iv)
		}
		data, ok := shiroCiphertext(sealed)
		if !ok {
			t.Fatalf("%s/%d: the sealed value was not read back as a ciphertext",
				envelope.mode, envelope.iv)
		}
		got, ok := shiroDecrypt(data, key, envelope)
		if !ok {
			t.Fatalf("%s/%d: the sealed value did not open", envelope.mode, envelope.iv)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("%s/%d: the round trip changed the plaintext", envelope.mode, envelope.iv)
		}
	}
}

// TestShiroIsRegistered keeps the registry honest about the check's declaration.
func TestShiroIsRegistered(t *testing.T) {
	check := checks.ByID("shiro-default-key")
	if check == nil {
		t.Fatal("shiro-default-key is not registered")
	}
	if !checks.IsRequestLevel(check) {
		t.Error("the check is about the request's cookie, so it has to be request level")
	}
	if check.Passive() {
		t.Error("the check sends a request, so it is not passive")
	}
	if checks.IsUnsafe(check) {
		t.Error("the check only offers the site's own cookie back; nothing needs consent")
	}
	for _, tc := range []shiroStringCase{
		{"title", string(check.TitleKey())},
		{"description", string(check.DescriptionKey())},
		{"remediation", string(check.RemediationKey())},
	} {
		if !strings.HasPrefix(tc.value, "check.shiro-default-key.") {
			t.Errorf("the %s key is %q, want a check.shiro-default-key.* key", tc.name, tc.value)
		}
	}
}
