package oob

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeInteractsh is as much of the deployment as the client talks to: it takes
// the registration, then serves poll responses encrypted the way the real one
// does, so that the RSA and AES halves of the client are exercised rather than
// assumed.
//
// It also copies the deployment's one silent behaviour: a correlation id outside
// the xid alphabet is accepted at registration and then credited with nothing.
// The tests that used to pass either way are the ones this exists for.
type fakeInteractsh struct {
	mu       sync.Mutex
	corrID   string
	records  []string
	requests []string
	server   *httptest.Server
	key      *rsa.PublicKey
	// attributable records whether the correlation id we were given is one the
	// deployment would ever match an interaction against.
	attributable bool
	// unattributed counts the callbacks we were told about but could not credit,
	// so a test can tell "no interactions" from "none of them ours".
	unattributed int
	// refuse makes /register answer the way a deployment does when it will not
	// take the key.
	refuse bool
	// legacyGCM writes records the way deployments before the IV change did.
	legacyGCM bool
}

// corrIDShape is the xid alphabet the deployment validates against.
var corrIDShape = regexp.MustCompile(`^[0-9a-v]{20}$`)

func newFakeInteractsh(t *testing.T) *fakeInteractsh {
	t.Helper()
	f := &fakeInteractsh{}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

// interact tells the fake that a callback arrived for a name, and credits it to the
// registration the way a deployment does — by the label's leading correlation id — so that a
// test can ask what the scan would have seen.
func (f *fakeInteractsh) interact(label, protocol, rawRequest string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.attributable || !strings.HasPrefix(label, f.corrID) {
		f.unattributed++
		return false
	}
	record := map[string]any{
		"protocol":       protocol,
		"full-id":        label,
		"remote-address": "203.0.113.7:4444",
	}
	if protocol == "dns" {
		record["q-type"] = "A"
	}
	if rawRequest != "" {
		record["raw-request"] = rawRequest
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return false
	}
	f.records = append(f.records, string(encoded))
	return true
}

// sealRecord writes one record the way the deployment writes it: a 16-byte IV and AES-CTR
// now, a 12-byte nonce and AES-GCM before that change. legacyGCM picks the older spelling so
// that a test can hold the client to reading both.
func sealRecord(block cipher.Block, record string, legacyGCM bool) []byte {
	if legacyGCM {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil
		}
		nonce := make([]byte, aead.NonceSize())
		_, _ = rand.Read(nonce)
		return append(nonce, aead.Seal(nil, nonce, []byte(record), nil)...)
	}
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	sealed := make([]byte, len(record))
	cipher.NewCTR(block, iv).XORKeyStream(sealed, []byte(record))
	return append(iv, sealed...)
}

func (f *fakeInteractsh) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.Path)

	switch r.URL.Path {
	case "/register":
		if f.refuse {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"could not read public Key"}`))
			return
		}
		var body struct {
			PublicKey     string `json:"public-key"`
			SecretKey     string `json:"secret-key"`
			CorrelationID string `json:"correlation-id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		// The deployment base64-decodes the field and reads the result as PEM,
		// so a client that sends anything else has to be caught here.
		raw, err := base64.StdEncoding.DecodeString(body.PublicKey)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"illegal base64 data"}`))
			return
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"failed to parse PEM block"}`))
			return
		}
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"could not read public Key"}`))
			return
		}
		f.corrID = body.CorrelationID
		f.attributable = corrIDShape.MatchString(body.CorrelationID)
		if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if key, ok := parsed.(*rsa.PublicKey); ok {
				f.key = key
			}
		}
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))

	case "/poll":
		// A deployment answers a poll for an id it cannot credit with an empty
		// set, which is the whole difficulty: this is not an error, and a scan
		// that reads it as one has no way to tell a quiet target from a broken
		// channel.
		if f.corrID == "" || !f.attributable || r.URL.Query().Get("id") != f.corrID {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		if len(f.records) == 0 {
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		// Encrypt with a fresh AES key and hand the key back RSA-encrypted, which
		// is the exchange the client has to undo.
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		block, err := aes.NewCipher(key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var entries []string
		for _, record := range f.records {
			entries = append(entries, base64.StdEncoding.EncodeToString(sealRecord(block, record, f.legacyGCM)))
		}
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, f.key, key, nil)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		payload, _ := json.Marshal(map[string]any{
			"data":    entries,
			"aes_key": base64.StdEncoding.EncodeToString(wrapped),
		})
		_, _ = w.Write(payload)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestInteractshRegistersAndDecrypts walks the whole exchange against a server
// that behaves the way a deployment does: the client registers a key, mints a
// name under the correlation id, and gets an interaction back that it could only
// read by undoing RSA and then AES.
func TestInteractshRegistersAndDecrypts(t *testing.T) {
	f := newFakeInteractsh(t)

	client, err := NewInteractsh(f.server.URL, "", nil)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	callback, token := client.NewURL("ssrf")
	if !strings.HasPrefix(callback, "http://") {
		t.Errorf("callback URL = %q, want an http URL", callback)
	}
	host := strings.TrimSuffix(strings.TrimPrefix(callback, "http://"), "/")
	if !strings.Contains(host, token) {
		t.Errorf("callback host %q does not carry the token %q", host, token)
	}
	// The label has to be the handle, and the handle has to lead with the
	// correlation id: anything in front of it and the deployment takes the
	// registration and credits it with nothing.
	if label, _, _ := strings.Cut(host, "."); label != token {
		t.Errorf("callback label %q is not the handle %q", label, token)
	}
	if !strings.HasPrefix(token, client.corrID) {
		t.Errorf("handle %q does not lead with the correlation id %q", token, client.corrID)
	}
	if !corrIDShape.MatchString(client.corrID) {
		t.Errorf("correlation id %q is outside the alphabet the deployment credits", client.corrID)
	}
	if !strings.Contains(host, client.corrID) {
		t.Errorf("callback host %q does not sit under the correlation id %q", host, client.corrID)
	}

	// Nothing has happened yet.
	if got := client.Poll(token); len(got) != 0 {
		t.Errorf("an interaction was reported before any was recorded: %v", got)
	}

	// Record one that names the token, and one that names nothing of ours.
	f.mu.Lock()
	f.records = []string{
		`{"protocol":"dns","full-id":"` + host + `","q-type":"A","remote-address":"203.0.113.9:5353"}`,
		`{"protocol":"http","full-id":"elsewhere.example","raw-request":"GET /nobody HTTP/1.1\r\nHost: elsewhere.example\r\n","remote-address":"203.0.113.10:5000"}`,
	}
	f.mu.Unlock()

	// The poll interval is a floor on network requests, not a cache lifetime for
	// the test: reset it so this call fetches.
	client.mu.Lock()
	client.lastPoll = client.lastPoll.Add(-2 * InteractshMinPollInterval)
	client.mu.Unlock()

	got := client.Poll(token)
	if len(got) != 1 {
		t.Fatalf("got %d interactions for the token, want 1: %v", len(got), got)
	}
	if got[0].Protocol != "dns" {
		t.Errorf("protocol = %q, want dns", got[0].Protocol)
	}
	if !strings.Contains(got[0].Detail, host) {
		t.Errorf("detail = %q, want it to name %q", got[0].Detail, host)
	}
	if got[0].RemoteAddr == "" {
		t.Error("the remote address was dropped")
	}
}

// TestInteractshCreditsAnInteractionToTheInjectionThatMintedIt walks the path the
// out-of-band checks depend on: a handle is minted, a callback arrives for it, and the
// record that comes back is credited to the injection that asked for it. Every part of it
// can fail silently against a real deployment — a handle whose label does not lead with the
// correlation id, or a record the client cannot decrypt, both end the same way, as a scan
// that found nothing.
func TestInteractshCreditsAnInteractionToTheInjectionThatMintedIt(t *testing.T) {
	f := newFakeInteractsh(t)
	client, err := NewInteractsh(f.server.URL, "", nil)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	callback, token := client.NewURL("ssrf")
	host := strings.TrimSuffix(strings.TrimPrefix(callback, "http://"), "/")
	if !f.interact(token, "http", "GET /ssrf HTTP/1.1\r\nHost: "+host+"\r\n") {
		t.Fatalf("the deployment would not credit a callback for %q", host)
	}

	client.mu.Lock()
	client.lastPoll = client.lastPoll.Add(-2 * InteractshMinPollInterval)
	client.mu.Unlock()

	got := client.Poll(token)
	if len(got) != 1 {
		t.Fatalf("got %d interactions for the handle, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0].Detail, token) {
		t.Errorf("detail = %q, want it to name the handle %q", got[0].Detail, token)
	}
	if !strings.Contains(got[0].Detail, "GET /ssrf") {
		t.Errorf("detail = %q, want it to keep what was asked for", got[0].Detail)
	}
	f.mu.Lock()
	unattributed := f.unattributed
	f.mu.Unlock()
	if unattributed != 0 {
		t.Errorf("%d callbacks went unattributed", unattributed)
	}
}

// TestInteractshStillReadsWhatAnOlderDeploymentWrites: the record format changed with the
// IV, and a client that reads only the current one goes quiet against a deployment that has
// not been updated — the same silent failure this fixed, facing the other way.
func TestInteractshStillReadsWhatAnOlderDeploymentWrites(t *testing.T) {
	f := newFakeInteractsh(t)
	f.legacyGCM = true
	client, err := NewInteractsh(f.server.URL, "", nil)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, token := client.NewURL("ssrf")
	if !f.interact(token, "dns", "") {
		t.Fatal("the deployment would not credit a callback")
	}

	client.mu.Lock()
	client.lastPoll = client.lastPoll.Add(-2 * InteractshMinPollInterval)
	client.mu.Unlock()

	if got := client.Poll(token); len(got) != 1 {
		t.Fatalf("got %d interactions against an older deployment, want 1: %v", len(got), got)
	}
}

// TestInteractshAgainstAPublicDeployment is the end-to-end check that cannot be faked: it
// registers with a real deployment, fetches a name it minted, and waits for the deployment
// to hand the interaction back. Off unless a deployment is named, because it sends traffic
// to somebody else's server.
func TestInteractshAgainstAPublicDeployment(t *testing.T) {
	server := os.Getenv("CRACKWEB_LIVE_INTERACTSH")
	if server == "" {
		t.Skip("set CRACKWEB_LIVE_INTERACTSH=<deployment> to exercise a real one")
	}

	client, err := NewInteractsh(server, "", t.Logf)
	if err != nil {
		t.Fatalf("registration with %s failed: %v", server, err)
	}
	callback, token := client.NewURL("live")
	response, err := http.Get(callback)
	if err != nil {
		t.Fatalf("fetching our own callback %s: %v", callback, err)
	}
	_ = response.Body.Close()
	t.Logf("fetched %s (%s)", callback, response.Status)

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if got := client.Poll(token); len(got) > 0 {
			t.Logf("the deployment credited %d interaction(s): %s", len(got), got[0].Detail)
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("no interaction came back for %s", callback)
}

// TestInteractshDoesNotPollMoreOftenThanTheFloor keeps the concurrency promise:
// checks call Poll in a loop, and every waiting check calling the deployment
// would be a request flood.
func TestInteractshDoesNotPollMoreOftenThanTheFloor(t *testing.T) {
	f := newFakeInteractsh(t)
	client, err := NewInteractsh(f.server.URL, "", nil)
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	_, token := client.NewURL("x")

	for i := 0; i < 20; i++ {
		client.Poll(token)
	}

	f.mu.Lock()
	polls := 0
	for _, path := range f.requests {
		if path == "/poll" {
			polls++
		}
	}
	f.mu.Unlock()
	if polls > 1 {
		t.Errorf("%d polls went out for 20 calls, want at most 1", polls)
	}
}

// TestInteractshReportsARefusedKey: a deployment that will not take the key has
// to fail at start-up, because a scan that runs on a channel which can never
// deliver is worse than one that does not run it at all.
func TestInteractshReportsARefusedKey(t *testing.T) {
	f := newFakeInteractsh(t)
	f.refuse = true

	if _, err := NewInteractsh(f.server.URL, "", nil); err == nil {
		t.Fatal("a refused registration was accepted")
	}
}

// TestInteractshRejectsAnEmptyServer: the provider is opt-in, so an empty
// address is a mistake worth naming rather than a silent no-op.
func TestInteractshRejectsAnEmptyServer(t *testing.T) {
	if _, err := NewInteractsh("   ", "", nil); err == nil {
		t.Fatal("an empty server address was accepted")
	}
}

// TestInteractshServerSpellingsBothWork: people type a host and they type a URL.
func TestInteractshServerSpellingsBothWork(t *testing.T) {
	for _, raw := range []string{"oob.example.com", "https://oob.example.com", "https://oob.example.com/"} {
		normalised, err := normaliseInteractshServer(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if normalised != "https://oob.example.com" {
			t.Errorf("%q normalised to %q", raw, normalised)
		}
	}
}
