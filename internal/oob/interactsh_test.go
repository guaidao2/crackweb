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
	"strings"
	"sync"
	"testing"
)

// fakeInteractsh is as much of the deployment as the client talks to: it takes
// the registration, then serves poll responses encrypted the way the real one
// does, so that the RSA and AES halves of the client are exercised rather than
// assumed.
type fakeInteractsh struct {
	mu       sync.Mutex
	corrID   string
	records  []string
	requests []string
	server   *httptest.Server
	key      *rsa.PublicKey
	// refuse makes /register answer the way a deployment does when it will not
	// take the key.
	refuse bool
}

func newFakeInteractsh(t *testing.T) *fakeInteractsh {
	t.Helper()
	f := &fakeInteractsh{}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
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
		if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if key, ok := parsed.(*rsa.PublicKey); ok {
				f.key = key
			}
		}
		_, _ = w.Write([]byte(`{"message":"registration successful"}`))

	case "/poll":
		if f.corrID == "" || r.URL.Query().Get("id") != f.corrID {
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
		aead, err := cipher.NewGCM(block)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var entries []string
		for _, record := range f.records {
			nonce := make([]byte, aead.NonceSize())
			_, _ = rand.Read(nonce)
			sealed := aead.Seal(nil, nonce, []byte(record), nil)
			entries = append(entries, base64.StdEncoding.EncodeToString(append(nonce, sealed...)))
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
