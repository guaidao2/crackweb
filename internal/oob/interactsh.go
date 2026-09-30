package oob

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
)

// Interactsh is an interaction server that is somebody else's.
//
// The server crackweb starts itself works only when the target can reach it: on a
// laptop behind NAT, or against anything on the public internet, a target that
// runs `curl http://10.0.0.5:8081/...` gets nowhere, and the report that comes
// back says nothing about the payload. A public or self-hosted interactsh
// deployment removes that condition — the callback name resolves from anywhere,
// and the interactions are collected on the far side and fetched from here.
//
// The trade is that the traffic leaves the operator's machine, so it is never
// chosen for them: a server address has to be given explicitly, and without one
// out-of-band testing stays off.
//
// The protocol is the one projectdiscovery/interactsh speaks:
//
//  1. Generate an RSA key pair and register its public half, along with a
//     correlation id and a secret, at POST /register.
//  2. Callback names are <anything>.<correlation-id>.<server>, which the
//     deployment resolves for every name without a second registration.
//  3. GET /poll?id=<correlation-id>&secret=<secret> returns the interactions,
//     the records encrypted with a fresh AES key that is itself returned
//     RSA-encrypted.
//
// Nothing here is bespoke: it is the same exchange the reference client makes.
type Interactsh struct {
	server string
	token  string
	client *http.Client
	logf   func(format string, args ...any)

	private  *rsa.PrivateKey
	corrID   string
	secret   string
	suffix   string // <correlation-id>.<host>, the part every callback shares
	setupErr error

	mu       sync.Mutex
	tokens   map[string]bool
	seen     map[string][]checks.Interaction
	lastPoll time.Time
}

// InteractshMinPollInterval is the least time between two network polls.
//
// Checks call Poll in a loop until their own deadline, and several run at once,
// so without a floor every waiting check would turn into a poll per iteration
// and the deployment would see a request flood for an answer that only changes
// when somebody's DNS resolver gets round to it. Between polls the cached
// records are handed back instead.
const InteractshMinPollInterval = 2 * time.Second

// interactshTimeout bounds each exchange with the deployment.
const interactshTimeout = 20 * time.Second

// NewInteractsh registers with an interactsh deployment and returns a provider
// that mints callback names under it.
//
// The registration is done once here rather than lazily: a server that is
// unreachable, or that refuses the key, has to be reported before the scan
// starts, not discovered as a run of payloads that could never have been
// answered.
func NewInteractsh(server, authToken string, logf func(format string, args ...any)) (*Interactsh, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	base, err := normaliseInteractshServer(server)
	if err != nil {
		return nil, err
	}

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oob: generate the interactsh key: %w", err)
	}

	i := &Interactsh{
		server:  base,
		token:   authToken,
		client:  &http.Client{Timeout: interactshTimeout},
		logf:    logf,
		private: private,
		corrID:  randomString(20),
		secret:  randomString(32),
		tokens:  map[string]bool{},
		seen:    map[string][]checks.Interaction{},
	}
	i.suffix = i.corrID + "." + hostOf(base)

	if err := i.register(context.Background()); err != nil {
		return nil, err
	}
	return i, nil
}

// normaliseInteractshServer accepts a deployment as a bare host or a full URL
// and returns the URL form, so that both spellings people type work.
func normaliseInteractshServer(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", fmt.Errorf("oob: interactsh server address is empty")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	parsed, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("oob: interactsh server %q: %w", server, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("oob: interactsh server %q has no host", server)
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

// hostOf returns the host part of a URL that has already been parsed.
func hostOf(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// register sends the public key and the identifiers that the deployment will
// answer under.
func (i *Interactsh) register(ctx context.Context) error {
	der, err := x509.MarshalPKIXPublicKey(&i.private.PublicKey)
	if err != nil {
		return fmt.Errorf("oob: encode the interactsh public key: %w", err)
	}
	// The deployment base64-decodes the field and then reads the result as a PEM
	// block, so the PEM text is what gets base64-encoded.
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	body, err := json.Marshal(map[string]string{
		"public-key":     base64.StdEncoding.EncodeToString(publicPEM),
		"secret-key":     i.secret,
		"correlation-id": i.corrID,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, interactshTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, i.server+"/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if i.token != "" {
		request.Header.Set("Authorization", i.token)
	}

	response, err := i.client.Do(request)
	if err != nil {
		return fmt.Errorf("oob: register with interactsh at %s: %w", i.server, err)
	}
	defer response.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("oob: interactsh at %s refused registration: %s %s",
			i.server, response.Status, strings.TrimSpace(string(payload)))
	}
	// A 200 with an error body is how this deployment reports a rejected key.
	if bytes.Contains(payload, []byte(`"error"`)) {
		return fmt.Errorf("oob: interactsh at %s refused registration: %s",
			i.server, strings.TrimSpace(string(payload)))
	}
	return nil
}

// NewURL mints a callback address and the handle that identifies it.
//
// The handle is the leading label of the name: when an interaction comes back,
// the queried or requested name contains it, and that is what ties the record to
// the injection that asked for it.
func (i *Interactsh) NewURL(label string) (string, string) {
	token := "crackweb" + randomString(8)
	if label != "" {
		token = "crackweb" + sanitiseLabel(label) + randomString(6)
	}
	name := token + "." + i.suffix

	i.mu.Lock()
	i.tokens[token] = true
	i.mu.Unlock()

	return "http://" + name + "/", token
}

// sanitiseLabel keeps a label to the characters a DNS name allows.
func sanitiseLabel(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(label) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
		if b.Len() >= 8 {
			break
		}
	}
	return b.String()
}

// Poll reports the interactions recorded for a token.
//
// The network is asked at most once every InteractshMinPollInterval however
// often this is called, and in between the last answer is reused. Iterations
// that happen to poll return the cached records for every token, so a check that
// is waiting does not have to be the one that paid for the request.
func (i *Interactsh) Poll(token string) []checks.Interaction {
	if i == nil || token == "" {
		return nil
	}
	i.refresh()

	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]checks.Interaction(nil), i.seen[token]...)
}

// refresh fetches the records if enough time has passed, and files them under
// the tokens they mention.
func (i *Interactsh) refresh() {
	i.mu.Lock()
	if time.Since(i.lastPoll) < InteractshMinPollInterval {
		i.mu.Unlock()
		return
	}
	i.lastPoll = time.Now()
	i.mu.Unlock()

	records, err := i.fetch(context.Background())
	if err != nil {
		i.logf("oob: poll interactsh at %s: %v", i.server, err)
		return
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	for _, interaction := range records {
		haystack := strings.ToLower(interaction.Detail)
		for token := range i.tokens {
			if strings.Contains(haystack, strings.ToLower(token)) {
				i.seen[token] = append(i.seen[token], interaction)
			}
		}
	}
}

// fetch performs one /poll exchange and decrypts what comes back.
func (i *Interactsh) fetch(ctx context.Context) ([]checks.Interaction, error) {
	endpoint := i.server + "/poll?id=" + url.QueryEscape(i.corrID) + "&secret=" + url.QueryEscape(i.secret)

	ctx, cancel := context.WithTimeout(ctx, interactshTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if i.token != "" {
		request.Header.Set("Authorization", i.token)
	}

	response, err := i.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s", response.Status, strings.TrimSpace(string(payload)))
	}

	var polled interactshPoll
	if err := json.Unmarshal(payload, &polled); err != nil {
		return nil, fmt.Errorf("decode the poll response: %w", err)
	}
	if polled.AESKey == "" || len(polled.Data) == 0 {
		return nil, nil
	}

	key, err := i.decryptKey(polled.AESKey)
	if err != nil {
		return nil, err
	}

	var out []checks.Interaction
	for _, entry := range polled.Data {
		record, err := decryptRecord(key, entry)
		if err != nil {
			continue
		}
		out = append(out, record.interaction(entry))
	}
	return out, nil
}

// decryptKey recovers the AES key that the poll response carries, which is
// encrypted with the public key registered at the start.
func (i *Interactsh) decryptKey(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode the poll key: %w", err)
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, i.private, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt the poll key: %w", err)
	}
	return key, nil
}

// decryptRecord opens one entry: base64, a 12-byte nonce, then AES-GCM.
func decryptRecord(key []byte, encoded string) (interactshRecord, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return interactshRecord{}, err
	}
	if len(raw) < 13 {
		return interactshRecord{}, fmt.Errorf("oob: interaction record is too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return interactshRecord{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return interactshRecord{}, err
	}
	plain, err := aead.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return interactshRecord{}, err
	}

	var record interactshRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		return interactshRecord{}, err
	}
	return record, nil
}

// interactshPoll is the poll response envelope.
type interactshPoll struct {
	Data   []string `json:"data"`
	AESKey string   `json:"aes_key"`
}

// interactshRecord is one decrypted interaction, in the field names the
// deployment uses.
type interactshRecord struct {
	Protocol      string `json:"protocol"`
	FullID        string `json:"full-id"`
	UniqueID      string `json:"unique-id"`
	QueryType     string `json:"q-type"`
	RemoteAddress string `json:"remote-address"`
	RawRequest    string `json:"raw-request"`
	RawResponse   string `json:"raw-response"`
	SMTPFrom      string `json:"smtp-from"`
}

// interaction turns a record into what the checks are written against.
func (r interactshRecord) interaction(fallback string) checks.Interaction {
	detail := r.FullID
	switch {
	case r.Protocol == "http" || r.RawRequest != "":
		// The request line is what proves an HTTP callback, and it carries the
		// path the payload asked for.
		if line, _, ok := strings.Cut(r.RawRequest, "\r\n"); ok && line != "" {
			detail = line
		} else if r.RawRequest != "" {
			detail = r.RawRequest
		}
		if r.RawRequest == "" {
			detail = r.FullID
		}
	case r.QueryType != "":
		detail = r.FullID + " (" + r.QueryType + ")"
	}
	if detail == "" {
		detail = fallback
	}

	protocol := r.Protocol
	if protocol == "" {
		protocol = "dns"
	}
	remote := r.RemoteAddress
	if remote == "" {
		remote = r.SMTPFrom
	}

	return checks.Interaction{
		Protocol:   protocol,
		RemoteAddr: remote,
		Detail:     detail,
		At:         time.Now().Unix(),
	}
}

// randomString returns n characters from a lower-case alphabet that is safe in
// a DNS label.
func randomString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for idx := range out {
		out[idx] = alphabet[randomIndex(len(alphabet))]
	}
	return string(out)
}

// randomIndex returns a uniform index below n.
func randomIndex(n int) int {
	if n <= 1 {
		return 0
	}
	limit := 256 - (256 % n)
	for {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0
		}
		if int(b[0]) < limit {
			return int(b[0]) % n
		}
	}
}
