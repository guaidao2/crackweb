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
//  2. Callback names are <correlation-id><random>.<server>: any name under it resolves
//     without a second registration, and an interaction is credited to this registration
//     when its label starts with the correlation id. That id is an xid — twenty characters
//     from 0123456789abcdefghijklmnopqrstuv — and one outside that alphabet is taken at
//     registration and then never credited, with no error anywhere to say so.
//  3. GET /poll?id=<correlation-id>&secret=<secret> returns the interactions, the records
//     encrypted with a fresh AES key that is itself returned RSA-encrypted and opened with
//     the private half of the registered key.
//
// The exchange is the reference client's (projectdiscovery/interactsh v1.4.1, pkg/client):
// this follows the formats it uses rather than an older version of them.
type Interactsh struct {
	server string
	token  string
	client *http.Client
	logf   func(format string, args ...any)

	private *rsa.PrivateKey
	corrID  string
	secret  string
	host    string // the deployment's host, which every callback name ends with

	mu       sync.Mutex
	tokens   map[string]bool
	seen     map[string][]checks.Interaction
	lastPoll time.Time

	// stop ends the keep-alive routine, and closing it twice would panic, so
	// Close guards it.
	stop     chan struct{}
	stopOnce sync.Once
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

// interactshKeepAliveInterval is how often the registration is renewed.
//
// A registration does not live as long as a scan: the deployment drops one it has
// not heard from, and a dropped registration answers every poll with an empty set,
// which is indistinguishable from a target that never called back. The reference
// client renews on this interval for the same reason, and re-registering an id the
// deployment already knows is answered as a no-op.
const interactshKeepAliveInterval = time.Minute

// The deployment's correlation id is an xid: twenty characters from this alphabet, and
// nothing else. A registration whose id steps outside it is accepted and then never matched
// to an interaction, which is a failure with no symptom at all — the poll answers, the data
// stays null, and the out-of-band checks quietly find nothing.
//
// The tail is random rather than the machine and process id that xid would encode: a
// callback carrying this id is observable by whoever resolves it, and the reference client
// avoids the same leak for the same reason.
const (
	interactshIDAlphabet    = "0123456789abcdefghijklmnopqrstuv"
	interactshIDLength      = 20
	interactshNonceAlphabet = "ybndrfg8ejkmcpqxot1uwisza345h769" // z-base-32, as the reference encodes the tail
	interactshNonceLength   = 13
	// interactshLabelLimit is what a DNS label holds; the id and the random tail are 33 of
	// those characters, and the caller's own name takes what is left.
	interactshLabelLimit = 63
)

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
		corrID:  randomFrom(interactshIDAlphabet, interactshIDLength),
		secret:  randomString(32),
		tokens:  map[string]bool{},
		seen:    map[string][]checks.Interaction{},
	}
	i.host = hostOf(base)
	i.stop = make(chan struct{})

	if err := i.register(context.Background()); err != nil {
		return nil, err
	}
	// A registration does not outlive a long scan on its own, and a registration the
	// deployment has dropped answers every poll with an empty set — the same silence
	// as a target that never called back. The reference client renews it, so this
	// does too.
	go i.keepAliveLoop()
	return i, nil
}

// keepAliveLoop renews the registration until Close is called.
//
// Re-registering an id the deployment already knows is a no-op. A renewal that
// fails is worth a note and nothing more: the next poll is what reports the channel
// being gone.
func (i *Interactsh) keepAliveLoop() {
	ticker := time.NewTicker(interactshKeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := i.register(context.Background()); err != nil {
				i.logf("oob: renew the interactsh registration at %s: %v", i.server, err)
			}
		case <-i.stop:
			return
		}
	}
}

// Close ends the session: the registration is given back to the deployment and the
// renewals stop, so a scan leaves nothing behind on a server that is not its own.
func (i *Interactsh) Close() error {
	var err error
	i.stopOnce.Do(func() {
		close(i.stop)
		err = i.deregister(context.Background())
	})
	return err
}

// deregister tells the deployment that the session is over.
func (i *Interactsh) deregister(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{
		"correlation-id": i.corrID,
		"secret-key":     i.secret,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, interactshTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, i.server+"/deregister", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if i.token != "" {
		request.Header.Set("Authorization", i.token)
	}

	response, err := i.client.Do(request)
	if err != nil {
		return fmt.Errorf("oob: deregister with interactsh at %s: %w", i.server, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
		return fmt.Errorf("oob: interactsh at %s refused the deregistration: %s %s",
			i.server, response.Status, strings.TrimSpace(string(payload)))
	}
	return nil
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
// The name is the handle, a dot, and the deployment: `<correlation-id><random>.<server>`.
// The correlation id has to lead it — the deployment matches an interaction to this
// registration by that prefix, and a label that carries anything in front of the id is
// accepted at registration and then never attributed, which is how this went unnoticed for
// so long. Everything after the leading id is ours: the random tail is what keeps two
// injections apart, and the caller's own name follows it for the reader.
func (i *Interactsh) NewURL(label string) (string, string) {
	token := i.corrID + randomFrom(interactshNonceAlphabet, interactshNonceLength)
	if extra := sanitiseLabel(label); extra != "" {
		if room := interactshLabelLimit - len(token); room > 0 {
			if len(extra) > room {
				extra = extra[:room]
			}
			token += extra
		}
	}
	name := token + "." + i.host

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

	var out []checks.Interaction

	// The encrypted half: the key comes back using the public half registered at
	// the start, and every record under data is opened with it.
	if polled.AESKey != "" && len(polled.Data) > 0 {
		key, err := i.decryptKey(polled.AESKey)
		if err != nil {
			return nil, err
		}
		for _, entry := range polled.Data {
			record, err := decryptRecord(key, entry)
			if err != nil {
				continue
			}
			out = append(out, record.interaction(entry))
		}
	}

	// The halves that are not encrypted at all: extra and tlddata arrive as plain
	// JSON, and they are not covered by the key that opens data. Reading only data
	// is how a callback that did arrive goes unseen, which is the same failure this
	// whole exchange had.
	for _, entry := range polled.Extra {
		if interaction, ok := plainInteraction(entry); ok {
			out = append(out, interaction)
		}
	}
	for _, entry := range polled.TLDData {
		if interaction, ok := plainInteraction(entry); ok {
			out = append(out, interaction)
		}
	}
	return out, nil
}

// plainInteraction reads one of the records the deployment does not encrypt.
func plainInteraction(entry string) (checks.Interaction, bool) {
	var record interactshRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(entry)), &record); err != nil {
		return checks.Interaction{}, false
	}
	return record.interaction(entry), true
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

// decryptRecord opens one entry: base64, a 16-byte IV, then AES-CTR.
//
// The IV is aes.BlockSize bytes and the cipher is CTR, which is how the reference
// client has written records since its first commit — there is no other spelling to
// allow for, and the plaintext is trimmed the way the reference trims it before the
// record is read.
func decryptRecord(key []byte, encoded string) (interactshRecord, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return interactshRecord{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return interactshRecord{}, err
	}
	if len(raw) <= aes.BlockSize {
		return interactshRecord{}, fmt.Errorf("oob: interaction record is too short")
	}
	iv, cipherText := raw[:aes.BlockSize], raw[aes.BlockSize:]
	plain := make([]byte, len(cipherText))
	cipher.NewCTR(block, iv).XORKeyStream(plain, cipherText)

	var record interactshRecord
	if err := json.Unmarshal(bytes.TrimRight(plain, " \t\r\n"), &record); err != nil {
		return interactshRecord{}, err
	}
	return record, nil
}

// interactshPoll is the poll response envelope.
//
// Only data is encrypted: extra carries records the deployment could not put under
// the session key, and tlddata the ones that arrived without a session at all, both
// as plain JSON.
type interactshPoll struct {
	Data    []string `json:"data"`
	Extra   []string `json:"extra"`
	AESKey  string   `json:"aes_key"`
	TLDData []string `json:"tlddata"`
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
	// The detail names the callback first, because that is what ties the record to the
	// injection that minted it, and then what was asked for. The name cannot be dropped in
	// favour of the request line: an HTTP callback carries the token in its Host header and a
	// DNS one has none in its first line, so a reader that kept only the line would lose the
	// only thing that says which injection this was.
	detail := r.FullID
	switch {
	case r.Protocol == "http" || r.RawRequest != "":
		if line, _, ok := strings.Cut(r.RawRequest, "\r\n"); ok && line != "" {
			detail = strings.TrimSpace(r.FullID + " " + line)
		} else if r.RawRequest != "" {
			detail = strings.TrimSpace(r.FullID + " " + r.RawRequest)
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
	return randomFrom(alphabet, n)
}

// randomFrom returns n characters drawn uniformly from an alphabet.
func randomFrom(alphabet string, n int) string {
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
