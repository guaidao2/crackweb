// Package oob is the out-of-band interaction server: the piece that makes
// invisible vulnerabilities visible.
//
// A blind SSRF, a blind command injection or a blind XXE produces no error, no
// change in the page and no delay. The only evidence it leaves is a connection
// the *target* makes to a host the attacker chose. crackweb therefore runs its
// own DNS and HTTP listeners, hands out unique callback names, and treats a
// callback as proof.
//
// The server can run inside a scan, or stand alone on a public host with
// --dns/--http so that targets which cannot reach the scanning machine can
// still call back.
package oob

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
)

// Default listen addresses.
const (
	DefaultHTTPAddr = "0.0.0.0:8081"
	DefaultDNSAddr  = "0.0.0.0:5353"
)

// tokenBytes is how much randomness goes into a callback name. Eight bytes is
// plenty to make collisions impossible within a scan, while keeping the name
// short enough to survive a filter that limits URL length.
const tokenBytes = 8

// Options configures the interaction server.
type Options struct {
	// HTTPAddr is where the HTTP callback listener binds.
	HTTPAddr string
	// DNSAddr is where the DNS callback listener binds.
	DNSAddr string
	// Domain is a delegated domain whose subdomains resolve to this server.
	// When set, callbacks use <token>.<domain>, which is what makes DNS
	// lookups observable at all.
	Domain string
	// PublicHost overrides the host used in generated URLs when no domain is
	// delegated, e.g. "203.0.113.10:8081".
	PublicHost string
	// Token is an operator-supplied secret mixed into every callback name, so
	// that two servers sharing a host do not mint colliding names.
	Token string
	// RebindFirst and RebindSecond are the two addresses a DNS-rebinding name
	// answers with: RebindFirst on the first A lookup, RebindSecond on every
	// lookup after it. They are what expresses a name whose address changes
	// between the validation a target does and the fetch it makes.
	//
	// RebindFirst defaults to a public documentation address (TEST-NET-3), so a
	// fetch that follows the first answer reaches nothing at all — which is what
	// makes a later connection back the proof that the *second* answer was used.
	// RebindSecond defaults to the address this server's HTTP listener is
	// reachable at when that is a loopback or private address, so the target can
	// connect to it; when the listener is only publicly reachable it falls back
	// to loopback, where a co-located target can still reach it.
	RebindFirst  net.IP
	RebindSecond net.IP
	// Logf receives status messages.
	Logf func(format string, args ...any)
}

// defaultRebindFirst is the address a rebinding name answers with first: a
// TEST-NET-3 documentation address, globally classified as unicast (so it passes
// a check that refuses private ranges) but routed nowhere (so a fetch that
// follows it reaches no listener of ours).
var defaultRebindFirst = net.IPv4(203, 0, 113, 1)

// rebindTTL is the TTL on a rebinding answer. Zero means "do not cache", so the
// second lookup reaches this server rather than being answered from a resolver's
// memory — which is the whole point of a rebinding name.
const rebindTTL = 0

// Event is one observed callback, for operator-facing output.
type Event struct {
	// Token is the callback name that was planted.
	Token string
	// Label says what the token was issued for.
	Label string
	// Protocol is "dns" or "http".
	Protocol string
	// RemoteAddr is where the interaction came from.
	RemoteAddr string
	// Detail carries protocol-specific evidence.
	Detail string
	// At is when it was seen.
	At time.Time
}

// Server is the interaction server.
type Server struct {
	opts Options

	httpServer *http.Server
	httpListen net.Listener
	dnsConn    *net.UDPConn

	mu           sync.Mutex
	interactions map[string][]checks.Interaction
	// events keeps every interaction, including ones already polled away, so a
	// standalone server can show its operator what is arriving.
	events []Event
	// labels record what a token was created for, so a report can say which
	// check a callback belongs to.
	labels map[string]string
	// rebinds marks the tokens that were minted as DNS-rebinding names, and
	// rebindHits counts how many A lookups each has answered so the answer can
	// change from the configured first address to the second.
	rebinds    map[string]bool
	rebindHits map[string]int

	closeOnce sync.Once
	done      chan struct{}
}

// New builds a server. Nothing is bound until Start.
func New(opts Options) *Server {
	if opts.HTTPAddr == "" {
		opts.HTTPAddr = DefaultHTTPAddr
	}
	if opts.DNSAddr == "" {
		opts.DNSAddr = DefaultDNSAddr
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &Server{
		opts:         opts,
		interactions: make(map[string][]checks.Interaction),
		labels:       make(map[string]string),
		rebinds:      make(map[string]bool),
		rebindHits:   make(map[string]int),
		done:         make(chan struct{}),
	}
}

// Start binds both listeners and serves until Close is called.
func (s *Server) Start(ctx context.Context) error {
	httpListener, err := net.Listen("tcp", s.opts.HTTPAddr)
	if err != nil {
		return fmt.Errorf("oob: listen for HTTP callbacks on %s: %w", s.opts.HTTPAddr, err)
	}
	s.httpListen = httpListener

	// Resolve the rebinding defaults now that the HTTP listener is bound: which
	// address a rebinding name should hand out second depends on where this
	// server can actually be reached.
	if s.opts.Domain != "" {
		if s.opts.RebindFirst == nil {
			s.opts.RebindFirst = defaultRebindFirst
		}
		if s.opts.RebindSecond == nil {
			s.opts.RebindSecond = s.defaultRebindSecond()
		}
	}

	// DNS is best-effort: a scan is still useful with only HTTP callbacks, and
	// port 53 or a delegated domain may be unavailable.
	dnsConn, dnsErr := net.ListenUDP("udp", mustResolveUDP(s.opts.DNSAddr))
	if dnsErr != nil {
		s.opts.Logf("oob: DNS listener unavailable on %s (%v); HTTP callbacks only", s.opts.DNSAddr, dnsErr)
	} else {
		s.dnsConn = dnsConn
	}

	s.httpServer = &http.Server{
		Handler:           http.HandlerFunc(s.handleHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	if s.dnsConn != nil {
		go s.serveDNS()
	}

	// The HTTP listener serves in the background, like the DNS one: the caller is a
	// scan that has to carry on with its checks, and only `crackweb oob` wants to
	// wait. A bind failure has already been reported by the Listen call above, so
	// returning here means the server is up.
	go func() {
		if err := s.httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			s.opts.Logf("oob: HTTP callbacks stopped: %v", err)
		}
	}()
	return nil
}

// Close stops both listeners.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		if s.httpServer != nil {
			err = s.httpServer.Close()
		}
		if s.dnsConn != nil {
			_ = s.dnsConn.Close()
		}
	})
	return err
}

// HTTPAddr returns the bound HTTP address, or the configured one before Start.
func (s *Server) HTTPAddr() string {
	if s.httpListen != nil {
		return s.httpListen.Addr().String()
	}
	return s.opts.HTTPAddr
}

// DNSAddr returns the bound DNS address, or the configured one before Start.
func (s *Server) DNSAddr() string {
	if s.dnsConn != nil {
		return s.dnsConn.LocalAddr().String()
	}
	return s.opts.DNSAddr
}

// NewURL mints a fresh callback URL and the token that identifies it. The token
// is what correlates a later callback back to the exact injection that planted
// it.
func (s *Server) NewURL(label string) (callbackURL, token string) {
	token = s.mintToken()

	s.mu.Lock()
	s.labels[token] = label
	s.mu.Unlock()

	if s.opts.Domain != "" {
		// A delegated domain lets the DNS listener see the lookup, which is the
		// only way to catch payloads that cannot make an HTTP request.
		return "http://" + token + "." + s.opts.Domain + "/", token
	}
	return "http://" + s.callbackHost() + "/" + token, token
}

// NewRebindURL mints a DNS-rebinding name and the token that identifies it, for
// a check that needs the address of a name to change between two lookups.
//
// The name is <token>.rebind.<domain>, so it is only expressible with a
// delegated domain — this server has to be the one answering the lookup for the
// answer to change. The returned URL carries this server's HTTP port, so that a
// target which follows the *second* answer (a loopback or private address)
// reaches our listener and shows up as a callback: that connection is the proof
// that the rebound address was fetched, not merely resolved.
func (s *Server) NewRebindURL(label string) (callbackURL, token string) {
	if s.opts.Domain == "" {
		return "", ""
	}
	token = s.mintToken()

	s.mu.Lock()
	s.labels[token] = label
	s.rebinds[token] = true
	s.rebindHits[token] = 0
	s.mu.Unlock()

	authority := net.JoinHostPort(token+".rebind."+s.opts.Domain, s.httpPort())
	return "http://" + authority + "/", token
}

// httpPort returns the port the HTTP listener answers on, so a rebinding URL can
// name it. Before Start the configured address is used, which is what a caller
// that builds a URL early would expect.
func (s *Server) httpPort() string {
	if _, port, err := net.SplitHostPort(s.HTTPAddr()); err == nil && port != "" {
		return port
	}
	return "80"
}

// defaultRebindSecond picks the address a rebinding name answers with after the
// first lookup: the place this server's HTTP listener can be reached, when that
// place is a loopback or private address. A public listener is not useful here —
// rebinding to a public address would demonstrate no bypass of a private-address
// filter — so it falls back to loopback, where a co-located target can still
// reach the listener.
func (s *Server) defaultRebindSecond() net.IP {
	if host, _, err := net.SplitHostPort(s.httpListen.Addr().String()); err == nil {
		if ip := net.ParseIP(host); isLocalAddress(ip) {
			return ip
		}
	}
	if out := net.ParseIP(localOutboundIP()); isLocalAddress(out) {
		return out
	}
	return net.IPv4(127, 0, 0, 1)
}

// isLocalAddress reports whether ip is an address a rebinding answer can usefully
// point at: a loopback or private one, not the unspecified "bind any" address.
func isLocalAddress(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && (ip.IsLoopback() || ip.IsPrivate())
}

// rebindAnswer returns the address a rebinding token should be answered with for
// the given query type, and whether this token is a rebinding one at all.
//
// Only an A query is answered: an AAAA query answered with an A record would be
// discarded by the resolver, so it is left empty to fall back to the A answer,
// and the hit counter is not advanced by it.
func (s *Server) rebindAnswer(token string, qtype uint16) (net.IP, bool) {
	if token == "" || qtype != dnsTypeA {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.rebinds[token] {
		return nil, false
	}
	hits := s.rebindHits[token]
	s.rebindHits[token] = hits + 1
	// The first lookup is answered with the public address, every later one with
	// the loopback/private address. A target that resolves once, validates and
	// fetches — the rebinding-vulnerable shape — asks twice; a target that only
	// answers from a cache never asks again.
	if hits == 0 {
		return s.opts.RebindFirst, true
	}
	return s.opts.RebindSecond, true
}

// mintToken produces a fresh callback name, mixing in the operator secret when
// one was supplied.
func (s *Server) mintToken() string {
	raw := randomToken()
	if s.opts.Token == "" {
		return raw
	}
	mac := hmac.New(sha256.New, []byte(s.opts.Token))
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// callbackHost is the authority used in generated URLs when no domain is
// delegated.
//
// When the listener is bound to a specific address, that address is what a
// callback should be sent to — a loopback-only server must not advertise the
// machine's LAN address. Only a wildcard bind needs the outbound address
// guessed, because that is the one a remote target can reach.
func (s *Server) callbackHost() string {
	if s.opts.PublicHost != "" {
		return s.opts.PublicHost
	}
	host, port, err := net.SplitHostPort(s.HTTPAddr())
	if err != nil {
		return s.HTTPAddr()
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "[::]" {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(localOutboundIP(), port)
}

// Poll returns the interactions recorded for a token and clears them, so a
// check that polls in a loop does not see the same callback twice.
func (s *Server) Poll(token string) []checks.Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := s.interactions[token]
	if len(got) == 0 {
		return nil
	}
	delete(s.interactions, token)
	return got
}

// Label returns what a token was issued for.
func (s *Server) Label(token string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.labels[token]
}

// Events returns every interaction seen so far, oldest first.
func (s *Server) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

// Count returns how many interactions have been recorded in total, including
// ones already polled away.
func (s *Server) record(token, protocol, remote, detail string) {
	if token == "" {
		return
	}
	entry := checks.Interaction{
		Protocol:   protocol,
		RemoteAddr: remote,
		Detail:     detail,
		At:         time.Now().Unix(),
	}
	s.mu.Lock()
	s.interactions[token] = append(s.interactions[token], entry)
	s.events = append(s.events, Event{
		Token:      token,
		Label:      s.labels[token],
		Protocol:   protocol,
		RemoteAddr: remote,
		Detail:     detail,
		At:         time.Now(),
	})
	s.mu.Unlock()
	s.opts.Logf("oob: %s callback for %s from %s (%s)", protocol, token, remote, detail)
}

// handleHTTP records every inbound HTTP request as an interaction.
//
// The token can arrive either in the path (/<token>) or in a subdomain
// (<token>.domain), so both are checked.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	token := s.tokenFromHTTP(r)
	s.record(token, "http", remoteIP(r.RemoteAddr), r.Method+" "+r.URL.RequestURI()+" Host: "+r.Host)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("crackweb out-of-band interaction recorded\n"))
}

// tokenFromHTTP extracts the token from a callback request.
func (s *Server) tokenFromHTTP(r *http.Request) string {
	// Every candidate is checked against the tokens this server minted. A name
	// that is not one of ours is part of the target's own path or domain, and
	// treating it as a token would both lose the interaction and mislabel it.
	if path := strings.Trim(r.URL.Path, "/"); path != "" {
		// The first path segment is the token; anything after it is the
		// target's own doing.
		first, _, _ := strings.Cut(path, "/")
		if s.knownToken(first) {
			return first
		}
	}

	host := r.Host
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	if domain := s.opts.Domain; domain != "" {
		if label, ok := strings.CutSuffix(host, "."+domain); ok {
			candidate, _, _ := strings.Cut(label, ".")
			if s.knownToken(candidate) {
				return candidate
			}
		}
	}

	// The callback may arrive with our URL carried inside a parameter of the
	// target's own — `?url=http://…/<token>`. That is exactly what a server-side
	// fetch looks like when the application passed the value along, and the
	// interaction is attributed only if the token is looked for there too.
	// Matching is against the tokens this server minted, so nothing else in the
	// query can be mistaken for one.
	return s.knownTokenIn(r.URL.RawQuery)
}

// knownToken reports whether name is a token this server issued.
func (s *Server) knownToken(name string) bool {
	if name == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.labels[name]
	return ok
}

// knownTokenIn returns the token this server issued that appears in value, or an
// empty string.
func (s *Server) knownTokenIn(value string) string {
	if value == "" {
		return ""
	}
	// The query is percent-encoded; a token is hexadecimal and survives encoding
	// unchanged, so the raw string can be searched directly.
	decoded := value
	if unescaped, err := url.QueryUnescape(value); err == nil {
		decoded = unescaped
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for token := range s.labels {
		if strings.Contains(decoded, token) {
			return token
		}
	}
	return ""
}

// serveDNS answers DNS queries and records them.
func (s *Server) serveDNS() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := s.dnsConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		query := make([]byte, n)
		copy(query, buf[:n])

		name, qEnd, ok := parseDNSQuestion(query)
		if !ok {
			continue
		}
		token := s.tokenFromName(name)

		// A rebinding name is the one case where the answer, not just the
		// lookup, is the point: its address changes from a public one to a
		// loopback/private one, and the interaction records which was served so
		// the evidence can say what the target was told.
		if ip, rebind := s.rebindAnswer(token, questionType(query, qEnd)); rebind {
			s.record(token, "dns", remoteIP(addr.String()), name+" -> "+ip.String())
			if reply := buildDNSReplyA(query, qEnd, ip, rebindTTL); reply != nil {
				_, _ = s.dnsConn.WriteToUDP(reply, addr)
			}
			continue
		}

		s.record(token, "dns", remoteIP(addr.String()), name)

		// Every other query is answered with nothing: the interaction is the
		// point, not the resolution.
		if reply := buildDNSReply(query, qEnd); reply != nil {
			_, _ = s.dnsConn.WriteToUDP(reply, addr)
		}
	}
}

// tokenFromName pulls the token out of a queried name, whether the query is
// <token>.domain or a longer name the target invented.
func (s *Server) tokenFromName(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if domain := strings.ToLower(s.opts.Domain); domain != "" {
		if label, ok := strings.CutSuffix(name, "."+domain); ok {
			name = label
		}
	}
	first, _, _ := strings.Cut(name, ".")
	return first
}

// randomToken returns a short random hex token.
func randomToken() string {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not recoverable, but a time-based token is
		// still better than none for correlation purposes.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buf)
}

// localOutboundIP returns the address this machine would use to reach the
// internet, which is the one a target is most likely able to call back to.
func localOutboundIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // TEST-NET-1: routable lookup, no packets sent
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return "127.0.0.1"
}

// remoteIP strips the port from a remote address.
func remoteIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// mustResolveUDP resolves a listen address for UDP, falling back to the
// original on failure so the caller reports the real bind error.
func mustResolveUDP(addr string) *net.UDPAddr {
	resolved, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{}
	}
	return resolved
}
