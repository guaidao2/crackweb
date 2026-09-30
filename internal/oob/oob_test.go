package oob

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// buildQuery assembles a minimal DNS query packet for a name.
func buildQuery(name string, qtype uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], 0x1234) // transaction id
	binary.BigEndian.PutUint16(packet[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(packet[4:6], 1)      // QDCOUNT

	for _, label := range strings.Split(name, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0) // root label

	quad := make([]byte, 4)
	binary.BigEndian.PutUint16(quad[0:2], qtype)
	binary.BigEndian.PutUint16(quad[2:4], 1) // class IN
	return append(packet, quad...)
}

func TestParseDNSQuestion(t *testing.T) {
	packet := buildQuery("abc123.oob.example.com", 1)

	name, end, ok := parseDNSQuestion(packet)
	if !ok {
		t.Fatal("parseDNSQuestion failed on a well-formed query")
	}
	if name != "abc123.oob.example.com" {
		t.Errorf("name = %q", name)
	}
	if end != len(packet) {
		t.Errorf("end = %d, want %d", end, len(packet))
	}
}

func TestParseDNSQuestionRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":           {},
		"short header":    make([]byte, 8),
		"no questions":    make([]byte, 12),
		"truncated label": append(buildQuery("a.example", 1)[:14], 5),
	}

	for name, packet := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := parseDNSQuestion(packet); ok {
				t.Errorf("parseDNSQuestion accepted %s", name)
			}
		})
	}
}

func TestBuildDNSReply(t *testing.T) {
	query := buildQuery("token.oob.example", 1)
	reply := buildDNSReply(query, len(query))
	if reply == nil {
		t.Fatal("buildDNSReply returned nil")
	}

	if binary.BigEndian.Uint16(reply[0:2]) != 0x1234 {
		t.Error("transaction id was not echoed")
	}
	flags := binary.BigEndian.Uint16(reply[2:4])
	if flags&0x8000 == 0 {
		t.Error("QR bit is not set: this is not a response")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		t.Errorf("RCODE = %d, want 0 (no error)", rcode)
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 1 {
		t.Error("QDCOUNT should be 1")
	}
	if binary.BigEndian.Uint16(reply[6:8]) != 0 {
		t.Error("ANCOUNT should be 0: crackweb answers nothing")
	}
}

func TestTokenExtraction(t *testing.T) {
	cases := []struct {
		domain string
		host   string
		want   string
	}{
		{"oob.example.com", "abc123.oob.example.com", "abc123"},
		{"oob.example.com", "abc123.sub.oob.example.com", "abc123"},
		{"oob.example.com", "abc123.oob.example.com.", "abc123"},
		{"", "abc123.whatever.example", "abc123"},
	}

	for _, tc := range cases {
		server := New(Options{Domain: tc.domain})
		if got := server.tokenFromName(tc.host); got != tc.want {
			t.Errorf("tokenFromName(%q) with domain %q = %q, want %q", tc.host, tc.domain, got, tc.want)
		}
	}
}

// TestTokenFromHTTPRequest: the token is read from where the payload put it — the
// first path segment, or the sub-domain — and a name that is not one of ours is
// not mistaken for it.
func TestTokenFromHTTPRequest(t *testing.T) {
	server := New(Options{Domain: "oob.example.com"})

	_, pathToken := server.NewURL("ssrf")
	req, _ := http.NewRequest("GET", "http://x/"+pathToken, nil)
	req.Host = "oob.example.com"
	if got := server.tokenFromHTTP(req); got != pathToken {
		t.Errorf("path token = %q, want %q", got, pathToken)
	}

	_, hostToken := server.NewURL("ssrf")
	req2, _ := http.NewRequest("GET", "http://x/", nil)
	req2.Host = hostToken + ".oob.example.com"
	if got := server.tokenFromHTTP(req2); got != hostToken {
		t.Errorf("subdomain token = %q, want %q", got, hostToken)
	}

	req3, _ := http.NewRequest("GET", "http://x/a/b/c", nil)
	req3.Host = "oob.example.com"
	if got := server.tokenFromHTTP(req3); got != "" {
		t.Errorf("an unknown path segment was taken for a token: %q", got)
	}
}

func TestNewURLMintsUniqueTokens(t *testing.T) {
	server := New(Options{PublicHost: "127.0.0.1:8081"})

	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		callbackURL, token := server.NewURL("test")
		if token == "" {
			t.Fatal("empty token")
		}
		if seen[token] {
			t.Fatalf("duplicate token %q", token)
		}
		seen[token] = true
		if !strings.Contains(callbackURL, token) {
			t.Errorf("callback URL %q does not contain its token", callbackURL)
		}
	}
}

func TestDomainFormCallbackURL(t *testing.T) {
	server := New(Options{Domain: "oob.example.com"})
	callbackURL, token := server.NewURL("ssrf")
	if want := "http://" + token + ".oob.example.com/"; callbackURL != want {
		t.Errorf("callback URL = %q, want %q", callbackURL, want)
	}
}

func TestSecretChangesTokens(t *testing.T) {
	a := New(Options{Token: "alpha"})
	b := New(Options{Token: "beta"})
	if a.mintToken() == b.mintToken() {
		t.Error("different secrets produced the same token")
	}
	for i := 0; i < 20; i++ {
		if token := a.mintToken(); len(token) != 16 {
			t.Fatalf("token %q has length %d, want 16", token, len(token))
		}
	}
}

// TestRecordsAndPollsHTTPInteraction is the end-to-end path a check relies on:
// an HTTP callback arrives, is correlated to its token, and is drained on poll.
func TestRecordsAndPollsHTTPInteraction(t *testing.T) {
	server := New(Options{HTTPAddr: "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && server.HTTPAddr() == "127.0.0.1:0" {
		time.Sleep(5 * time.Millisecond)
	}

	callbackURL, token := server.NewURL("ssrf")
	if _, err := http.Get(callbackURL); err != nil {
		t.Fatalf("callback request failed: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	var interactions []struct {
		Protocol string
		Detail   string
	}
	for time.Now().Before(deadline) {
		got := server.Poll(token)
		if len(got) > 0 {
			for _, interaction := range got {
				interactions = append(interactions, struct {
					Protocol string
					Detail   string
				}{interaction.Protocol, interaction.Detail})
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(interactions) == 0 {
		t.Fatal("the callback was not recorded")
	}
	if interactions[0].Protocol != "http" {
		t.Errorf("protocol = %q, want http", interactions[0].Protocol)
	}
	if !strings.Contains(interactions[0].Detail, token) {
		t.Errorf("detail %q does not mention the token", interactions[0].Detail)
	}
	// Polling drains, so a check that loops does not see the callback twice.
	if again := server.Poll(token); len(again) != 0 {
		t.Errorf("second poll returned %d interaction(s), want none", len(again))
	}
	_ = server.Close()
}

// TestRecordsDNSInteraction exercises the UDP path with a real query.
func TestRecordsDNSInteraction(t *testing.T) {
	server := New(Options{HTTPAddr: "127.0.0.1:0", DNSAddr: "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && server.DNSAddr() == "127.0.0.1:0" {
		time.Sleep(5 * time.Millisecond)
	}
	if server.dnsConn == nil {
		t.Skip("DNS listener unavailable in this environment")
	}

	conn, err := net.Dial("udp", server.DNSAddr())
	if err != nil {
		t.Fatalf("dial DNS listener: %v", err)
	}
	defer conn.Close()

	query := buildQuery("feedface.example", 1)
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write query: %v", err)
	}

	reply := make([]byte, 1500)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if n < 12 {
		t.Fatalf("reply is %d bytes, want at least a header", n)
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 0x1234 {
		t.Error("reply did not echo the transaction id")
	}

	// The lookup is recorded even though the answer carries nothing.
	deadline = time.Now().Add(2 * time.Second)
	recorded := false
	for time.Now().Before(deadline) {
		for _, event := range server.Events() {
			if event.Token == "feedface" && event.Protocol == "dns" {
				recorded = true
			}
		}
		if recorded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !recorded {
		t.Error("the DNS lookup was not recorded")
	}
	_ = server.Close()
}

func TestEventsCarryTheLabel(t *testing.T) {
	server := New(Options{Domain: "oob.example"})
	_, token := server.NewURL("command-injection")
	server.record(token, "dns", "10.0.0.9", "x.oob.example")

	events := server.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Label != "command-injection" {
		t.Errorf("label = %q, want the one the token was minted for", events[0].Label)
	}
	if events[0].RemoteAddr != "10.0.0.9" {
		t.Errorf("remote = %q", events[0].RemoteAddr)
	}
}

// TestCallbackCarriedInAQueryValueIsAttributed: a target that passed our URL along
// as a parameter of its own sends the callback with the token inside the query
// rather than in the path. That is what a server-side fetch looks like from here,
// and the interaction is attributed only if the token is looked for there too.
func TestCallbackCarriedInAQueryValueIsAttributed(t *testing.T) {
	server := New(Options{HTTPAddr: "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Start returns once the listener is up, which is what a scan needs; the
	// serving happens in the background.
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer server.Close()

	callbackURL, token := server.NewURL("ssrf")
	endpoint := "http://" + server.HTTPAddr() + "/fetch?url=" + url.QueryEscape(callbackURL)
	if _, err := http.Get(endpoint); err != nil {
		t.Fatalf("callback request failed: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := server.Poll(token); len(got) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a callback carrying the token in a query value was not attributed")
}
