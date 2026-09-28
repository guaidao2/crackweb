package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/ca"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// testProxy starts a proxy on an ephemeral port and returns it with its address.
func testProxy(t *testing.T, opts Options) *Proxy {
	t.Helper()
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	if opts.CA == nil {
		authority, err := ca.Generate("crackweb-test")
		if err != nil {
			t.Fatalf("ca.Generate: %v", err)
		}
		opts.CA = authority
	}
	p, err := New(opts)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		_ = p.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("proxy did not shut down")
		}
	})

	// Wait for the listener to come up before handing the address out.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if addr := p.Addr(); addr != opts.Listen {
			return p
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("proxy did not start listening")
	return nil
}

// proxyClient returns an HTTP client that routes through the proxy and trusts
// the given CA.
func proxyClient(t *testing.T, p *Proxy, authority *ca.CA) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + p.Addr())
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(authority.Certificate())

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		},
	}
}

func TestForwardsPlainHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s method=%s", r.URL.Path, r.Method)
	}))
	defer target.Close()

	authority, _ := ca.Generate("test")
	p := testProxy(t, Options{CA: authority})
	client := proxyClient(t, p, authority)

	resp, err := client.Get(target.URL + "/plain")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "path=/plain method=GET" {
		t.Errorf("body = %q", body)
	}
}

func TestForwardsPOSTBody(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got:%s", body)
	}))
	defer target.Close()

	authority, _ := ca.Generate("test")
	p := testProxy(t, Options{CA: authority})
	client := proxyClient(t, p, authority)

	resp, err := client.PostForm(target.URL+"/submit", url.Values{"user": {"admin"}})
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "got:user=admin" {
		t.Errorf("body = %q, want the form body to survive the proxy", body)
	}
}

// TestInterceptsHTTPS is the milestone's core claim: a client that trusts only
// crackweb's CA can reach a TLS origin through the proxy, which means the proxy
// really is terminating and re-signing the connection.
func TestInterceptsHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "secure path=%s", r.URL.Path)
	}))
	defer target.Close()

	authority, _ := ca.Generate("test")
	// Insecure covers the target's own throwaway certificate; the client below
	// still has to accept crackweb's CA, so interception is genuinely proven.
	p := testProxy(t, Options{CA: authority, Insecure: true})
	client := proxyClient(t, p, authority)

	resp, err := client.Get(target.URL + "/inside")
	if err != nil {
		t.Fatalf("HTTPS GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "secure path=/inside" {
		t.Errorf("body = %q", body)
	}

	if resp.TLS == nil {
		t.Fatal("client connection was not TLS")
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificate presented")
	}
	// The certificate the client saw must have been signed by crackweb's CA,
	// not by the origin.
	leaf := resp.TLS.PeerCertificates[0]
	if err := leaf.CheckSignatureFrom(authority.Certificate()); err != nil {
		t.Errorf("leaf certificate was not signed by crackweb's CA: %v", err)
	}
}

func TestInterceptedTrafficReachesTheCallbacks(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "body-marker")
	}))
	defer target.Close()

	var (
		mu       sync.Mutex
		requests []*httpmsg.Request
		gotResp  *httpmsg.Response
	)

	authority, _ := ca.Generate("test")
	p := testProxy(t, Options{
		CA:       authority,
		Insecure: true,
		OnRequest: func(req *httpmsg.Request) {
			mu.Lock()
			defer mu.Unlock()
			requests = append(requests, req)
		},
		OnResponse: func(_ *httpmsg.Request, resp *httpmsg.Response) {
			mu.Lock()
			defer mu.Unlock()
			gotResp = resp
		},
	})
	client := proxyClient(t, p, authority)

	if _, err := client.Get(target.URL + "/hooked?q=1"); err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(requests) == 0 {
		t.Fatal("OnRequest was never called")
	}
	req := requests[0]
	if req.Method != "GET" {
		t.Errorf("captured method = %q, want GET", req.Method)
	}
	if req.URL == nil || req.URL.Scheme != "https" {
		t.Errorf("captured URL = %v, want an https URL", req.URL)
	}
	if got := req.URL.Query().Get("q"); got != "1" {
		t.Errorf("captured query q = %q, want 1", got)
	}
	if gotResp == nil {
		t.Fatal("OnResponse was never called")
	}
	if gotResp.Status != 200 || string(gotResp.Body) != "body-marker" {
		t.Errorf("captured response = %d %q", gotResp.Status, gotResp.Body)
	}
}

// TestOutOfScopeHostsAreTunnelled checks the promise that only in-scope traffic
// is intercepted: everything else is relayed untouched, so unrelated browsing
// keeps working and is not modified.
func TestOutOfScopeHostsAreTunnelled(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "untouched")
	}))
	defer target.Close()

	authority, _ := ca.Generate("test")
	p := testProxy(t, Options{
		CA:       authority,
		Insecure: true,
		Scope:    []string{"only.example.com"},
	})

	// The client does NOT trust the CA: if the proxy intercepted, the
	// handshake would fail. Success proves the connection was tunnelled.
	proxyURL, _ := url.Parse("http://" + p.Addr())
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(target.URL + "/")
	if err != nil {
		t.Fatalf("tunnelled GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "untouched" {
		t.Errorf("body = %q", body)
	}
	// The origin's own certificate must have come through unchanged.
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificate")
	}
	if err := resp.TLS.PeerCertificates[0].CheckSignatureFrom(authority.Certificate()); err == nil {
		t.Error("out-of-scope host was intercepted: the certificate was signed by crackweb")
	}
}

func TestRejectsNonProxyRequest(t *testing.T) {
	authority, _ := ca.Generate("test")
	p := testProxy(t, Options{CA: authority})

	// A request in origin form (not an absolute URL) is not proxy traffic.
	resp, err := http.Get("http://" + p.Addr() + "/not-a-proxy-request")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
