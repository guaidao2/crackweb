package crawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/httpclient"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// TestCrawlerAppliesConfiguredCredentialsBeforeTheChecksRead keeps the half of the
// credential contract that is easy to lose: the message-model request handed to the
// scanner has to carry the identity, not only the wire copy. Without it a crawl browses
// behind a login while every check reads an anonymous request.
func TestCrawlerAppliesConfiguredCredentialsBeforeTheChecksRead(t *testing.T) {
	var (
		mu       sync.Mutex
		onWire   []string
		toChecks []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		onWire = append(onWire, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{
		Timeout:     5 * time.Second,
		Credentials: []httpclient.Credential{{Name: "Authorization", Value: "Bearer configured"}},
	})
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	crawler := New(Options{
		Client:   client,
		Engine:   EngineHTTP,
		Depth:    1,
		MaxPages: 2,
		OnExchange: func(req *httpmsg.Request, _ *httpmsg.Response) {
			mu.Lock()
			toChecks = append(toChecks, req.Header.Get("Authorization"))
			mu.Unlock()
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := crawler.Run(ctx, server.URL+"/"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(onWire) == 0 || len(toChecks) == 0 {
		t.Fatalf("no exchange was observed (wire=%d, checks=%d)", len(onWire), len(toChecks))
	}
	for _, got := range onWire {
		if got != "Bearer configured" {
			t.Errorf("wire request carried %q", got)
		}
	}
	for _, got := range toChecks {
		if got != "Bearer configured" {
			t.Errorf("the request the checks read carried %q", got)
		}
	}
}
