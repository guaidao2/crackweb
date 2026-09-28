// Package sitemap records the traffic crackweb has seen.
//
// It serves two purposes. First, it is the working set the scanner draws from:
// everything the proxy captured or the crawler discovered lands here, and the
// scan queue is fed from it. Second, it is the memory of the run — the site
// tree a report can show, and the list of endpoints that were tested.
//
// Entries are deduplicated on a key that ignores parameter *values*: a page
// requested with ?id=1 and later ?id=2 is one endpoint with one injectable
// parameter, and testing it twice would waste requests and produce duplicate
// findings.
package sitemap

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// DefaultLimit bounds how many exchanges are kept in memory. A long browsing
// session or an unbounded crawl can otherwise grow without limit.
const DefaultLimit = 20000

// Entry is one observed request/response exchange.
type Entry struct {
	ID       string
	Request  *httpmsg.Request
	Response *httpmsg.Response
	Origin   httpmsg.Origin
	// At is when the exchange was observed.
	At time.Time
	// Key is the deduplication key.
	Key string
}

// Store is a bounded, deduplicated record of observed traffic.
type Store struct {
	mu      sync.RWMutex
	entries []*Entry
	index   map[string]*Entry
	limit   int
	// dropped counts entries rejected once the limit was reached.
	dropped int
}

// New returns a store bounded to limit entries. A non-positive limit uses the
// default.
func New(limit int) *Store {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return &Store{
		index: make(map[string]*Entry),
		limit: limit,
	}
}

// Add records an exchange. It returns the stored entry, which is the existing
// one when the endpoint was already known, plus whether this was new.
//
// A repeat visit still refreshes the stored response: the newest response is
// the one worth scanning, and a session cookie set on the second visit is
// exactly the sort of thing a scanner needs.
func (s *Store) Add(req *httpmsg.Request, resp *httpmsg.Response) (*Entry, bool) {
	if req == nil {
		return nil, false
	}
	key := Key(req)

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.index[key]; ok {
		if resp != nil {
			existing.Response = resp
		}
		existing.Request = req
		existing.At = time.Now()
		return existing, false
	}

	if len(s.entries) >= s.limit {
		s.dropped++
		return nil, false
	}

	entry := &Entry{
		ID:       req.ID,
		Request:  req,
		Response: resp,
		Origin:   req.Origin,
		At:       time.Now(),
		Key:      key,
	}
	s.entries = append(s.entries, entry)
	s.index[key] = entry
	return entry, true
}

// Len returns how many unique endpoints are stored.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Dropped returns how many exchanges were rejected after the limit was hit.
func (s *Store) Dropped() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dropped
}

// All returns every entry, oldest first.
func (s *Store) All() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Requests returns every stored request, oldest first.
func (s *Store) Requests() []*httpmsg.Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*httpmsg.Request, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e.Request)
	}
	return out
}

// Scannable returns the entries worth handing to the scanner: those that carry
// at least one injectable parameter.
func (s *Store) Scannable() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if len(e.Request.Params()) > 0 {
			out = append(out, e)
		}
	}
	return out
}

// Hosts returns the distinct hosts seen, sorted.
func (s *Store) Hosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, e := range s.entries {
		seen[e.Request.Hostname()] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for host := range seen {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

// Key is the deduplication key for a request: the method, host, path and the
// sorted set of parameter names, ignoring their values.
func Key(req *httpmsg.Request) string {
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteByte(' ')
	b.WriteString(req.Hostname())
	if req.URL != nil {
		b.WriteString(req.URL.EscapedPath())
	} else {
		b.WriteByte('/')
	}

	params := req.Params()
	if len(params) > 0 {
		names := make([]string, 0, len(params))
		for _, p := range params {
			names = append(names, string(p.In)+":"+p.Name)
		}
		sort.Strings(names)
		b.WriteByte('?')
		b.WriteString(strings.Join(names, "&"))
	}
	return b.String()
}
