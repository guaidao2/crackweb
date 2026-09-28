// Package scope matches hostnames against a set of patterns.
//
// Both the proxy and the crawler need the same answer to "is this host part of
// the engagement?", and getting it wrong is expensive in both directions:
// too broad and a scan touches systems nobody authorised, too narrow and it
// silently covers half the application.
package scope

import (
	"net"
	"strings"
)

// Scope decides which hosts crackweb intercepts and tests, and which it merely
// tunnels.
//
// The distinction matters: interception is intrusive — it terminates TLS and
// can rewrite traffic — so applying it to a host the user did not ask about is
// simply wrong. Anything out of scope is relayed untouched, which also keeps
// the browser working normally for unrelated sites while a scan runs.
type Scope struct {
	patterns []string
}

// NewScope builds a scope from patterns such as "example.com",
// "*.example.com" or "10.0.0.0/8".
//
// An empty pattern list matches everything, which is what a user gets when they
// point a browser at the proxy without narrowing it.
func NewScope(patterns []string) *Scope {
	cleaned := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return &Scope{patterns: cleaned}
}

// Empty reports whether the scope matches everything.
func (s *Scope) Empty() bool { return s == nil || len(s.patterns) == 0 }

// Patterns returns the configured patterns.
func (s *Scope) Patterns() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.patterns...)
}

// Contains reports whether a host:port authority is in scope.
func (s *Scope) Contains(host string) bool {
	if s.Empty() {
		return true
	}
	name := strings.ToLower(StripPort(host))
	for _, pattern := range s.patterns {
		if matchHost(pattern, name) {
			return true
		}
	}
	return false
}

// matchHost matches one pattern against a bare hostname.
func matchHost(pattern, host string) bool {
	// A CIDR range covers the "test my internal network" case.
	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		ip := net.ParseIP(host)
		return ip != nil && network.Contains(ip)
	}

	// ".example.com" and "*.example.com" both mean "any subdomain", and by
	// convention the bare domain too, because that is what users expect.
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	if suffix, ok := strings.CutPrefix(pattern, "."); ok {
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}

	if pattern == host {
		return true
	}
	// A bare domain also covers its subdomains, so that --scope example.com
	// does not silently skip www.example.com.
	return strings.HasSuffix(host, "."+pattern)
}

// StripPort removes a trailing port from an authority, leaving IPv6 literals
// intact.
func StripPort(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}
