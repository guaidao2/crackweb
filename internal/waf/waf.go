// Package waf detects whether a target is behind a web application firewall,
// identifies which one, and remembers which payload generation gets through.
//
// Two design decisions matter here.
//
// The first is that detection is conservative. A false positive is expensive:
// every payload would be escalated through four generations of mutation, which
// multiplies request count for nothing. So a target is only marked as protected
// when a probe produces a response that a WAF is known to produce — a specific
// status code, or a page carrying a vendor's marker. "The response changed" is
// not enough; applications change their own responses all the time.
//
// The second is that the result is remembered per target and per check. Once
// mutation generation 2 is found to pass, every later payload for that target
// starts at generation 2 instead of rediscovering the fact. That is what makes
// escalation affordable rather than wasteful.
package waf

import (
	"sync"

	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// BlockedStatuses are the status codes a WAF uses to refuse a request. They are
// unusual enough that an application is unlikely to produce them by accident,
// which is what makes them usable as evidence.
var BlockedStatuses = map[int]bool{
	403: true, // forbidden — the most common
	406: true, // not acceptable — mod_security's default
	419: true, // authentication timeout — some commercial WAFs
	501: true, // not implemented — some WAFs answer this to obvious attacks
	999: true, // used by LinkedIn and others to mean "we refused this"
}

// State is the per-scan memory of WAF behaviour.
type State struct {
	mu      sync.Mutex
	targets map[string]*Target
	// enabled records whether detection should run at all; the user can turn
	// it off when they know the target is unprotected and want the requests
	// spent on payloads instead.
	enabled bool
}

// Target is what is known about one host.
type Target struct {
	// Probed records that detection has run.
	Probed bool
	// Vendor is the identified WAF, or "" when none was found.
	Vendor string
	// Signature is what a refusal from this target looks like.
	Signature Signature
	// Floors maps a check ID to the mutation generation known to get through.
	Floors map[string]int
}

// NewState builds the WAF memory.
func NewState(enabled bool) *State {
	return &State{targets: map[string]*Target{}, enabled: enabled}
}

// Enabled reports whether detection is on.
func (s *State) Enabled() bool { return s != nil && s.enabled }

// target returns the record for a host, creating it if needed.
func (s *State) target(host string) *Target {
	if existing, ok := s.targets[host]; ok {
		return existing
	}
	created := &Target{Signature: defaultSignature(), Floors: map[string]int{}}
	s.targets[host] = created
	return created
}

// Vendor returns the identified WAF for a host.
func (s *State) Vendor(host string) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target(host).Vendor
}

// Protected reports whether the host is known to be behind a WAF.
func (s *State) Protected(host string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target(host).Vendor != ""
}

// NeedsProbe reports whether detection should run for a host.
func (s *State) NeedsProbe(host string) bool {
	if !s.Enabled() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.target(host).Probed
}

// MarkProbed records that detection has run for a host.
func (s *State) MarkProbed(host, vendor string, signature Signature) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.target(host)
	target.Probed = true
	target.Vendor = vendor
	if len(signature.BodyMarkers) > 0 || len(signature.Statuses) > 0 {
		target.Signature = signature
	}
}

// IsBlocked reports whether a response looks like a refusal from the target's
// WAF.
//
// When no WAF was detected, only the unmistakable signals count: a block status
// code paired with a body that says something refused the request. Anything
// looser would escalate payloads against applications that simply dislike
// certain input.
func (s *State) IsBlocked(host string, resp *httpmsg.Response) bool {
	if resp == nil {
		return false
	}
	// A 5xx from the origin is a crash, not a refusal. Treating it as a block
	// would push every payload up a generation for no reason.
	if resp.Status >= 500 && resp.Status != 501 {
		return false
	}

	if s == nil {
		return genericBlock(resp)
	}

	s.mu.Lock()
	target := s.target(host)
	known := target.Vendor != ""
	signature := target.Signature
	s.mu.Unlock()

	if !known {
		return genericBlock(resp)
	}
	return signature.matches(resp)
}

// Floor returns the generation a check should start at for a host.
func (s *State) Floor(host, check string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target(host).Floors[check]
}

// Raise records that a generation got through, so later payloads start there.
//
// Only ever moves the floor up: a target that let generation 1 through once and
// refused it later is better served by starting from the generation that
// reliably works.
func (s *State) Raise(host, check string, generation int) {
	if s == nil || generation <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.target(host)
	if generation > target.Floors[check] {
		target.Floors[check] = generation
	}
}

// Summary describes what was detected, for a report.
type Summary struct {
	Host   string
	Vendor string
	Floors map[string]int
	Probed bool
}

// Summaries returns what was learned about every host, for reporting.
func (s *State) Summaries() []Summary {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Summary, 0, len(s.targets))
	for host, target := range s.targets {
		floors := make(map[string]int, len(target.Floors))
		for check, generation := range target.Floors {
			floors[check] = generation
		}
		out = append(out, Summary{
			Host:   host,
			Vendor: target.Vendor,
			Floors: floors,
			Probed: target.Probed,
		})
	}
	// Deterministic order for reproducible reports.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Host < out[j-1].Host; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
