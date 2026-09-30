// Package checks defines what a crackweb vulnerability check is and how one is
// wired into a scan.
//
// A check is deliberately small and self-contained: it declares what it is, how
// severe a hit is, whether it needs to send traffic, and a Run method that
// inspects a target. Everything a check needs to reach the network or the
// out-of-band server comes in through Context, so checks are trivially
// testable and cannot grow hidden global state.
package checks

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// Target is what a check is asked to inspect: a request, the response it got,
// and the parameter to focus on when the check injects.
//
// Passive checks use Request and Response only. Active checks use Param, which
// is nil when a request carries no injectable parameters.
type Target struct {
	Request  *httpmsg.Request
	Response *httpmsg.Response
	Param    *httpmsg.Param
}

// ParamKey returns a stable identifier for the target's parameter, or "" when
// there is none.
func (t *Target) ParamKey() string {
	if t == nil || t.Param == nil {
		return ""
	}
	return t.Param.Key()
}

// OOBProvider is the out-of-band interaction server, as seen by checks.
//
// It is an interface so that checks can depend on the capability without
// depending on the implementation, and so that a check can run with out-of-band
// testing disabled by receiving nil.
type OOBProvider interface {
	// NewURL returns a freshly minted callback URL and a polling handle that
	// correlates any interaction back to this specific injection.
	NewURL(label string) (callbackURL, token string)
	// Poll reports whether the token has been interacted with.
	Poll(token string) []Interaction
}

// Browser is a real browser, as a check sees it.
//
// A DOM cross-site scripting flaw exists only while a browser is running the page: the
// server returns the same bytes whether the page is vulnerable or not, and what makes it
// vulnerable is what the page's own script does with those bytes afterwards. Every other
// check answers from a response; this one cannot. It is an interface for the same reason
// the interaction server is: a caller without a browser passes nil, and checks that need
// one skip themselves rather than guessing.
type Browser interface {
	// Probe loads a target in a browser and reports whether the page turned the markup the
	// caller planted into part of its document, and what the browser made of it.
	Probe(ctx context.Context, target, marker string) (embedded bool, detail string, err error)
	// Eval loads a target in a browser and returns the value of a JavaScript expression in
	// that page, as a string. It is what a question about runtime state needs — whether a
	// property exists on an object's prototype, for instance, which leaves no markup behind
	// and cannot be read from a response.
	Eval(ctx context.Context, target, expression string) (string, error)
}

// BrowserCheck is an optional interface for checks that need a browser to answer.
//
// Every other check answers from a response; these cannot, because the flaw exists only
// while a page is running. The marker is separate from Unsafe because the two are
// different questions: one says the probe has effects beyond the request, the other says
// the check is meaningless without a browser. A caller without one starts the browser only
// when it is asked for.
type BrowserCheck interface {
	NeedsBrowser() bool
}

// RequiresBrowser reports whether a check needs a browser to run.
func RequiresBrowser(c Check) bool {
	marker, ok := c.(BrowserCheck)
	return ok && marker.NeedsBrowser()
}

// Interaction is one callback the out-of-band server observed.
type Interaction struct {
	// Protocol is "dns" or "http".
	Protocol string
	// RemoteAddr is where the interaction came from.
	RemoteAddr string
	// Detail carries protocol-specific evidence, such as the queried name or
	// the request line.
	Detail string
	// At is when it happened, as a Unix timestamp.
	At int64
}

// Check is one vulnerability test.
type Check interface {
	// ID is the stable machine name, e.g. "sqli-error". It appears in CLI
	// filters and in report metadata.
	ID() string
	// TitleKey and DescriptionKey are catalogue keys, so findings render in the
	// user's language without the check knowing about languages.
	TitleKey() i18n.Key
	DescriptionKey() i18n.Key
	// Severity is the severity of a positive hit.
	Severity() finding.Severity
	// RemediationKey is the catalogue key for fix advice.
	RemediationKey() i18n.Key
	// Tags group checks for filtering, e.g. "injection", "owasp-top10".
	Tags() []string
	// Passive reports whether the check analyses existing traffic instead of
	// sending anything. Passive checks are safe to run against production.
	Passive() bool
	// Run inspects the target and returns any findings.
	Run(ctx context.Context, c *Context, t *Target) []*finding.Finding
}

// RequestLevel is an optional interface for checks that operate on a request as
// a whole rather than on each of its parameters.
//
// A template describes one request to send, so running it once per parameter
// would fire the same request several times and report the same finding; a
// check like "is this file exposed?" is likewise about the URL, not a form
// field. Checks that do not implement this interface are run per parameter,
// which is what injection checks want.
type RequestLevel interface {
	IsRequestLevel() bool
}

// IsRequestLevel reports whether a check operates on the request rather than on
// a single parameter.
func IsRequestLevel(c Check) bool {
	marker, ok := c.(RequestLevel)
	return ok && marker.IsRequestLevel()
}

// Unsafe is an optional interface for checks whose probes can affect the target
// beyond the request they are testing.
//
// Request smuggling is the case that motivates it: a content-length confusion
// payload can leave bytes queued on a connection, which its neighbouring
// requests then see. Against a host the user does not own that is not a test,
// it is an incident. Such checks are therefore registered but never selected by
// default — the user has to ask for them by name or with the explicit flag.
type Unsafe interface {
	// IsUnsafe reports that the check sends probes with side effects.
	IsUnsafe() bool
}

// IsUnsafe reports whether a check needs to be opted into.
func IsUnsafe(c Check) bool {
	marker, ok := c.(Unsafe)
	return ok && marker.IsUnsafe()
}

// registry holds every registered check.
var (
	registryMu sync.RWMutex
	registry   []Check
	registryID = map[string]Check{}
)

// Register adds a check to the global registry. It panics on a duplicate or
// empty ID, because both are programming errors that would otherwise surface as
// a silently missing check.
func Register(c Check) {
	registryMu.Lock()
	defer registryMu.Unlock()

	id := c.ID()
	if id == "" {
		panic("checks: Register called with an empty ID")
	}
	if _, exists := registryID[id]; exists {
		panic(fmt.Sprintf("checks: duplicate check ID %q", id))
	}
	registry = append(registry, c)
	registryID[id] = c
}

// All returns every registered check, ordered by ID for reproducible runs.
func All() []Check {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Check, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// ByID looks a check up by its ID.
func ByID(id string) Check {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registryID[id]
}

// allowed filters out checks that need explicit consent.
func allowed(candidates []Check, includeUnsafe bool) []Check {
	if includeUnsafe {
		return candidates
	}
	out := make([]Check, 0, len(candidates))
	for _, c := range candidates {
		if IsUnsafe(c) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// IDs returns the IDs of every registered check, sorted.
func IDs() []string {
	checks := All()
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		out = append(out, c.ID())
	}
	return out
}

// Select resolves a list of check IDs or tags against the registered checks,
// excluding those that need explicit consent.
func Select(names []string) (selected []Check, unknown []string) {
	return SelectFrom(All(), names, false)
}

// SelectFrom resolves a list of check IDs or tags against an explicit set of
// candidates.
//
// Taking the candidate list as a parameter is what lets dynamically loaded
// checks — templates read from disk — take part in selection: they are not in
// the global registry, but `--checks template` must still find them.
//
// The special value "all" selects everything. A name matches either an exact
// check ID or a tag, so `--checks injection` runs every injection check and
// `--checks sqli-error` runs exactly one. Unknown names are returned so the
// caller can fail loudly rather than silently scanning less than asked.
func SelectFrom(candidates []Check, names []string, includeUnsafe bool) (selected []Check, unknown []string) {
	if len(names) == 0 {
		return nil, nil
	}
	for _, name := range names {
		if name == "all" {
			return allowed(candidates, includeUnsafe), nil
		}
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}

	seen := map[string]bool{}
	for _, c := range candidates {
		// Naming an unsafe check explicitly is the consent; "all" and tags are
		// not, because a user who did not know it existed cannot have agreed to
		// its side effects.
		if IsUnsafe(c) && !wanted[c.ID()] {
			continue
		}
		matched := wanted[c.ID()]
		if !matched {
			for _, tag := range c.Tags() {
				if wanted[tag] {
					matched = true
					break
				}
			}
		}
		if matched && !seen[c.ID()] {
			seen[c.ID()] = true
			selected = append(selected, c)
		}
	}

	matchedNames := map[string]bool{}
	for _, c := range selected {
		matchedNames[c.ID()] = true
		for _, tag := range c.Tags() {
			matchedNames[tag] = true
		}
	}
	for _, name := range names {
		if !matchedNames[name] {
			unknown = append(unknown, name)
		}
	}
	return selected, unknown
}
