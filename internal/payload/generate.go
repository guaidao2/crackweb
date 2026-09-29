package payload

import (
	"strings"
)

// Variant is one concrete string to send, with the provenance needed to explain
// it in a report and to learn from the outcome.
type Variant struct {
	// Value is the string to put on the wire.
	Value string
	// Generation is how many mutators were applied: 0 is the plain seed.
	Generation int
	// Mutators names the transformations, in application order.
	Mutators []string
}

// Label renders the variant for evidence, e.g. "base+urlencode".
func (v Variant) Label() string {
	if len(v.Mutators) == 0 {
		return "base"
	}
	return "base+" + strings.Join(v.Mutators, "+")
}

// Generation limits. They exist because the alternative — sending every
// combination of every mutator — is a denial of service against the target and
// against the scanner's own time budget.
const (
	// MaxGeneration is the deepest transformation stack attempted.
	MaxGeneration = 3
	// maxPerGeneration caps how many variants a single generation contributes,
	// across all seeds. An unprotected target never gets past generation 0, so
	// these limits only bite on a hardened one.
	maxPerGeneration = 14
	// maxSeeds bounds how many base payloads are expanded at once.
	//
	// Generation 0 is one request per seed, so this is what a check spends
	// before any mutation happens. It has to be large enough for a check whose
	// coverage *is* its seeds — cross-site scripting needs a distinct closing
	// form for each context a payload can land in, and eight does not reach the
	// attribute cases — and small enough that a target is not flooded. Checks
	// with fewer seeds are unaffected: the limit is a ceiling, not a quota.
	maxSeeds = 20
)

// Generations expands seeds into variants grouped by generation.
//
// The grouping is the interface that makes adaptive escalation work: a check
// walks generation 0 first, and only asks for generation 1 if the target
// refused everything in generation 0. So the cost of a clean target is one
// request per seed, and the full grammar is reserved for targets that need it.
//
// Within a generation, mutators in the same family never combine, because they
// compete for the same characters: applying both "space to comment" and "space
// to tab" produces a payload that is neither.
func Generations(kind Kind, seeds []string) [][]Variant {
	if len(seeds) == 0 {
		return nil
	}
	if len(seeds) > maxSeeds {
		seeds = seeds[:maxSeeds]
	}

	applicable := MutatorsFor(kind)
	structure, encoding := splitByFamily(applicable)

	var (
		out  = make([][]Variant, MaxGeneration+1)
		seen = map[string]bool{}
	)

	// Generation 0: the seeds themselves. A variant is only recorded once, so a
	// later generation that reproduces an earlier string is dropped rather than
	// re-sent.
	add := func(gen int, value string, names []string) bool {
		if value == "" || seen[value] {
			return false
		}
		seen[value] = true
		out[gen] = append(out[gen], Variant{Value: value, Generation: gen, Mutators: names})
		return true
	}

	for _, seed := range seeds {
		add(0, seed, nil)
	}

	// Generation 1: one structural rewrite, then one encoding if the budget
	// allows. Structural rewrites are tried first because they are the ones a
	// signature-based WAF actually misses.
	count := 0
	for _, seed := range seeds {
		for _, m := range structure {
			if count >= maxPerGeneration {
				break
			}
			if value := m.Apply(seed); value != seed {
				if add(1, value, []string{m.Name}) {
					count++
				}
			}
		}
		if count >= maxPerGeneration {
			break
		}
	}
	for _, seed := range seeds {
		for _, m := range encoding {
			if count >= maxPerGeneration {
				break
			}
			if value := m.Apply(seed); value != seed {
				if add(1, value, []string{m.Name}) {
					count++
				}
			}
		}
		if count >= maxPerGeneration {
			break
		}
	}

	// Generation 2: a structural rewrite plus an encoding. This is the
	// combination that defeats a WAF which normalises once and matches once —
	// the encoding gets past the normaliser, and the structural rewrite gets
	// past the rule.
	count = 0
	for _, seed := range seeds {
		for _, s := range structure {
			structural := s.Apply(seed)
			if structural == seed {
				continue
			}
			for _, e := range encoding {
				if count >= maxPerGeneration {
					break
				}
				value := e.Apply(structural)
				if value == structural {
					continue
				}
				if add(2, value, []string{s.Name, e.Name}) {
					count++
				}
			}
			if count >= maxPerGeneration {
				break
			}
		}
		if count >= maxPerGeneration {
			break
		}
	}

	// Generation 3: three deep, and only the widest-reaching pairings. Reserved
	// for targets where nothing else got through.
	count = 0
	for _, seed := range seeds {
		for _, s := range structure {
			structural := s.Apply(seed)
			if structural == seed {
				continue
			}
			for _, e1 := range encoding {
				once := e1.Apply(structural)
				if once == structural {
					continue
				}
				for _, e2 := range encoding {
					if count >= maxPerGeneration {
						break
					}
					if e2.Family == e1.Family {
						continue
					}
					value := e2.Apply(once)
					if value == once {
						continue
					}
					if add(3, value, []string{s.Name, e1.Name, e2.Name}) {
						count++
					}
				}
				if count >= maxPerGeneration {
					break
				}
			}
			if count >= maxPerGeneration {
				break
			}
		}
		if count >= maxPerGeneration {
			break
		}
	}

	return out
}

// splitByFamily separates mutators into those that restructure syntax and those
// that change encoding. A generation-2 variant takes one of each: encoding
// alone does not defeat a rule that normalises, and restructuring alone does
// not defeat one that matches on a decoded value.
func splitByFamily(mutators []Mutator) (structure, encoding []Mutator) {
	for _, m := range mutators {
		switch m.Family {
		case "encoding", "casing":
			encoding = append(encoding, m)
		default:
			structure = append(structure, m)
		}
	}
	return structure, encoding
}

// Best returns the generation with the highest yield, which is where an
// escalated scan should start. It is used to give a variant list a sensible
// entry point when a target is already known to be protected.
func Best(generations [][]Variant) int {
	for gen := len(generations) - 1; gen >= 0; gen-- {
		if len(generations[gen]) > 0 {
			return gen
		}
	}
	return 0
}

// NeedsTransportEncoding reports whether a variant still has to be
// percent-encoded before it can be placed in a request.
//
// The distinction matters because encoding twice silently changes the payload:
// a URL-encoded variant that is encoded again arrives at the application as a
// literal percent sequence rather than as the character it stood for. So a
// variant whose last transformation already produced transport form is sent
// verbatim, and everything else is encoded exactly once.
func (v Variant) NeedsTransportEncoding() bool {
	if len(v.Mutators) == 0 {
		return true
	}
	last, ok := MutatorByName(v.Mutators[len(v.Mutators)-1])
	if !ok {
		return true
	}
	return !last.ProducesEncoded
}

// Count reports how many variants a generation list holds in total.
func Count(generations [][]Variant) int {
	total := 0
	for _, gen := range generations {
		total += len(gen)
	}
	return total
}
