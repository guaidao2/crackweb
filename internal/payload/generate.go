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
	// generationCeiling is the most requests one generation may spend on a single
	// parameter. It is a budget, not a coverage rule: the coverage rule is that
	// every transformation that applies gets sent at least once, and budgetFor
	// guarantees it by never returning less than the number of transformations.
	//
	// When the two disagree — the catalogue has grown past this ceiling — the test
	// in this package fails, so a transformation cannot quietly stop being sent
	// the day somebody adds one.
	generationCeiling = 32
	// maxSeeds bounds how many base payloads are expanded at once.
	//
	// Generation 0 is one request per seed, so this is what a check spends
	// before any mutation happens. It has to be large enough for a check whose
	// coverage *is* its seeds — cross-site scripting needs a distinct closing
	// form for each context a payload can land in, and eight does not reach the
	// attribute cases, nor the spellings that survive a filter which strips the
	// spaces between attributes — and small enough that a target is not flooded.
	// Checks with fewer seeds are unaffected: the limit is a ceiling, not a quota.
	maxSeeds = 32
)

// budgetFor returns how many variants a generation may contribute.
//
// The number is derived from the catalogue rather than fixed: every
// transformation has to reach the wire at least once, so the count of applicable
// transformations is the floor; a second seed each is worth having while the
// request budget allows; and generationCeiling stops a grown catalogue from
// turning one parameter into a flood. Adding a transformation therefore widens
// the generation by a request per seed instead of silently starving whichever
// one sat at the end of the list.
func budgetFor(transformations, seeds int) int {
	if transformations == 0 {
		return 0
	}
	budget := transformations
	if seeds >= 2 {
		budget = transformations * 2
	}
	if budget > generationCeiling {
		budget = generationCeiling
	}
	return budget
}

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
	//
	// The budget is spent mutator-first rather than seed-first. Seed-first gives
	// the first payload in the list every transformation and leaves the rest of
	// them with none — which is backwards, because the transformations are what
	// gets past a filter and each seed is a context somebody has to be able to
	// reach. Mutator-first spreads the same number of requests across the seeds:
	// measured on a real target, the seed-first order reached two of the seven
	// command-injection time seeds and mutator-first reaches all of them.
	// perMutator caps how many seeds one pairing may claim in the deeper
	// generations, so a single combination cannot spend the whole budget before the
	// others are reached.
	const perMutator = 3

	// stageOne is coverage, and it is not subject to the budget: every
	// transformation that can rewrite any of these seeds gets one payload. The rule
	// the budget exists to serve is that no transformation sits in the catalogue
	// unsent, and a transformation that only applies to one shape in the list —
	// `keyword-split-union` needs a UNION, `terminator-to-hash` needs a comment —
	// would be skipped by any round-robin that ran out of budget first.
	//
	// What keeps this from costing more than the ceiling is the catalogue itself:
	// TestTheCatalogueFitsTheCeiling fails if a kind ever has more transformations
	// than the ceiling allows.
	all := make([]Mutator, 0, len(structure)+len(encoding))
	all = append(append(all, structure...), encoding...)
	budget := budgetFor(len(all), len(seeds))

	count := 0
	for _, m := range all {
		for _, seed := range seeds {
			if value := m.Apply(seed); value != seed {
				if add(1, value, []string{m.Name}) {
					count++
				}
				break
			}
		}
	}

	// stageTwo is depth, and it spends what is left: further seeds for the same
	// transformations, so a target that recognises one shape is still reached
	// through another.
	for round := 1; round < len(seeds) && round < perMutator; round++ {
		for _, m := range all {
			if count >= budget {
				break
			}
			if value := m.Apply(seeds[round]); value != seeds[round] {
				if add(1, value, []string{m.Name}) {
					count++
				}
			}
		}
	}

	// Generation 2: a structural rewrite plus an encoding. This is the
	// combination that defeats a WAF which normalises once and matches once —
	// the encoding gets past the normaliser, and the structural rewrite gets
	// past the rule. The budget here is derived from how many pairings exist, so
	// a wider catalogue widens the generation instead of truncating it.
	count = 0
	budget = budgetFor(len(structure)*len(encoding), len(seeds))
spendPair:
	for _, s := range structure {
		for _, e := range encoding {
			spent := 0
			for _, seed := range seeds {
				if count >= budget || spent >= perMutator {
					break
				}
				structural := s.Apply(seed)
				if structural == seed {
					continue
				}
				value := e.Apply(structural)
				if value == structural {
					continue
				}
				if add(2, value, []string{s.Name, e.Name}) {
					count++
					spent++
				}
			}
		}
		if count >= budget {
			break spendPair
		}
	}

	// Generation 3: three deep, and only the widest-reaching pairings. Reserved
	// for targets where nothing else got through. The budget is spent
	// combination-first here too, for the reason given above.
	count = 0
	budget = budgetFor(len(structure)*len(encoding), len(seeds))
spendTriple:
	for _, s := range structure {
		for _, e1 := range encoding {
			for _, e2 := range encoding {
				if e2.Family == e1.Family {
					continue
				}
				spent := 0
				for _, seed := range seeds {
					if count >= budget || spent >= perMutator {
						break
					}
					structural := s.Apply(seed)
					if structural == seed {
						continue
					}
					once := e1.Apply(structural)
					if once == structural {
						continue
					}
					value := e2.Apply(once)
					if value == once {
						continue
					}
					if add(3, value, []string{s.Name, e1.Name, e2.Name}) {
						count++
						spent++
					}
				}
			}
		}
		if count >= budget {
			break spendTriple
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
