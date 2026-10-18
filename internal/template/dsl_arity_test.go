package template

import "testing"

// TestDSLHelpersWithMissingArgumentsReturnAnError: a template is external input, and a
// helper called with fewer arguments than it reads used to panic the check. The scanner
// recovers the panic, so the symptom was a template that silently stopped matching.
func TestDSLHelpersWithMissingArgumentsReturnAnError(t *testing.T) {
	for _, expression := range []string{
		`substr("abc")`,
		`to_number()`,
	} {
		if _, err := Eval(expression, map[string]Value{}); err == nil {
			t.Errorf("Eval(%q) succeeded, want an error", expression)
		}
	}
}
