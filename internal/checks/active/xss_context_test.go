package active

import "testing"

// TestExecutableContext is the judgement the reflected check rests on: a payload
// that appears in the response is not automatically one that a browser runs.
func TestExecutableContext(t *testing.T) {
	const payload = "<script>alert(1)</script>"

	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{
			name: "plain body",
			body: "<html><body><p>" + payload + "</p></body></html>",
			want: true,
		},
		{
			name: "inside a comment",
			body: "<html><body><!-- " + payload + " --></body></html>",
			want: false,
		},
		{
			name: "inside a textarea",
			body: "<html><body><textarea>" + payload + "</textarea></body></html>",
			want: false,
		},
		{
			name: "inside a title",
			body: "<html><head><title>" + payload + "</title></head></html>",
			want: false,
		},
		{
			name: "inside an attribute value",
			body: `<html><body><input value="` + payload + `"></body></html>`,
			want: false,
		},
		{
			name: "closing the attribute first",
			body: `<html><body><input value="` + `"><script>alert(1)</script>` + `"></body></html>`,
			want: true,
		},
		{
			name: "after a closed textarea",
			body: "<html><body><textarea>old</textarea>" + payload + "</body></html>",
			want: true,
		},
		{
			name: "marker absent",
			body: "<html><body>nothing here</body></html>",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := payload
			if tc.name == "closing the attribute first" {
				marker = `"><script>alert(1)</script>`
			}
			if got := executableContext(tc.body, marker); got != tc.want {
				t.Errorf("executableContext(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestDescribeContextNamesThePlace: the evidence has to say where the payload
// landed, or a reader cannot judge the finding.
func TestDescribeContextNamesThePlace(t *testing.T) {
	const payload = "<script>alert(1)</script>"
	cases := map[string]string{
		"<html><body>" + payload + "</body></html>":                             "in the document body",
		"<html><body><script>var a = '" + payload + "';</script></body></html>": "inside a script block",
		`<html><body><input value="` + payload + `"></body></html>`:             "in an attribute, closing it first",
	}
	for body, want := range cases {
		if got := describeContext(body, payload); got != want {
			t.Errorf("describeContext = %q, want %q", got, want)
		}
	}
}
