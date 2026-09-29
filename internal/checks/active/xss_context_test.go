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
		{
			// A javascript: URL carries no markup characters, so in a text node
			// it is inert — it only runs from a URL-bearing attribute.
			name: "javascript url in body text",
			body: "<html><body><p>Results for: javascript:alert(1)</p></body></html>",
			want: false,
		},
		{
			// The same string, echoed back into an ordinary form field. A browser never
			// follows `value` as a URL, so this is inert however it looks.
			name: "javascript url in a form value",
			body: `<html><body><input type="hidden" name="category" value="javascript:alert(1)"></body></html>`,
			want: false,
		},
		{
			// And the event-handler spelling, which also needs to leave the attribute to
			// do anything: inside the value it is just text.
			name: "event handler inside a form value",
			body: `<html><body><input type="text" name="q" value=" autofocus onfocus=alert(1)"></body></html>`,
			want: false,
		},
		{
			name: "javascript url in an href",
			body: `<html><body><a href="javascript:alert(1)">click</a></body></html>`,
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := payload
			switch tc.name {
			case "closing the attribute first":
				marker = `"><script>alert(1)</script>`
			case "javascript url in body text", "javascript url in an href",
				"javascript url in a form value":
				marker = "javascript:alert(1)"
			case "event handler inside a form value":
				marker = " autofocus onfocus=alert(1)"
			}
			if got := executableContext(tc.body, marker); got != tc.want {
				t.Errorf("executableContext(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestDescribeContextNamesThePlace: the evidence has to say where the payload
// landed, or a reader cannot judge the finding. Each case carries its own marker,
// because what matters is where that exact string sits.
func TestDescribeContextNamesThePlace(t *testing.T) {
	const payload = "<script>alert(1)</script>"
	const escaping = `"><img src=x onerror=alert(1)>`
	for _, tc := range []struct {
		name   string
		body   string
		marker string
		want   string
	}{
		{
			name:   "document body",
			body:   "<html><body>" + payload + "</body></html>",
			marker: payload,
			want:   "in the document body",
		},
		{
			name:   "script block",
			body:   "<html><body><script>var a = '" + payload + "';</script></body></html>",
			marker: payload,
			want:   "inside a script block",
		},
		{
			// Starts with `<`, so it does not close the attribute — it sits inside the value.
			name:   "inside an attribute value",
			body:   `<html><body><input value="` + payload + `"></body></html>`,
			marker: payload,
			want:   "inside an attribute value",
		},
		{
			name:   "after closing the attribute",
			body:   `<html><body><input value="` + escaping + `"></body></html>`,
			marker: escaping,
			want:   "in an attribute, after closing it",
		},
		{
			name:   "URL-bearing attribute",
			body:   `<html><body><a href="javascript:alert(1)">x</a></body></html>`,
			marker: "javascript:alert(1)",
			want:   "in a URL-bearing attribute",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeContext(tc.body, tc.marker); got != tc.want {
				t.Errorf("describeContext = %q, want %q", got, tc.want)
			}
		})
	}
}
