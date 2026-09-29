package active

import "testing"

func TestEchoOnlyInBody(t *testing.T) {
	const canary = hostCanary
	cases := []struct {
		name   string
		body   string
		header string
		want   bool
	}{
		{
			name:   "the page printed the request it received",
			body:   "<pre>GET / HTTP/1.1\r\nHost: " + canary + "\r\nUser-Agent: x\r\n</pre>",
			header: "Host",
			want:   true,
		},
		{
			name:   "the application built a link out of the value",
			body:   `<a href="http://` + canary + `/reset">reset</a>`,
			header: "Host",
			want:   false,
		},
		{
			name:   "one appearance is a dump and another is not",
			body:   "<pre>Host: " + canary + "</pre><a href=\"http://" + canary + "/x\">x</a>",
			header: "Host",
			want:   false,
		},
		{
			name:   "a forwarded field dumped verbatim",
			body:   "Forwarded: host=" + canary,
			header: "Forwarded",
			want:   true,
		},
		{
			name:   "the value shows up under a different header name",
			body:   "X-Forwarded-Host: " + canary,
			header: "Host",
			want:   false,
		},
		{
			name:   "no canary at all",
			body:   "nothing to see",
			header: "Host",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := echoOnlyInBody(tc.body, tc.header, canary); got != tc.want {
				t.Errorf("echoOnlyInBody(%q, %q) = %v, want %v", tc.body, tc.header, got, tc.want)
			}
		})
	}
}
