package crawl

import (
	"net/url"
	"strings"
	"testing"
)

func TestScriptTargetsFindsEndpointsThePageCalls(t *testing.T) {
	base, _ := url.Parse("http://example.com/documents")
	body := `<html><body><script>
		const r = await fetch('/api/documents/search?keyword=' + encodeURIComponent(k));
		await fetch("/api/documents/upload", { method: 'POST' });
		await fetch(` + "`" + `/api/documents/${id}` + "`" + `);
		xhr.open('GET', '/api/users/me');
		axios.delete('/api/announcements/3');
	</script></body></html>`

	// scriptCalls sees every call; scriptTargets only turns the reads into links.
	got := make([]string, 0)
	for _, call := range scriptCalls(body, base, true) {
		got = append(got, call.URL)
	}
	want := map[string]bool{
		"http://example.com/api/documents/search?keyword=": true, // the query is built at runtime
		"http://example.com/api/documents/upload":          true,
		"http://example.com/api/documents/1":               true,
		"http://example.com/api/users/me":                  true,
		"http://example.com/api/announcements/3":           true,
	}
	for _, address := range got {
		delete(want, address)
	}
	if len(want) != 0 {
		t.Errorf("these endpoints were missed: %v (got %v)", want, got)
	}
	if len(got) == 0 {
		t.Fatal("nothing was extracted at all")
	}
}

// TestScriptTargetsIgnoresWhatIsNotAnEndpoint: a script is full of paths, and most of them
// are not requests. Queueing them costs a request each and finds nothing.
func TestScriptTargetsIgnoresWhatIsNotAnEndpoint(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := `<html><head>
	<link rel="stylesheet" href="/static/css/style.css">
	<script src="/static/js/app.js"></script>
	</head><body>
	<img src="/static/logo.png">
	<script>
		window.location = '/dashboard';
		const label = 'the /static/ path';
	</script></body></html>`
	if got := scriptTargets(body, base, false); len(got) != 0 {
		t.Errorf("non-endpoints were queued: %v", got)
	}
}

// TestScriptTargetsStaysInScope: the same rule the rest of the crawler follows. A script
// naming another host's API is not an invitation.
func TestScriptTargetsStaysInScope(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := `<script>fetch('https://other.example.net/api/collect');</script>`
	if got := scriptTargets(body, base, false); len(got) != 0 {
		t.Errorf("an off-host endpoint was queued: %v", got)
	}
}

// TestScriptTargetsDeduplicates: the same path appears in several handlers, and it is one
// endpoint.
func TestScriptTargetsDeduplicates(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := `<script>
		fetch('/api/messages');
		fetch('/api/messages');
		xhr.open('GET', '/api/messages');
	</script>`
	if got := scriptTargets(body, base, false); len(got) != 1 {
		t.Errorf("got %d addresses, want 1: %v", len(got), got)
	}
}

// TestScriptTargetsSkipsWriteEndpointsByDefault: the crawler fetches what it discovers with
// GET, and a GET to an address whose own script says "delete" is not obviously harmless to
// whatever is behind it. Queueing those is what the flag is for.
func TestScriptTargetsSkipsWriteEndpointsByDefault(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := `<script>
		fetch('/api/documents');
		fetch('/api/documents/1', { method: 'DELETE' });
		xhr.open('POST', '/api/announcements');
		axios.put('/api/rules/1');
		axios.get('/api/users/me');
	</script>`

	safe := scriptTargets(body, base, false)
	want := map[string]bool{
		"http://example.com/api/documents": true,
		"http://example.com/api/users/me":  true,
	}
	for _, address := range safe {
		if !want[address] {
			t.Errorf("%s was queued but its script writes", address)
		}
		delete(want, address)
	}
	if len(want) != 0 {
		t.Errorf("these safe endpoints were skipped: %v (got %v)", want, safe)
	}

	// With the flag, the writes are discovered too — as calls to replay.
	all := scriptCalls(body, base, true)
	if len(all) <= len(safe) {
		t.Errorf("--allow-state-change found %d calls, same as without it (%d)", len(all), len(safe))
	}
	writes := 0
	for _, call := range all {
		if !safeMethods[call.Method] {
			writes++
		}
	}
	if writes == 0 {
		t.Errorf("no writes were found: %v", all)
	}
}

// TestScriptTargetsTreatsAMethodlessCallAsARead: fetch with no options is a GET, which is
// how most of these calls are written.
func TestScriptTargetsTreatsAMethodlessCallAsARead(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := `<script>fetch('/api/documents');</script>`
	if got := scriptTargets(body, base, false); len(got) != 1 {
		t.Errorf("a methodless fetch was skipped: %v", got)
	}
}

// TestScriptCallsReadsTheMethodAndBody: a discovered address is not a tested request. The
// method and the body shape are what make it one — an upload endpoint reached with GET has
// nothing to say.
func TestScriptCallsReadsTheMethodAndBody(t *testing.T) {
	base, _ := url.Parse("http://example.com/")
	body := `<script>
		async function send() {
			const fd = new FormData();
			fd.append('title', document.getElementById('docTitle').value);
			fd.append('file', document.getElementById('docFile').files[0]);
			await fetch('/api/documents/upload', { method: 'POST', body: fd });
		}
		function save() {
			fetch('/api/documents', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ title: docTitle, content: docContent })
			});
		}
		fetch('/api/documents/search?keyword=k');
	</script>`

	byURL := map[string]scriptCall{}
	for _, call := range scriptCalls(body, base, true) {
		byURL[call.URL] = call
	}

	upload, ok := byURL["http://example.com/api/documents/upload"]
	if !ok {
		t.Fatalf("the upload call was missed: %v", byURL)
	}
	if upload.Method != "POST" {
		t.Errorf("upload method = %q, want POST", upload.Method)
	}
	if upload.Body != bodyMultipart {
		t.Errorf("upload body = %v, want multipart", upload.Body)
	}
	if len(upload.Fields) != 2 || upload.Fields[0] != "title" || upload.Fields[1] != "file" {
		t.Errorf("upload fields = %v, want [title file]", upload.Fields)
	}

	create, ok := byURL["http://example.com/api/documents"]
	if !ok {
		t.Fatalf("the create call was missed: %v", byURL)
	}
	if create.Body != bodyJSON {
		t.Errorf("create body = %v, want JSON", create.Body)
	}
	if len(create.Fields) != 2 || create.Fields[0] != "title" || create.Fields[1] != "content" {
		t.Errorf("create fields = %v, want [title content]", create.Fields)
	}

	search, ok := byURL["http://example.com/api/documents/search?keyword=k"]
	if !ok {
		t.Fatalf("the search call was missed: %v", byURL)
	}
	if search.Method != "GET" || search.Body != bodyNone {
		t.Errorf("search = %s/%v, want GET with no body", search.Method, search.Body)
	}
}

// TestEncodeScriptMultipartGivesTheFileFieldAFile: an endpoint that checks the media type
// before anything else is checking this header, and a check that needs a file part has
// nothing to look at without one.
func TestEncodeScriptMultipartGivesTheFileFieldAFile(t *testing.T) {
	body, contentType := encodeScriptMultipart([]string{"title", "file"})
	text := string(body)
	if !strings.Contains(contentType, "multipart/form-data") {
		t.Errorf("content type = %q", contentType)
	}
	if !strings.Contains(text, `name="title"`) || !strings.Contains(text, "crackweb") {
		t.Errorf("the text field is missing:\n%s", text)
	}
	if !strings.Contains(text, `name="file"; filename=`) {
		t.Errorf("the file field has no filename:\n%s", text)
	}
	if !strings.Contains(text, "Content-Type: image/png") {
		t.Errorf("the file part has no media type:\n%s", text)
	}
}
