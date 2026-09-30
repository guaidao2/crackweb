package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file holds one test per payload that was added to close a coverage gap,
// and nothing else. Each one is a target that answers the new shape and refuses
// every older one, so the test fails if the seed is dropped — or if the judgement
// stops recognising what the seed produces. A payload nobody can recognise is the
// same as no payload at all.

// TestPathTraversalFiresOnHostsFile covers `/etc/hosts`, which was reachable
// before only by accident: the file carries no `root:x:0:0` line, so the check
// had a path with no signature to match and could never report it.
func TestPathTraversalFiresOnHostsFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "/etc/hosts") {
			fmt.Fprint(w, "<pre>127.0.0.1\tlocalhost\n127.0.1.1\tbuild-box\n"+
				"::1\tlocalhost ip6-localhost ip6-loopback</pre>")
			return
		}
		fmt.Fprint(w, "<html><body>file not found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/?file=readme.txt")
	if len(findings) == 0 {
		t.Fatal("a readable /etc/hosts was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "localhost ip6-localhost") {
		t.Errorf("the evidence does not quote the file: %v", findings[0].Evidence.Matches)
	}
}

// TestPathTraversalFiresOnPHPFilterWrapper covers `php://filter`, whose whole
// point is that the file arrives encoded: the read happened, and a check that
// looked only at the body as it stands would miss it. What the evidence quotes is the file's
// own line, decoded, with the encoding named — a reader can check it against the file rather
// than against a string they would have to decode first.
func TestPathTraversalFiresOnPHPFilterWrapper(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "php://filter") {
			fmt.Fprint(w, "<pre>cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo=</pre>")
			return
		}
		fmt.Fprint(w, "<html><body>file not found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, pathTraversal{}, server.URL+"/?file=readme.txt")
	if len(findings) == 0 {
		t.Fatal("a php://filter read was not reported")
	}
	evidence := strings.Join(findings[0].Evidence.Matches, " ")
	if !strings.Contains(evidence, "root:x:0:0") {
		t.Errorf("the evidence does not quote the file: %v", findings[0].Evidence.Matches)
	}
	if !strings.Contains(evidence, "through an encoding") {
		t.Errorf("the evidence does not say the body was encoded: %v", findings[0].Evidence.Matches)
	}
}

// TestSSTIFiresOnHandlebarsTripleStash covers the engines that are not the
// double-brace family. A page that evaluates `{{{ }}}` evaluates none of the
// seeds the check used to send, so the target looked clean.
func TestSSTIFiresOnHandlebarsTripleStash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Only the triple-stash form is evaluated here, so the test fails if that
		// seed goes away rather than passing on an older one.
		if strings.Contains(name, "{{{1999*1999}}}") {
			fmt.Fprint(w, "<html><body><h1>Hello 3996001</h1></body></html>")
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello %s</h1></body></html>", name)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, ssti{}, server.URL+"/?name=world")
	if len(findings) == 0 {
		t.Fatal("a template expression that was evaluated was not reported")
	}
	if !strings.Contains(findings[0].Payload, "{{{") {
		t.Errorf("payload = %q, want the delimiter the target evaluates", findings[0].Payload)
	}
}

// TestNoSQLFiresOnArrayOperators covers `$or` and `$nin`, the operators used in
// place of `$ne` when a filter has learned to strip the simple ones. The mock
// recognises only those two, so the test fails if either seed goes away.
func TestNoSQLFiresOnArrayOperators(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		if strings.Contains(username, "$or") || strings.Contains(username, "$nin") {
			fmt.Fprint(w, "<html><body>MongoError: unknown top level operator</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>Welcome</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := withParameter(t, h, nosqli{}, server.URL+"/login?username=admin")
	if len(findings) == 0 {
		t.Fatal("a MongoDB operator error was not reported")
	}
	if !strings.Contains(findings[0].Payload, "$or") && !strings.Contains(findings[0].Payload, "$nin") {
		t.Errorf("payload = %q, want an array operator", findings[0].Payload)
	}
}

// TestCommandInjectionCoversBracedIFS pins the `${IFS}` spelling. The mutation
// engine produces the bare `$IFS`, which a filter that strips that exact string
// leaves untouched on the braced form — and the shell reads both.
func TestCommandInjectionCoversBracedIFS(t *testing.T) {
	found := false
	for _, seed := range commandInjectionSeeds {
		if strings.Contains(seed, "${IFS}") {
			found = true
		}
	}
	if !found {
		t.Error("no ${IFS} seed: a filter that strips $IFS would hide the injection")
	}
}

// TestXXECoversXIncludeAndJavaSchemes covers the two shapes the seeds were
// missing: XInclude, which reaches a file without a DOCTYPE at all, and the
// Java-only scheme that reads a document where `file://` would not.
func TestXXECoversXIncludeAndJavaSchemes(t *testing.T) {
	var xinclude, netdoc bool
	for _, seed := range xxeSeeds {
		if strings.Contains(seed, "xi:include") {
			xinclude = true
		}
		if strings.Contains(seed, "netdoc://") {
			netdoc = true
		}
	}
	if !xinclude {
		t.Error("no XInclude seed: a parser that blocks DOCTYPE is still reachable")
	}
	if !netdoc {
		t.Error("no netdoc:// seed: a Java parser reads files through it")
	}
}

// TestOracleErrorSeedsArePresent pins the two Oracle spellings and the signature
// that names any of their codes. `ORA-29257` from an out-of-band call does not
// start with `ORA-0`, so a prefix match is what covers them.
func TestOracleErrorSeedsArePresent(t *testing.T) {
	seed := false
	for _, s := range sqlErrorSeeds {
		if strings.Contains(s, "utl_inaddr") || strings.Contains(s, "ctxsys") {
			seed = true
		}
	}
	if !seed {
		t.Error("no Oracle error-based seed")
	}
	signature := false
	for _, s := range sqlErrorSignatures {
		if s == "ora-" {
			signature = true
		}
	}
	if !signature {
		t.Error("the Oracle signature does not cover ORA-29257 and friends")
	}
}
