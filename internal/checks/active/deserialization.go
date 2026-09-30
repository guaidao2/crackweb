package active

import (
	"context"
	"net/url"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// deserializationSeeds are well-formed serialised objects, one per runtime.
//
// They carry no exploit: they are ordinary objects in each format, chosen so that
// a parser recognises them as its own and complains when they are damaged. The
// mutation engine then damages them in the ways a filter would not anticipate,
// which is how a wrapped or re-encoded parameter is reached.
var deserializationSeeds = []string{
	// Java: a serialised HashMap, base64 as java.util.prefs and Spring sessions
	// carry it.
	"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAAAAAAAAAABAwAAeHAAAAAA",
	// Java ObjectStream in the other base64 alphabet, with padding.
	"rO0ABXNyABFqYXZhLm5ldC5VUkkAAAAAAAAAAQIAAHhyABBqYXZhLm5ldC5VUkkAAAAAAAAAAHhw",
	// PHP serialize().
	`O:8:"stdClass":1:{s:4:"test";s:4:"test";}`,
	`a:1:{i:0;s:4:"test";}`,
	// PHP: an object whose class does not exist. `unserialize` still builds it — as
	// `__PHP_Incomplete_Class` — and that name appears for no other reason, so it is
	// evidence the value really went through the deserialiser. Nothing is executed: the
	// point is the object, not a gadget chain.
	`O:9:"NoSuchCls":0:{}`,
	`a:2:{i:0;O:9:"NoSuchCls":0:{}i:1;s:4:"test";}`,
	// .NET BinaryFormatter.
	"AAEAAAD/////AQAAAAAAAAAMAgAAAE5TeXN0ZW0uQ29sbGVjdGlvbnM=",
	// Python pickle, base64 of a small dict.
	"gASVBwAAAAAAAAB9lIwEdGVzdJSFlC4=",
	// Python pickle that names a module that does not exist. `pickle.loads` imports it before
	// anything else, so the failure is a ModuleNotFoundError naming this module — no code
	// runs, and the name in the error is one nothing else would produce.
	"Y2NyYWNrd2VicGlja2xlCm5vdGFmdW5jdGlvbgou",
	// Ruby Marshal.
	"BAh7BkkiCXRlc3QGOhZFVA==",
}

// deserializationSignatures are the errors a parser produces when the bytes are
// not what it expected. They are specific to each runtime, which is what makes
// them usable as evidence rather than as noise.
var deserializationSignatures = []string{
	"java.io.streamcorruptedexception",
	"java.io.invalidclassexception",
	"java.io.objectinputstream",
	"invalid stream header",
	"classnotfoundexception",
	"java.io.eofexception",
	"unserialize()",
	"cannot unserialize",
	"unserialize(): error",
	"__php_incomplete_class",
	"pickle",
	"unpicklingerror",
	// The module the probe above names. Quoted forms are avoided everywhere these signatures
	// are matched, because a page that escapes its output would write &#39; instead and the
	// signature would never match.
	"crackwebpickle",
	"invalidloadkey",
	"binaryformatter",
	"serializationexception",
	"invalidcastexception",
	"system.runtime.serialization",
	"marshal.dump",
	"marshal.load",
	"ruby/marshal",
	"ysoserial",
	"cannot deserialize",
	"deserialization failed",
	"反序列化",
}

// deserialization detects an entry point that parses serialised data from a
// request.
//
// What it confirms and what it does not is worth being precise about. Sending a
// damaged object and receiving the parser's own complaint proves the application
// deserialises attacker-supplied bytes. It does not prove code execution — that
// requires a gadget chain for the exact runtime and version in use.
//
// The distinction is kept in the report rather than papered over, because a
// finding that claims RCE it never demonstrated is worse than one that says
// "this is where you would look".
type deserialization struct{}

func (deserialization) ID() string                 { return "deserialization" }
func (deserialization) TitleKey() i18n.Key         { return i18n.KeyCheckDeserialTitle }
func (deserialization) DescriptionKey() i18n.Key   { return i18n.KeyCheckDeserialDesc }
func (deserialization) RemediationKey() i18n.Key   { return i18n.KeyCheckDeserialFix }
func (deserialization) Severity() finding.Severity { return finding.SeverityHigh }
func (deserialization) Tags() []string {
	return []string{"active", "deserialization", "owasp-top10"}
}
func (deserialization) Passive() bool { return false }

func (deserialization) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	baseline := strings.ToLower(string(t.Response.Body))
	c.ProbeWAF(ctx, t)

	var matched string
	attempt, err := c.SendVariants(ctx, t, payload.Generic, "deserialization", deserializationSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, variant payload.Variant) bool {
			matched = firstNewSignatureNotEchoed(
				strings.ToLower(string(resp.Body)), baseline, deserializationSignatures, strings.ToLower(variant.Value))
			return matched != ""
		})
	if err != nil || attempt == nil {
		// Nothing came back in the response. Java's JSON deserialisers can still be asked to
		// resolve a name, and the resolution is the proof: the value is turned into an address
		// before anything else happens, so a hostname the scan controls comes to the resolver.
		if f := deserializationCallback(ctx, c, t); f != nil {
			return []*finding.Finding{f}
		}
		return nil
	}

	f := checks.NewFinding(deserialization{}, t,
		i18n.KeyCheckDeserialTitle, i18n.KeyCheckDeserialDesc, i18n.KeyCheckDeserialFix)
	f.Severity = finding.SeverityHigh
	// Firm rather than certain: the entry point is proven, the impact is not.
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-502"
	f.References = []string{
		"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
		"https://cwe.mitre.org/data/definitions/502.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{matched, variantNote(c, attempt)}
	f.Evidence.Diff = extractAround(string(attempt.Response.Body), matched, 240)
	return []*finding.Finding{f}
}

// deserializationOOBSeeds ask a Java JSON deserialiser to resolve a name.
//
// The type in the payload turns its value into a network address, which means the runtime
// resolves it first — and a name only the scan knows resolves to the scan. That is the whole
// evidence: no class is instantiated and no code runs, but the parser built a value the caller
// chose, which is the entry point every gadget chain needs.
//
// These only work with a delegated domain (--oob-domain). Without one the callback name is an
// address, and an address is not resolved — so the payloads are never sent, and nothing is spent
// on a technique that cannot answer.
var deserializationOOBSeeds = []string{
	`{"@type":"java.net.Inet4Address","val":"` + checks.CallbackHost + `"}`,
	`{"@type":"java.net.InetAddress","val":"` + checks.CallbackHost + `"}`,
	`{"@type":"java.net.InetSocketAddress","val":"` + checks.CallbackHost + `:80"}`,
	// Jackson's default typing writes the same thing as an array.
	`["java.net.Inet4Address",["` + checks.CallbackHost + `"]]`,
	// A framework may unwrap one object to find the type inside it.
	`{"val":{"@type":"java.net.Inet4Address","val":"` + checks.CallbackHost + `"}}`,
}

// deserializationCallback sends the resolving payloads and reports the first one that came back.
func deserializationCallback(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	if c.OOB == nil {
		return nil
	}
	// These payloads work by being resolved, and only a name is resolved. Whether the callback
	// the server hands out is a name or an address decides whether there is anything to send:
	// with no delegated domain it is an address, the payloads would be asking the runtime to
	// resolve `10.0.0.5`, and nothing would come back.
	callbackURL, _ := c.OOB.NewURL("deserialization")
	address, err := url.Parse(callbackURL)
	if err != nil || address.Hostname() == "" || !strings.ContainsFunc(address.Hostname(), isLetter) {
		return nil
	}
	attempt, err := c.ProbeOOB(ctx, t, "deserialization", deserializationOOBSeeds, 0)
	if err != nil || attempt == nil || len(attempt.Interactions) == 0 {
		return nil
	}

	f := checks.NewFinding(deserialization{}, t,
		i18n.KeyCheckDeserialTitle, i18n.KeyCheckDeserialDesc, i18n.KeyCheckDeserialFix)
	f.Severity = finding.SeverityHigh
	// Firm, not certain: the entry point is proven — the parser resolved a name the caller
	// chose — and what could be done with it is not something this request can show.
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-502"
	f.References = []string{
		"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
		"https://cwe.mitre.org/data/definitions/502.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 2048)
	f.Evidence.Matches = []string{
		"the target resolved the name carried in the payload and connected back to it",
		describeInteraction(c, attempt),
		"the parser built an address from a value the caller wrote, which is the entry point a " +
			"gadget chain needs; no class was instantiated by this request",
	}
	return f
}

// isLetter reports whether a rune is one of the ASCII letters.
func isLetter(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}
