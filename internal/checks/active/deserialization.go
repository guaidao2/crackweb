package active

import (
	"context"
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
	// .NET BinaryFormatter.
	"AAEAAAD/////AQAAAAAAAAAMAgAAAE5TeXN0ZW0uQ29sbGVjdGlvbnM=",
	// Python pickle, base64 of a small dict.
	"gASVBwAAAAAAAAB9lIwEdGVzdJSFlC4=",
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
