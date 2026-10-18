package active

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

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

// deserializationReferences are the background a reader needs, the same for every finding
// this check produces.
var deserializationReferences = []string{
	"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
	"https://cwe.mitre.org/data/definitions/502.html",
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
		// A JSON body and a JSON-valued parameter are asked a different way, because the
		// value has to be the @type object itself rather than a string that contains it.
		if f := deserializationAutoType(ctx, c, t); f != nil {
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
	f.References = deserializationReferences
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
	f.References = deserializationReferences
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

// The generic seeds above replace a parameter's value with a serialised object. That is the
// right shape for a query string or a form field and the wrong one for a JSON document: the
// document rewriter in httpmsg quotes every payload as a JSON string, so what reaches the
// target is a JSON string whose contents happen to be an object — and neither fastjson nor
// Jackson reads a type id out of a string.
//
// The probes below ask the same question of a JSON body and of a JSON-valued parameter the
// way those parsers can answer it: the addressed field is replaced with the object itself, so
// the parser sees `{"@type":...}` where it looks for one. Nothing here is a gadget chain. The
// payload names one of the JDK's own address classes, whose deserialiser turns a string into a
// host, so the most a successful probe can make the target do is resolve a name the scan
// chose — and where no name can be delegated, the probe names a type that cannot exist and
// reports the parser's own complaint instead.

// deserializationAutoTypeObjects are the values planted in place of a JSON field.
//
// Each is a benign auto-type object naming a class whose deserialiser resolves a string into a
// host. The object carries no method call, no gadget and nothing executable: the only thing
// the target can do with it is look the name up.
var deserializationAutoTypeObjects = []string{
	`{"@type":"java.net.Inet4Address","val":"` + checks.CallbackHost + `"}`,
	`{"@type":"java.net.InetAddress","val":"` + checks.CallbackHost + `"}`,
	`{"@type":"java.net.InetSocketAddress","val":"` + checks.CallbackHost + `:80"}`,
	// Jackson's default typing writes the same thing as an array: the type id first, the
	// value it applies to second.
	`["java.net.Inet4Address","` + checks.CallbackHost + `"]`,
}

// deserializationAutoTypeMiss is the type named when no callback can be delegated. Nothing
// can resolve it, so the parser's complaint about it is the whole of the evidence — and the
// name is one nothing but this probe would put in a response.
const deserializationAutoTypeMiss = "crackweb.nosuch.AutotypeProbe"

// deserializationAutoTypeMissSeeds ask the parser what it makes of a type it cannot know.
//
// The object form is fastjson's spelling and the array form is Jackson's. Both are well-formed
// JSON: the document parses and only the type id is unsatisfiable, so the answer tells a
// parser that reads type ids apart from one that never looks.
var deserializationAutoTypeMissSeeds = []string{
	`{"@type":"` + deserializationAutoTypeMiss + `"}`,
	`["` + deserializationAutoTypeMiss + `",{}]`,
}

// deserializationAutoTypeSignatures are the complaints only a parser that read the @type
// member produces, in the spelling of each library that reads one.
//
// The list is deliberately short, and the library names are deliberately absent: a Jackson or
// fastjson stack trace appears in the answer to any value the application's own data binding
// did not expect — a handler whose field is a string rejects an object with a
// MismatchedInputException, which says nothing about type ids and would flag every JSON API
// there is. What is kept is only the wording those libraries produce when the type id is what
// they were looking for.
//
// None of them can appear in a payload, which is what keeps a page that repeats its input from
// being reported. Quoted forms are avoided: a page that escapes what it prints would write
// &quot; instead, and a signature carrying a quote would never match.
var deserializationAutoTypeSignatures = []string{
	// fastjson, in both its spellings: the 1.x one and the 2.x one. It produces them when the
	// value carried a type id it was asked to honour, which means it read the member.
	"autotype is not support",
	"not support autotype",
	// Jackson's default typing unable to resolve the id it was given.
	"could not resolve type id",
	"invalidtypeidexception",
	// Jackson's default typing expecting a type wrapper and finding none, in the two forms
	// that message takes.
	"need json array to contain as.wrapper_array",
	"need json string that contains type id",
}

// autoTypePollInterval is how often the interaction server is checked while waiting. The
// proof arrives on another connection, so it cannot be read from the response.
const autoTypePollInterval = 250 * time.Millisecond

// autoTypeSeed is one value the probe plants, with the callback token that would prove it.
type autoTypeSeed struct {
	// object is the value written in place of the addressed field, as raw JSON.
	object string
	// token correlates a callback back to this payload. Empty when no callback is expected.
	token string
}

// autoTypeAttempt is one planted value, the request that carried it and what came back.
type autoTypeAttempt struct {
	object       string
	token        string
	signature    string
	request      *httpmsg.Request
	response     *httpmsg.Response
	interactions []checks.Interaction
}

// autoTypeCarrier reports whether the parameter's value is written inside a JSON document,
// which is the only place an @type object can be planted as a field.
//
// A query or form value is addressed directly and is already covered by the generic seeds. A
// JSON body field and a field of a JSON document carried as another parameter's value are the
// two shapes this probe exists for.
func autoTypeCarrier(param *httpmsg.Param) bool {
	if param == nil {
		return false
	}
	// A field of a JSON body is addressable whatever wrapper the value itself uses: the
	// enclosing document is what an @type member is planted in, and RawName and
	// Occurrence still find the field. Asking about the location first keeps a base64
	// scalar inside a JSON body covered, which it would not be if the wrapper decided.
	switch param.In {
	case httpmsg.LocJSON, httpmsg.LocJSONBase64:
		return true
	}
	switch param.Wrapper {
	case httpmsg.WrapJSON, httpmsg.WrapBase64JSON:
		return param.In == httpmsg.LocQuery || param.In == httpmsg.LocBody
	}
	return false
}

// deserializationAutoType asks a JSON parser to honour an @type member the request carries.
//
// It is the JSON-shaped half of this check and it runs only after the generic seeds have
// produced nothing. Two ways of answering are supported, and which one is used is decided by
// whether a name can be delegated: a real callback when the scan owns a domain, and the
// parser's own complaint about a type it cannot resolve otherwise. Either one proves what this
// check claims — that the value the request carried reached a parser that reads type ids — and
// neither claims code execution, which no request of this shape can demonstrate.
func deserializationAutoType(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	if c == nil || t == nil || t.Request == nil || t.Param == nil || !autoTypeCarrier(t.Param) {
		return nil
	}
	baseline := strings.ToLower(string(t.Response.Body))

	seeds, callback := deserializationAutoTypePayloads(c)
	if len(seeds) == 0 {
		return nil
	}

	sent := make([]autoTypeAttempt, 0, len(seeds))
	for _, seed := range seeds {
		request, ok := autoTypeRequest(t.Request, *t.Param, seed.object)
		if !ok {
			continue
		}
		response, err := c.Do(ctx, request)
		if err != nil || response == nil {
			continue
		}
		// A refused request proves nothing about what the target does with the value, and an
		// edge that answers with its own error page could otherwise be read as the parser's
		// complaint.
		if c.WAF.IsBlocked(request.Hostname(), response) {
			continue
		}
		attempt := autoTypeAttempt{
			object:   seed.object,
			token:    seed.token,
			request:  request,
			response: response,
		}
		attempt.signature = firstNewSignatureNotEchoed(
			strings.ToLower(string(response.Body)), baseline,
			deserializationAutoTypeSignatures, strings.ToLower(seed.object))
		sent = append(sent, attempt)
	}

	// The parser's complaint is read first: it arrives with the response, while a callback has
	// to be waited for, and a parser that refused the type id is not going to resolve the name
	// as well.
	for _, attempt := range sent {
		if attempt.signature != "" {
			return autoTypeErrorFinding(c, t, attempt)
		}
	}
	if !callback {
		return nil
	}
	if attempt := awaitAutoTypeCallback(ctx, c, sent); attempt != nil {
		return autoTypeCallbackFinding(c, t, *attempt)
	}
	return nil
}

// deserializationAutoTypePayloads returns the values to plant and whether a callback is
// expected in answer.
//
// A callback payload works by being resolved, and only a name is resolved. Whether the callback
// the server hands out is a name or an address therefore decides which payloads are worth
// sending: with no delegated domain it is an address, the payloads would be asking the parser
// to resolve `10.0.0.5`, and nothing would ever come back.
func deserializationAutoTypePayloads(c *checks.Context) ([]autoTypeSeed, bool) {
	if c.OOB == nil {
		return autoTypeMissSeeds(), false
	}
	seeds := make([]autoTypeSeed, 0, len(deserializationAutoTypeObjects))
	for _, shape := range deserializationAutoTypeObjects {
		callbackURL, token := c.OOB.NewURL("deserialization")
		address, err := url.Parse(callbackURL)
		if err != nil || address.Hostname() == "" || !strings.ContainsFunc(address.Hostname(), isLetter) {
			return autoTypeMissSeeds(), false
		}
		seeds = append(seeds, autoTypeSeed{
			object: strings.ReplaceAll(shape, checks.CallbackHost, address.Hostname()),
			token:  token,
		})
	}
	return seeds, true
}

// autoTypeMissSeeds returns the payloads that ask about a type nothing can resolve.
func autoTypeMissSeeds() []autoTypeSeed {
	seeds := make([]autoTypeSeed, 0, len(deserializationAutoTypeMissSeeds))
	for _, object := range deserializationAutoTypeMissSeeds {
		seeds = append(seeds, autoTypeSeed{object: object})
	}
	return seeds
}

// awaitAutoTypeCallback polls the interaction server until one of the planted values has been
// resolved, or the wait expires.
func awaitAutoTypeCallback(ctx context.Context, c *checks.Context, sent []autoTypeAttempt) *autoTypeAttempt {
	wait := c.OOBWait
	if wait <= 0 {
		wait = checks.OOBWait
	}
	deadline := time.Now().Add(wait)
	for {
		for index := range sent {
			if sent[index].token == "" {
				continue
			}
			if interactions := c.OOB.Poll(sent[index].token); len(interactions) > 0 {
				sent[index].interactions = interactions
				return &sent[index]
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-time.After(autoTypePollInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

// autoTypeRequest rebuilds the request so that the value the parameter addresses is the
// auto-type object itself.
//
// The document rewriter in httpmsg quotes every payload as a JSON string, which is right for an
// injected value and wrong here: fastjson and Jackson read `@type` from an object, and a string
// that contains an object is just a string to both of them. So the field's bytes are replaced
// with the object as it is written, and every other field keeps its position, its spacing and
// its escaping.
func autoTypeRequest(req *httpmsg.Request, param httpmsg.Param, object string) (*httpmsg.Request, bool) {
	if req == nil {
		return nil, false
	}
	switch param.In {
	case httpmsg.LocJSON, httpmsg.LocJSONBase64:
		out := req.Clone()
		document, encoding, ok := jsonBodyDocument(out.Body, param.In)
		if !ok {
			return nil, false
		}
		updated, ok := spliceJSONValue(document, param.RawName, param.Occurrence, object)
		if !ok {
			return nil, false
		}
		body := updated
		if encoding != nil {
			body = []byte(encoding.EncodeToString(updated))
		}
		out.Body = body
		out.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return out, true

	case httpmsg.LocQuery, httpmsg.LocBody:
		return wrappedAutoTypeRequest(req, param, object)

	default:
		return nil, false
	}
}

// wrappedAutoTypeRequest rebuilds a request whose addressed value lives inside a JSON document
// carried as another parameter's value, e.g. `?id={"uid":1}`.
//
// The envelope is rebuilt rather than replaced: the document is decoded, the field inside it is
// rewritten, and the result is put back in the same shape, so the parameter still parses when
// the target reads it.
func wrappedAutoTypeRequest(req *httpmsg.Request, param httpmsg.Param, object string) (*httpmsg.Request, bool) {
	if param.Wrapper != httpmsg.WrapJSON && param.Wrapper != httpmsg.WrapBase64JSON {
		return nil, false
	}
	out := req.Clone()

	var container string
	switch param.In {
	case httpmsg.LocQuery:
		if out.URL == nil {
			return nil, false
		}
		container = out.URL.RawQuery
	case httpmsg.LocBody:
		container = string(out.Body)
	default:
		return nil, false
	}

	parts := strings.Split(container, "&")
	seen := 0
	for index, part := range parts {
		name, rawValue, _ := strings.Cut(part, "=")
		if name != param.Outer {
			continue
		}
		if seen != param.OuterOccurrence {
			seen++
			continue
		}

		document := []byte(decodeParameterValue(rawValue))
		var encoding *base64.Encoding
		if param.Wrapper == httpmsg.WrapBase64JSON {
			decoded, decodedWith, ok := jsonBodyDocument(document, httpmsg.LocJSONBase64)
			if !ok {
				return nil, false
			}
			document, encoding = decoded, decodedWith
		}

		if len(param.Path) > 1 {
			// spliceJSONValue matches a leaf name across the whole document; a nested path
			// such as b.id would otherwise rewrite the first "id" it finds, which may be
			// a different field. Nested fields are left to the generic JSON checks.
			return nil, false
		}
		updated, ok := spliceJSONValue(document, param.RawName, param.Occurrence, object)
		if !ok {
			return nil, false
		}
		value := string(updated)
		if encoding != nil {
			value = encoding.EncodeToString(updated)
		}
		parts[index] = name + "=" + url.QueryEscape(value)

		rewritten := strings.Join(parts, "&")
		switch param.In {
		case httpmsg.LocQuery:
			out.URL.RawQuery = rewritten
		case httpmsg.LocBody:
			out.Body = []byte(rewritten)
			out.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
		}
		return out, true
	}
	return nil, false
}

// decodeParameterValue percent-decodes one on-the-wire parameter value, falling back to the
// raw text when it is not valid encoding — the same tolerance httpmsg applies when it first
// addressed the value.
func decodeParameterValue(raw string) string {
	if decoded, err := url.QueryUnescape(raw); err == nil {
		return decoded
	}
	return raw
}

// jsonBodyDocument returns the JSON document a request body carries and, when the body is
// base64-encoded, the encoding the edited document has to be written back with.
func jsonBodyDocument(body []byte, loc httpmsg.ParamLocation) ([]byte, *base64.Encoding, bool) {
	if loc == httpmsg.LocJSON {
		if !looksLikeJSONDocument(body) {
			return nil, nil, false
		}
		return body, nil, true
	}
	trimmed := string(bytes.TrimSpace(body))
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(trimmed)
		if err != nil || !looksLikeJSONDocument(decoded) {
			continue
		}
		return decoded, encoding, true
	}
	return nil, nil, false
}

// looksLikeJSONDocument reports whether data opens as a JSON object or array. It is
// deliberately shallow: the document came from a request the scanner has already addressed,
// and all this decides is how its bytes are written back.
func looksLikeJSONDocument(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[')
}

// spliceJSONValue rewrites the document so that the occurrence-th member named key carries
// object as its value, written as it stands.
//
// A key the document does not carry is added to the top-level object rather than the request
// being rewritten into one the application never receives.
func spliceJSONValue(document []byte, key string, occurrence int, object string) ([]byte, bool) {
	start, end, ok := jsonValueSpan(document, key, occurrence)
	if !ok {
		return addJSONMember(document, key, object)
	}
	out := make([]byte, 0, len(document)-(end-start)+len(object))
	out = append(out, document[:start]...)
	out = append(out, object...)
	out = append(out, document[end:]...)
	return out, true
}

// jsonValueSpan locates the value of the occurrence-th member named key, in document order.
//
// Only a quote that opens a member counts, so a string value that reads like the key's name is
// not mistaken for the member itself. A repeated key is told apart by occurrence, which is how
// httpmsg counts the fields it addresses as well.
func jsonValueSpan(document []byte, key string, occurrence int) (int, int, bool) {
	needle := []byte(`"` + key + `"`)
	seen := 0
	for offset := 0; offset < len(document); {
		index := bytes.Index(document[offset:], needle)
		if index < 0 {
			return 0, 0, false
		}
		position := offset + index
		offset = position + 1
		if !jsonMemberOpensAt(document, position) {
			continue
		}
		start, end, ok := jsonValueAfterKey(document, position+len(needle))
		if !ok {
			continue
		}
		if seen == occurrence {
			return start, end, true
		}
		seen++
	}
	return 0, 0, false
}

// jsonMemberOpensAt reports whether the quote at position begins a member, i.e. whether the last
// thing before it was the start of its object or the comma that separates members.
func jsonMemberOpensAt(document []byte, position int) bool {
	for index := position - 1; index >= 0; index-- {
		switch document[index] {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', ',':
			return true
		default:
			return false
		}
	}
	return false
}

// jsonValueAfterKey returns the byte range of the value that follows a member name which ends
// at position.
func jsonValueAfterKey(document []byte, position int) (int, int, bool) {
	position = jsonSkipSpace(document, position)
	if position >= len(document) || document[position] != ':' {
		return 0, 0, false
	}
	position = jsonSkipSpace(document, position+1)
	if position >= len(document) {
		return 0, 0, false
	}
	end, ok := jsonValueEnd(document, position)
	if !ok {
		return 0, 0, false
	}
	// A member's value is followed by the next member or by the end of its container; anything
	// else means this was not a value after all.
	after := jsonSkipSpace(document, end)
	if after < len(document) && document[after] != ',' && document[after] != '}' && document[after] != ']' {
		return 0, 0, false
	}
	return position, end, true
}

// jsonSkipSpace returns the position of the next character that is not JSON whitespace.
func jsonSkipSpace(document []byte, position int) int {
	for position < len(document) {
		switch document[position] {
		case ' ', '\t', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}

// jsonValueEnd returns the position just past the JSON value that starts at position.
func jsonValueEnd(document []byte, position int) (int, bool) {
	switch document[position] {
	case '"':
		return jsonStringEnd(document, position)
	case '{', '[':
		return jsonContainerEnd(document, position)
	}
	end := position
	for end < len(document) && !isJSONSeparator(document[end]) {
		end++
	}
	if end == position {
		return 0, false
	}
	return end, true
}

// jsonStringEnd returns the position just past the string literal that starts at position.
func jsonStringEnd(document []byte, position int) (int, bool) {
	for index := position + 1; index < len(document); index++ {
		switch document[index] {
		case '\\':
			index++
		case '"':
			return index + 1, true
		}
	}
	return 0, false
}

// jsonContainerEnd returns the position just past the object or array that starts at position,
// counting only the brackets that fall outside its strings.
func jsonContainerEnd(document []byte, position int) (int, bool) {
	depth := 0
	for index := position; index < len(document); index++ {
		switch document[index] {
		case '"':
			end, ok := jsonStringEnd(document, index)
			if !ok {
				return 0, false
			}
			index = end - 1
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return index + 1, true
			}
		}
	}
	return 0, false
}

// isJSONSeparator reports whether a byte ends a bare JSON value.
func isJSONSeparator(c byte) bool {
	switch c {
	case ',', '}', ']', ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

// addJSONMember appends a member to the document's top-level object: the field is added rather
// than the whole request being rewritten, so the fields the application already reads are still
// there when it parses.
func addJSONMember(document []byte, key, value string) ([]byte, bool) {
	trimmed := bytes.TrimSpace(document)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, false
	}
	body := trimmed[:len(trimmed)-1]
	var out bytes.Buffer
	out.Grow(len(trimmed) + len(key) + len(value) + 4)
	out.Write(body)
	// An object that already has a member needs the comma that separates them; an empty one
	// must not have it.
	if len(bytes.TrimRight(body, " \t\r\n")) > 1 {
		out.WriteByte(',')
	}
	out.WriteString(jsonMemberKey(key))
	out.WriteByte(':')
	out.WriteString(value)
	out.WriteByte('}')
	return out.Bytes(), true
}

// jsonMemberKey writes a member name as a JSON string literal.
func jsonMemberKey(key string) string {
	var out strings.Builder
	out.Grow(len(key) + 2)
	out.WriteByte('"')
	for index := 0; index < len(key); index++ {
		switch c := key[index]; {
		case c == '"' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c < 0x20:
			fmt.Fprintf(&out, `\u%04x`, c)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// autoTypeErrorFinding reports a parser that read the @type member of a value the request
// carried and refused, or failed, the type it named.
//
// Firm rather than certain, for the same reason the check's other findings are: the entry point
// is proven and what could be done with it is not something one request can show.
func autoTypeErrorFinding(c *checks.Context, t *checks.Target, attempt autoTypeAttempt) *finding.Finding {
	f := checks.NewFinding(deserialization{}, t,
		i18n.KeyCheckDeserialTitle, i18n.KeyCheckDeserialDesc, i18n.KeyCheckDeserialFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.object
	f.CWE = "CWE-502"
	f.References = deserializationReferences
	f.Evidence.Request = attempt.request.Raw()
	f.Evidence.Response = truncate(attempt.response.Body, 8192)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"the JSON parser answered the @type member the request carried with its own complaint (" +
			attempt.signature + ")",
		"the value reached a parser that reads type ids, which is the entry point a gadget chain " +
			"needs; no class was instantiated by this request",
	}
	f.Evidence.Diff = extractAround(string(attempt.response.Body), attempt.signature, 240)
	return f
}

// autoTypeCallbackFinding reports a parser that resolved the name carried in the @type member:
// the resolution is the proof, and it arrived on another connection.
func autoTypeCallbackFinding(c *checks.Context, t *checks.Target, attempt autoTypeAttempt) *finding.Finding {
	f := checks.NewFinding(deserialization{}, t,
		i18n.KeyCheckDeserialTitle, i18n.KeyCheckDeserialDesc, i18n.KeyCheckDeserialFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.object
	f.CWE = "CWE-502"
	f.References = deserializationReferences
	f.Evidence.Request = attempt.request.Raw()
	f.Evidence.Response = truncate(attempt.response.Body, 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 2048)
	f.Evidence.Matches = []string{
		"the JSON parser read the @type member of the value the request carried and resolved the " +
			"name it gave",
		describeAutoTypeInteraction(c, attempt.interactions),
		"the parser built an address from a value the caller wrote, which is the entry point a " +
			"gadget chain needs; no class was instantiated by this request",
	}
	return f
}

// describeAutoTypeInteraction renders the callback that proved the finding.
func describeAutoTypeInteraction(c *checks.Context, interactions []checks.Interaction) string {
	if len(interactions) == 0 {
		return c.Bundle.T(i18n.KeyEvidenceOOB, "", "", "")
	}
	first := interactions[0]
	return c.Bundle.T(i18n.KeyEvidenceOOB,
		strings.TrimSpace(first.Detail), first.Protocol, first.RemoteAddr)
}
