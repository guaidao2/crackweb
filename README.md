# crackweb

Maintained by **guaidao2 & coolmoon**

**English** · [简体中文](README.zh-CN.md)

> A traffic-driven web DAST scanner. Point your browser at the proxy, browse the
> application, and crackweb tests what it sees.

crackweb is a dynamic application security testing (DAST) tool written in Go, built in
the shape of [xray](https://github.com/chaitin/xray): you configure your browser — or
any HTTP client — to use crackweb as its proxy, browse the target normally, and every
request that flows through is inspected and, where it carries parameters, actively
replayed with mutation payloads. A crawler drives the same engine for targets nobody is
going to click through by hand.

One static binary, no runtime dependencies, MIT licensed. English by default, Simplified
Chinese on request.

---

## Quick start

```sh
git clone https://github.com/guaidao2/crackweb && cd crackweb
make build          # -> bin/crackweb
```

**Browse and scan at the same time.** Start the proxy, point your browser at
`127.0.0.1:7777`, install the CA certificate it prints, and use the application as you
normally would. Findings appear in the terminal as you go.

```sh
crackweb proxy --listen 127.0.0.1:7777 --export-ca ~/crackweb-ca.crt
```

**Or let the crawler do the walking.**

```sh
crackweb crawl -u https://example.com --engine hybrid -o report.html
```

**Or test a single request.**

```sh
crackweb scan -u "https://example.com/api/items?category=books" -o report.html
crackweb scan -r request.txt          # a capture saved from Burp
crackweb scan -u https://example.com/login --forms   # also submit the forms the page declares
```

`--forms` covers the case a one-URL scan otherwise misses: a page whose interesting parameters
are not in the URL. With it crackweb submits what the page declares — its HTML forms, and the
requests its own scripts make (a JSON body for a search call, a multipart body for an upload) —
the same way the crawler does. Each of those posts to its own address with its own body and
encoding, so nothing the seed request carries reaches it; that is what makes a login page, a
search box or an upload widget testable without crawling the whole site. Calls the page only ever
makes with PUT, PATCH or DELETE stay out: no form submits with them.

## Language

English is the default output language, regardless of the host locale. Chinese is always
an explicit choice:

```sh
crackweb --help                   # English
crackweb --lang zh --help         # Chinese
CRACKWEB_LANG=zh crackweb --help  # the same, via the environment
```

The same applies to reports: a scan run with `--lang zh` produces a Chinese report.

## Commands

| Command | Purpose |
| --- | --- |
| `proxy` | Run the intercepting proxy: browse through it, and crackweb tests the traffic it sees |
| `crawl` | Crawl a target and scan every request it discovers |
| `scan` | Scan a single target, or a raw HTTP request saved from another tool |
| `oob` | Run the out-of-band interaction server (DNS and HTTP callbacks) |
| `ca` | Create, inspect and export the CA certificate used for HTTPS interception |

`crackweb <command> --help` documents every option; `crackweb scan --list-checks` lists
the available checks.

## How it works

### One message model

Everything crackweb touches — traffic off the proxy, requests the crawler discovered,
requests pasted in from Burp, requests the scanner built while mutating a parameter — is
the same `httpmsg.Request`. That is what makes the proxy, the crawler and the scanner one
tool rather than three: anything one of them sees can be replayed, mutated and reported
by the others.

Headers are stored as an ordered, case-preserving list rather than a map, so a capture
can be modified and written back out byte-for-byte identical apart from the intended
change.

### Traffic-driven testing

```
                    ┌──── sources ────┐
  browser →[proxy]──▶  proxy traffic  │
                    │  crawler finds  ├──▶ httpmsg.Request ──▶ scan queue
  raw file ─────────▶  manual import  │
                    └─────────────────┘
                              │
   Layer 0  passive analysis  no extra traffic   headers, cookies, CORS, leaks
   Layer 1  replayed mutation injects payloads   SQLi, XSS, SSRF, RCE, SSTI, LFI, …
   Layer 2  templates         nuclei-compatible  thousands of published checks
                              │
                              ▼
                   findings → HTML / JSON / SARIF / Markdown
```

Layer 1 is the heart of it: the scanner takes each request the browser actually made,
extracts its parameters, and replays targeted variants — judging what changed with a
normalisation and similarity engine that ignores timestamps, CSRF tokens and other
dynamic noise. A page that differs only by its embedded clock does not look like a
change, so payloads that do nothing are not reported.

Because coverage follows the traffic rather than a crawl, the scan starts working
immediately, reaches everything the user reaches (authenticated pages included), and
wastes no requests on parameters that do not exist.

### Out-of-band testing

A blind SSRF, a blind command injection or a stored XSS leaves no trace in the response.
crackweb runs its own DNS and HTTP callback listeners and treats a callback as proof:

```sh
crackweb proxy --listen 127.0.0.1:7777 --oob-http 0.0.0.0:8081 --oob-dns 0.0.0.0:5353
crackweb oob --domain oob.example.com      # or standalone, on a host targets can reach
```

That listener only works when the target can call back to this machine — a lab network, or a host
with a reachable address. Against anything else (a laptop behind NAT, a target on the public
internet) the payloads go out and the answers can never arrive, so crackweb does not start the
listener unless you ask for one: with no `--oob-http`, `--oob-dns` or `--oob-interactsh`, the
out-of-band checks skip themselves instead of sending payloads that could not be answered.

For those targets, point crackweb at an [interactsh](https://github.com/projectdiscovery/interactsh)
deployment — your own, or a public one. The callback names resolve under its domain, so they work
from anywhere:

```sh
crackweb scan -u https://target.example --oob-interactsh oob.example.com
crackweb scan -u https://target.example --oob-interactsh oob.example.com --oob-token "$TOKEN"
```

crackweb registers with the deployment at start-up and polls it for interactions; a deployment that
refuses the registration is reported and out-of-band testing stays off rather than running on a
channel that can never deliver.

## Checks

**Passive** — analyse traffic crackweb already has; safe to run against production.

| Check | Finds |
| --- | --- |
| `passive-security-headers` | Missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| `passive-csp` | Content-Security-Policy present but weakened (`unsafe-inline`, wildcards, missing nonce) |
| `passive-cookie-flags` | Cookies without Secure, HttpOnly or SameSite |
| `passive-cors` | Reflected or wildcard `Access-Control-Allow-Origin`, with credentials |
| `passive-info-disclosure` | `Server`, `X-Powered-By` and friends leaking versions |
| `passive-mixed-content` | Plain-HTTP subresources on an HTTPS page |
| `passive-cache-control` | Session-establishing responses that may be cached |
| `passive-directory-listing` | Auto-generated directory indexes |
| `passive-cleartext-password` | Credentials submitted over http:// — the value is never reproduced in the report |
| `passive-sri` | Scripts and stylesheets from another origin without a Subresource Integrity hash |
| `passive-error-disclosure` | Stack traces and framework error messages in a response body |
| `passive-content-disclosure` | Internal IP addresses, server-side paths and mailboxes in a response body |
| `passive-private-key` | A PEM private key served over HTTP — the key is never reproduced in the report |
| `passive-insecure-transport` | A password field served over plain HTTP |
| `passive-vulnerable-library` | A front-end library at a version with a published vulnerability, named with its advisory |

**Active** — send payloads and reason about what comes back.

| Check | Severity |
| --- | --- |
| `sqli-error` | Critical |
| `sqli-boolean` | High |
| `sqli-union` | Critical |
| `sqli-time` | High |
| `xss-reflected` | High |
| `xss-stored` | High |
| `sqli-order-by` | High |
| `path-traversal` | High |
| `ssti` | High |
| `ssrf` | High |
| `command-injection` | Critical |
| `open-redirect` | Medium |
| `crlf-injection` | Medium |
| `nosqli` | High |
| `xxe` | High |
| `deserialization` | High |
| `second-order-injection` | High |
| `jwt` | Critical |
| `upload` | Medium |
| `csrf` | Medium |
| `host-header` | Medium |
| `method-override` | Medium |
| `idor` | High *(needs two sessions)* |
| `access-control-variants` | High *(runs on a 401/403)* |
| `pagination-bypass` | Medium |
| `parameter-type-bypass` | Medium |
| `dom-xss` | High *(opt-in: runs the page in a browser)* |
| `prototype-pollution` | High *(opt-in: runs the page in a browser)* |
| `client-template-injection` | High *(opt-in: runs the page in a browser)* |
| `ldap-injection` | High |
| `xpath-injection` | High |
| `odata-injection` | High |
| `graphql-introspection` | Low |
| `cache-poisoning` | High *(opt-in: writes into a shared cache)* |
| `request-smuggling` | High *(opt-in)* |
| `path-override` | High |
| `ip-spoof` | High |
| `http-put` | High *(opt-in: stores a file on the target)* |
| `cors-origin` | High |
| `exposed-path` | High |
| `jsonp` | Low |
| `content-type-bypass` | Medium |
| `referer-bypass` | High |
| `websocket-origin` | Low |

Select checks by name or by tag: `--checks sqli`, `--checks injection`, `--checks all`.
`--passive-only` turns the proxy into a pure observation post that never sends a request
of its own.

### Access control (IDOR)

Testing for horizontal privilege escalation needs two identities, because the question is
not "did the response change?" — it is "can someone else see this?". Supply two sessions
and crackweb compares what each of them gets against what an anonymous request gets:

```sh
crackweb scan -u "https://shop.example.com/order?id=42"   --session "Cookie: sess=alice-token"   --session "Cookie: sess=bob-token"
```

A finding is raised only when **both sessions receive the same content and an anonymous
request does not**. That combination means the object is protected but not scoped to its
owner. A page anyone can read is not reported, and neither is one where each user
correctly sees their own record — which is what keeps the check worth reading.

Sessions can also be a bearer token or any custom header: `--session "Authorization:
Bearer x"`. Without two sessions the check is skipped, and crackweb says so.

### Opt-in checks

`request-smuggling` is **not** run by default, and `--checks all` will not pull it
in. Its probes leave bytes queued on the target's connection, which the next
request on that connection may then read — against a host you do not own that is
an incident, not a test. Selecting it by name is the consent:

```sh
crackweb scan -u https://staging.example.com --checks request-smuggling
crackweb scan -u https://staging.example.com --enable-unsafe-checks --checks all
```

Either way it announces itself before sending anything.

`dom-xss` is opt-in for a different reason. It loads the page in a real browser, and a
browser runs every script the page carries — the ones that fetch further data and the ones
that write it included. On a target whose pages have side effects, that is more than
testing the request it was given. Naming it, or passing `--enable-unsafe-checks`, is the
consent; without a browser installed the check reports nothing rather than guessing.
`prototype-pollution` is opt-in for the same reason, and answers a different question: it
loads the page and asks its runtime whether a property named in the query string reached
`Object.prototype`.


```sh
crackweb scan -u https://app.example.com/page --checks dom-xss
```

## WAF evasion

A scanner that ships fixed payloads — `' OR 1=1--`, `<script>alert(1)</script>` —
is caught by any signature-based firewall on the first request. So crackweb does
not ship payloads; it derives them.

```
seeds (a few clearly-correct expressions)
  ↓ structural rewrites   comment splitting, keyword breaking, whitespace
  ↓ encoding              URL, double URL, Unicode, hex, HTML entity, base64
generations               gen 0 = as written · gen 1 = one rewrite · gen 2 = two · …
```

**Variants are ordered by generation, and the walk stops as soon as it can.**
Generation 0 is the plain payload, so an unprotected target costs one request per
seed and never sees a mutated one. Only when the target refuses a generation does
the next one run — and when a generation gets through, that fact is remembered
per host, so later payloads start where the last one succeeded instead of
rediscovering the firewall from scratch.

That rule reads a refusal, and a modern edge frequently does not give one: it rewrites
the payload and answers `200`, leaving nothing in the response that says it filtered
anything. Against such a target the rule never fires — the evidence it acts on is exactly
what is withheld — and the mutations, which are the part that gets through, would never be
sent.

So crackweb does not wait for the evidence. **It assumes a firewall is there**, and sends
the first two generations of every payload whether or not anything was refused. Two, and not
one, because the first generation spends its budget on structural rewrites; the combination
that defeats a firewall which normalises once and matches once — a rewrite wrapped in an
encoding — is reached in the second. The cost is real: on an unprotected target the request
count goes up about fourfold. `--no-assume-waf` keeps the detection and drops the
assumption, for a target you already know has nothing in front of it.

Two rules keep the variants meaningful. Mutators in the same family never
combine (three different ways to hide a space produce a payload that is none of
them), and encoding is applied exactly once — a variant whose last transformation
already produced transport form is sent verbatim, because encoding it again would
arrive at the application as a literal percent sequence.

Detection is deliberately conservative. A target is only marked as filtered when
a probe produces a response a firewall is known to produce — a block status code
with refusal wording, or a vendor fingerprint (Cloudflare, AWS WAF, ModSecurity,
Sucuri, 安全狗, 宝塔, 长亭雷池, …). "The response changed" is not enough: a wrong
verdict would escalate every later payload through extra generations for nothing.

```sh
crackweb scan -u https://example.com --no-waf    # also stop looking for a vendor fingerprint
```

## Advanced techniques

Beyond ordinary injection, crackweb uses the techniques that separate a scanner
from a fuzzer:

| Technique | What it does |
| --- | --- |
| **Statistics, not a stopwatch** | A time-based finding requires four conditions together: the delay reaches most of what the payload asked for, it does **not** run past it — a three-second sleep cannot make a request take five, so a measurement that overshoots is measuring something else, such as another check holding a connection — it stands clear of the target's own measured variation (3× the interquartile range), and it reproduces across samples. One slow response proves nothing. |
| **HTTP parameter pollution** | When a payload is refused on its own, it is sent again as a *second* occurrence of the same parameter — a filter reading the first one never sees it, while a framework resolving the last one acts on it. |
| **Column counting** | A `UNION` whose arms differ in width is a syntax error in every database, so the arm count is found by trial — and each column is filled with a unique number, so the injected values can be told apart from the payload being echoed back into the form. A search page also prints the term in prose, where removing the payload does not reach it, so the check first asks for the bare marker and counts how many times this page repeats it. |
| **Path normalisation** | `//etc/passwd`, `/.//etc/passwd`, `/etc//passwd` — for implementations that strip `../` correctly and still collapse `//` wrongly. |
| **Second-order injection** | A payload is written through one request and the *already-observed* pages are replayed to see whether reading it back broke something. Compared against what those pages returned **before** the write, so the evidence is the change the write caused. |
| **Blind testing by callback** | A blind SSRF, command injection or XXE leaves nothing in the response. Each attempt plants a unique callback address and the proof arrives later, on a separate listener. |
| **Encoded parameter documents** | A parameter whose value is a JSON document — base64-wrapped or not — is opened, and its fields are tested one by one. The envelope is rebuilt around every mutation, so a payload inside the document still reaches the application as valid input instead of breaking the parameter it arrived in. |

## Authenticated scanning

Everything behind a login is invisible to a crawler that arrives anonymously, and
every check aimed at an anonymous view tests the wrong surface. Give the client an
identity and it carries it on every request — including the ones checks build
themselves:

```sh
crackweb crawl -u https://app.example.com --cookie "session=abc; csrf=xyz"
crackweb crawl -u https://app.example.com --header "Authorization: Bearer eyJ..."
crackweb crawl -u https://staging.example.com --basic-auth alice:s3cret
```

- `-C, --cookie` is merged into any cookie the request already carries, because
  dropping a CSRF token would break the session this exists to preserve.
- `-H, --header` is repeatable, and only fills a gap: a request that already names
  an identity is more specific than a command-line default and is never overridden.
- `--basic-auth` takes `user:password`; only the first colon separates them, since
  passwords contain colons.

`--sessions` is a different thing. It takes two or more identities and is used by
the access-control check to compare what each of them can reach:

```sh
crackweb scan -u https://app.example.com/orders/1001 \
  --sessions "Cookie: session=alice" --sessions "Cookie: session=bob"
```

## User-Agent

By default crackweb identifies itself, so a scan is visible in the target's logs.
That is the honest default for a tool meant to be run on systems you are allowed to
test.

`--random-ua` composes a fresh, plausible User-Agent for every request instead. The
pool is built from the parts real browsers advertise — engine, platform, version —
rather than a fixed list, because a short list is itself a fingerprint. Use it when
the tool's own name would pollute a log you are reviewing, or when a scan must not be
grouped by a stable header.

## Templates

crackweb runs **nuclei-compatible YAML templates**, so the published template corpus
works without being rewritten:

```sh
crackweb scan -u https://example.com --templates ./my-templates
crackweb crawl -u https://example.com --templates ./templates --checks template
```

```yaml
id: example-sqli-error

info:
  name: Error-based SQL injection
  author: crackweb
  severity: high
  description: The parameter reaches a SQL statement unparameterised.
  tags: sqli,injection
  classification:
    cwe-id: CWE-89

http:
  - method: GET
    path:
      - "{{RootURL}}/?id=1'"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "You have an error in your SQL syntax"
          - "SQLSTATE"
        condition: or
      - type: status
        status: [200]
```

Supported: `id`/`info`, `variables`, `http` (also spelled `requests`), `path` and `raw`
request forms, `headers`, `body`, `payloads` with `{{name}}` substitution, extractors
(regex, kval, json, dsl) feeding later requests, and the `word`, `regex`, `status`,
`size`, `binary` and `dsl` matcher types with `condition`, `matchers-condition`,
`negative` and `case-insensitive`.

The `dsl` evaluator understands comparisons, `&&`/`||`/`!`, and the usual helpers —
`contains`, `contains_all`, `contains_any`, `starts_with`, `ends_with`, `len`, `tolower`,
`toupper`, `trim`, `replace`, `concat`, `substr`, `reverse`, `regex`, `md5`, `sha1`,
`sha256`, `base64`, `base64_decode`, `url_encode`, `url_decode`, `hex_encode`,
`hex_decode`, `rand_int`, `randstr`, `unix_time` — over `body`, `all_headers`, `raw`,
`status_code`, `content_length`, `duration` and any response header.

Templates using features crackweb cannot honour (`flow`, `unsafe` raw requests, pipelining,
xpath matchers, non-batteringram attack types) are **skipped with a warning**, never run
half-way. See `examples/templates/` to start.

## Reports

`-o report.html` — and `.json`, `.sarif`, `.md` are recognised by extension.

The HTML report is a single self-contained file: a severity summary, a filter box, and
one collapsible card per finding with the description, the fix, the matched evidence, the
raw request, the response, the baseline it was compared against, and a ready-to-paste
`curl` command. It respects the reader's light or dark preference and prints cleanly.

Reports also carry the **coverage boundary**: how many requests never came back, and which
hosts had something answering in front of the application. A refusal and a clean result look
the same from the outside, so the report says which one it was rather than leaving the reader
to guess.

SARIF output plugs straight into GitHub code scanning.

## Performance

Figures below are from real runs on a 4-core / 3.8 GB machine with the target on
the same host, so they describe the scanner rather than the network.

| | |
| --- | --- |
| Binary | ~17 MB, one static file — no runtime, no interpreter, no dependency tree |
| Cold start | ~5 ms |
| Throughput | 60–90 requests/second across 8 threads, capped by `--rate` |
| A full crawl and active scan | ~200 pages and ~16,000 requests in about 3 minutes |
| Passive-only mode | reads traffic that is already flowing; sends nothing of its own |

Concurrency and rate are explicit flags rather than fixed constants, because the
right value is a property of the target and not of the tool: a lab machine takes
8 threads at 80 requests/second, a production system usually does not.

## Design notes

**False positives are the enemy.** A scanner that reports everything trains its users to
ignore it. Three things guard against that: the normalisation engine above; confidence
levels (`certain`, `firm`, `tentative`) on every finding; and checks that require positive
evidence — a database error string, file contents, or an out-of-band callback — rather
than merely "the response changed".

**Scope is enforced.** The proxy only intercepts hosts matching `--scope`; everything else
is tunnelled untouched, so unrelated browsing keeps working and is never modified. The
crawler stays on the seed host unless told otherwise.

**Failures are visible.** Requests that never get a response are counted and reported, not
silently skipped: a target refusing connections must not look like a clean scan.

**Crawling degrades instead of failing.** The headless engine needs a Chromium-based
browser. crackweb looks for one in this order: `CRACKWEB_CHROME`, then `PATH`, then the
locations each platform actually installs to (including Edge, which every Windows machine
has), then the browser caches left by Playwright and Puppeteer. If none is found it says
so once and continues with the HTTP engine, which needs no browser — so `--engine hybrid`
on a machine without Chromium still crawls, just less deeply into JavaScript.

**The browser's own requests are replayed as they were sent.** The crawler's rule is that
the HTTP engine makes every request the scanner sees, so one code path produces them all. A
request carrying a body is the exception that rule cannot cover: the page's script chose
the method, the bytes and the content type, and none of that can be reconstructed from the
address it went to. Fetching that address as a GET would miss the endpoint entirely — which
is how a JSON API the browser talked to all along ends up untested. So those requests go
back out exactly as they went, and a page that posts JSON is scanned like any other. A
bodyless POST is left alone: there is no parameter to test, and sending it again does have
an effect.

**A published API description is read.** An OpenAPI or Swagger document is the best input a
scan can be handed — every path, every method, and the parameters of each one — and most of
what it lists is unreachable by following links, because nothing links to an API. crackweb
asks the addresses such a document is commonly published at, follows the ones a page or a
script points at (Swagger UI carries its own address in its initialiser), reads both
generations of the format, and turns each operation into a request: path and query
parameters get a value of their declared type, a request body is built from its schema, and
the result goes to the scanner like any other request. A description is free to name any
host; the scope is applied to what it names before anything is sent.

**A site's robots file and sitemap are read too**, and for opposite reasons. A sitemap is a
page list nobody had to crawl for, and it nests — an index points at further sitemaps, which
are followed. A robots file lists what the site would rather nobody looked at, which is
where the interesting addresses usually are: an entry there is a path somebody decided not
to link to. Reading it is a deliberate choice rather than an oversight — the convention
exists for search engines, which are trying not to be a nuisance, and a scan its operator
authorised is asking a different question. The paths are fetched like any other address and
reported as coming from there. Only entries that name a path are used: an empty value means
everything is allowed, a bare `/` means nothing is, and a value with `*` or `$` in it is a
pattern rather than an address. `--no-discovery` turns all of it off, for a target where
even one address the user did not name is one too many.

The common addresses cover the frameworks that publish a description at a fixed place. A site
that moved it — a version prefix, an internal name, a path somebody invented — is not
something a guess finds, so `--api-doc <path>` asks for an extra address by name. It is
repeatable.

### Endpoints a page's script calls

A single-page application keeps its endpoints in string literals rather than links: a delete
button's handler, a form that assembles its own request, a search box that fetches when it is
submitted. Nothing on the page links to them and the browser issues none of them while the
page loads, so a link-only crawl never sees them.

They are read out of the script with the method and the body the call uses, because a
discovered address is not the same thing as a tested request. A **read** becomes a link and
is fetched as usual — with interpolated segments (`/api/documents/${id}`) filled in with a
number, or the address cannot be requested at all. A **write** is replayed instead: sent with
the method the script names, and with a body of the same shape — a `FormData` becomes
multipart with a file part for the field that asks for one, a `JSON.stringify` becomes JSON
with the same field names. That is what lets the upload check see an upload endpoint whose
form exists only in script.

Writes are skipped unless `--allow-state-change` is given, and that flag now means what it
says: it will send the `DELETE` a page's script contains. Point it at a target where that is
acceptable.

## Project layout

```
cmd/crackweb/          executable entry point
internal/
  ca/                  CA generation, per-host leaf certificates
  checks/              the check interface, registry and injection context
    passive/           checks that send no traffic
    active/            checks that inject payloads
  cli/                 argument parsing, command dispatch, bilingual help
  crawl/               HTTP and headless crawlers, HTML and form extraction
  diff/                normalisation, response fingerprinting, difference judgement
  finding/             the result model
  httpclient/          request sending: timeouts, retries, rate limiting, proxies
  httpmsg/             the shared request/response model, raw parsing, parameters
  i18n/                English and Chinese message catalogues
  oob/                 out-of-band DNS and HTTP interaction server
  payload/             payload seeds, the mutator catalogue, generation layering
  proxy/               intercepting proxy: CONNECT, TLS MITM, WebSocket relay
  report/              HTML, JSON, SARIF and Markdown reports
  scan/                scan queue, dispatch, deduplication
  scope/               host matching
  sitemap/             observed-traffic store
  template/            nuclei-compatible template engine and DSL
  version/             version and authorship
  waf/                 firewall detection, fingerprinting, escalation memory
```

## Development

`make check` (gofmt + vet + test) must pass before a pull request.

Two conventions matter here. First, every user-facing string belongs in `internal/i18n`;
the catalogue tests fail the build when a translation is missing or when a translation's
printf verbs drift away from the English original. Second, a check declares its own
severity, tags and remediation text, and does its work through the `checks.Context` it is
handed — no globals, which is what makes each check testable in isolation.

## Disclaimer

crackweb is intended for authorised security testing, CTF practice and research only.
Do not use it against systems you neither own nor have written permission to test.

## License

MIT — see [LICENSE](LICENSE).
