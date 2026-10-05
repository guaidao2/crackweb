package i18n

// english is the default catalogue and the reference for every other
// translation: when a key is missing elsewhere, this table is what gets shown.
var english = map[Key]string{
	KeyAppTagline: "Traffic-driven web DAST scanner — point your browser at the proxy and find vulnerabilities as you browse.",
	KeyAppDisclaimer: "crackweb is intended for authorised security testing, CTF practice and research only. " +
		"Do not use it against systems you neither own nor have written permission to test.",

	KeyHelpUsage:           "USAGE",
	KeyHelpUsageLine:       "crackweb [global options] <command> [command options]",
	KeyHelpCommandsTitle:   "COMMANDS",
	KeyHelpOptionsTitle:    "GLOBAL OPTIONS",
	KeyHelpCmdOptionsTitle: "OPTIONS",
	KeyHelpExamplesTitle:   "EXAMPLES",
	KeyHelpSubcommandHint:  "Run 'crackweb <command> --help' for options specific to a command.",
	KeyHelpGlobalHint:      "Global options such as --lang, --no-color and --quiet also apply here.",
	KeyHelpMoreInfoTitle:   "MORE INFO",
	KeyHelpCommandUsageFmt: "crackweb %s",
	KeyRepoLabel:           "Repository:",
	KeyHelpExamples: `  # Start the intercepting proxy and browse the target through it
  crackweb proxy --listen 127.0.0.1:7777

  # Crawl a target and scan every request it finds
  crackweb crawl -u https://example.com

  # Scan a request saved from Burp
  crackweb scan -r request.txt

  # Run the out-of-band interaction server
  crackweb oob --dns 0.0.0.0:5353 --http 0.0.0.0:8081`,

	KeyFlagLang:    "Output language: en (default) or zh. CRACKWEB_LANG=zh does the same thing.",
	KeyFlagHelp:    "Show this help and exit.",
	KeyFlagVersion: "Show version information and exit.",
	KeyFlagNoColor: "Disable coloured output.",
	KeyFlagQuiet:   "Print findings only; hide progress and status lines.",

	KeyCmdProxySummary:            "Run the intercepting proxy: browse through it and crackweb tests the traffic it sees.",
	KeyCmdCrawlSummary:            "Crawl a target and scan every request it discovers.",
	KeyCmdScanSummary:             "Scan a single target, or a raw HTTP request saved from another tool.",
	KeyCmdOobSummary:              "Run the out-of-band interaction server (DNS and HTTP callbacks).",
	KeyFlagJWTSecret:              "A signing key you already know; the token the target issues is re-signed with it and offered back. Repeatable.",
	KeyMsgJWTSecrets:              "%d signing key(s) supplied; the jwt check will test whether the target accepts tokens they sign.",
	KeyCmdLocalJWTTitle:           "Decode a JSON Web Token, recover its signing secret, and sign one of your own.",
	KeyCmdLocalHashTitle:          "Identify a hash, and try a wordlist against the kinds that allow it.",
	KeyUsageLocalJWT:              "local jwt <token> [options]",
	KeyUsageLocalHash:             "local hash <value> [options]",
	KeyFlagLocalSecret:            "Use this signing key directly instead of searching for it.",
	KeyFlagLocalForge:             "Print a token signed with the recovered (or supplied) key.",
	KeyFlagLocalClaim:             "Replace a claim in the forged token: name=value. Repeatable. A value of true/false/42/{\"a\":1} takes that type.",
	KeyErrLocalNoHash:             "local hash needs a value.",
	KeyErrLocalForgeNeedsSecret:   "--forge needs a key: supply one with --secret, or let the search find it.",
	KeyErrLocalForgeNotSymmetric:  "%s cannot be signed from a secret, so --forge has nothing to reproduce.",
	KeyErrLocalBadClaim:           "--claim wants name=value; got %q.",
	KeyMsgLocalSubjects:           "offline analyses:",
	KeyMsgLocalHashUnknown:        "that does not look like a hash this recognises.",
	KeyMsgLocalHashIdentified:     "%d possible identity(ies):",
	KeyMsgLocalHashNotCrackable:   "none of these can be attacked from a wordlist: the value carries its own salt, or the algorithm is deliberately slow.",
	KeyMsgLocalHashTrying:         "trying %d candidate password(s) (local arithmetic; nothing is sent).",
	KeyMsgLocalHashNoPassword:     "none of the %d candidates produced this digest.",
	KeyMsgLocalHashFound:          "the password is %q: it %s-hashes to the value (found after %d guess(es)).",
	KeyCmdLocalSummary:            "Run an offline analysis on something you already have (no traffic sent).",
	KeyUsageLocal:                 "local <subject> [options]",
	KeyFlagLocalWordlist:          "File of candidate secrets, one per line; the built-in list is always tried too.",
	KeyErrLocalNoSubject:          "local needs a subject: try `crackweb local jwt <token>`.",
	KeyErrLocalUnknownSubject:     "unknown local subject %q; try `crackweb local jwt`.",
	KeyErrLocalNoToken:            "local jwt needs a token.",
	KeyErrLocalBadToken:           "that is not a readable JSON Web Token: %v",
	KeyErrLocalWordlist:           "could not read the wordlist: %v",
	KeyMsgLocalHeader:             "header",
	KeyMsgLocalClaims:             "claims",
	KeyMsgLocalField:              "%s:",
	KeyMsgLocalNoAlgorithm:        "the token names no algorithm.",
	KeyMsgLocalAlgorithm:          "signed with %s.",
	KeyMsgLocalUnsigned:           "the token carries no signature at all.",
	KeyMsgLocalExpired:            "expired at %s.",
	KeyMsgLocalValidUntil:         "valid until %s.",
	KeyMsgLocalNotSymmetric:       "%s is not a keyed-hash algorithm, so there is no guessable secret to find.",
	KeyMsgLocalTrying:             "trying %d candidate secret(s) against the signature (arithmetic only; nothing is sent).",
	KeyMsgLocalNoSecret:           "none of the %d candidates signed this token.",
	KeyMsgLocalSecretFound:        "the signing secret is %q (found after %d guess(es)): anyone holding it can mint a token for any identity.",
	KeyMsgLocalSecretFromFile:     "it came from the wordlist you supplied.",
	KeyMsgLocalSecretFromDefaults: "it came from the built-in list of common secrets.",
	KeyMsgLocalSecretDerived:      "it was derived from the token's own claims, so the key is built from something the token publishes.",
	KeyMsgLocalSigned:             "re-signing with it reproduces the original token: %v",
	KeyCmdCaSummary:               "Manage the CA certificate used for HTTPS interception.",

	KeyUsageProxy: "proxy [options]",
	KeyUsageCrawl: "crawl -u <url> [options]",
	KeyUsageScan:  "scan (-u <url> | -r <file>) [options]",
	KeyUsageOob:   "oob [options]",
	KeyUsageCa:    "ca [options]",

	KeyFlagListen:      "Address to listen on, e.g. 127.0.0.1:7777.",
	KeyFlagUpstream:    "Forward intercepted traffic through an upstream proxy (http:// or socks5://).",
	KeyFlagScope:       "Only test hosts matching this pattern; repeatable. Other hosts are tunnelled untouched.",
	KeyFlagPassiveOnly: "Analyse traffic without ever replaying a modified request.",

	KeyFlagURL:      "Seed URL to start from.",
	KeyFlagDepth:    "Maximum crawl depth; 0 means unlimited.",
	KeyFlagEngine:   "Crawler engine: http, headless or hybrid (default).",
	KeyFlagMaxPages: "Stop after visiting this many pages; 0 means unlimited.",

	KeyFlagScanURL:    "Target URL to scan.",
	KeyFlagScanMethod: "HTTP method to use.",
	KeyFlagScanData:   "Request body; sending one turns the request into a form POST.",
	KeyFlagScanHeader: "Extra request header, e.g. 'Cookie: a=b'; repeatable.",
	KeyFlagRaw:        "Read the request to scan from a raw HTTP file, e.g. saved from Burp.",
	KeyFlagChecks:     "Comma-separated check names or tags, or 'all'. Checks marked opt-in in --list-checks are never pulled in by 'all'.",
	KeyFlagScanOutput: "Report path; the format follows the extension (.html, .json, .sarif, .md).",
	KeyFlagScanForms:  "Also submit what the scanned page declares — its forms, and the requests its scripts make — and test what each one sends. A form or a script call posts to its own address with its own body, which a scan of one URL never reaches on its own.",

	KeyFlagDNSAddr:       "Listen address for the DNS interaction server, e.g. 0.0.0.0:5353.",
	KeyFlagHTTPAddr:      "Listen address for the HTTP interaction server, e.g. 0.0.0.0:8081.",
	KeyFlagOOBToken:      "Optional shared secret: it correlates a callback with the request that triggered it, and is also the authorization value an interactsh server may require.",
	KeyFlagOOBDomain:     "Base domain pointing at this server, when running behind a delegation.",
	KeyFlagOOBInteractsh: "An interactsh server to collect interactions at, e.g. oob.example.com; callback names resolve under it, so it works when the target cannot reach this machine. Without it out-of-band testing is off.",

	KeyFlagOutDir: "Directory to create or export CA material into.",
	KeyFlagForce:  "Overwrite existing CA material.",

	KeyErrUnknownCommand: "unknown command %q",
	KeyErrUnknownFlag:    "unknown option %s",
	KeyErrFlagNeedsValue: "option %s requires a value",
	KeyErrInvalidValue:   "invalid value %q for %s: %s",
	KeyErrBadLang:        "unsupported language %q; supported languages: en, zh",
	KeyErrNeedTarget:     "provide either -u/--url or -r/--raw",
	KeyErrURLRequired:    "a target URL is required (-u/--url)",

	KeyMsgNotImplemented: "%s is scaffolded but not implemented yet in this build.",
	KeyMsgPlannedFor:     "Planned for milestone %s.",

	KeyDiffReasonStatus:     "status code %d → %d",
	KeyDiffReasonRedirect:   "redirect target changed: %s → %s",
	KeyDiffReasonTitle:      "title %q → %q",
	KeyDiffReasonLength:     "normalised length %d → %d (%+d bytes; raw length %d → %d)",
	KeyDiffReasonBinaryLen:  "binary response length %d → %d (%+d bytes)",
	KeyDiffReasonContent:    "content similarity %.3f is below the threshold %.3f",
	KeyDiffReasonKeyword:    "new sensitive pattern in the response: %s",
	KeyDiffReasonEmpty:      "the response body became empty",
	KeyDiffReasonType:       "content type changed: %s → %s",
	KeyDiffReasonError:      "the request failed: %s",
	KeyDiffReasonBaseError:  "the baseline request failed (%s); this result is unreliable",
	KeyDiffReasonEcho:       "the parameter value is reflected in the response: %s",
	KeyDiffReasonNoBaseline: "no baseline response to compare against",

	KeyDiffCodeStatus:     "status code changed",
	KeyDiffCodeRedirect:   "redirect target changed",
	KeyDiffCodeTitle:      "page title changed",
	KeyDiffCodeLength:     "length changed",
	KeyDiffCodeContent:    "content changed",
	KeyDiffCodeKeyword:    "sensitive keyword",
	KeyDiffCodeEmpty:      "response became empty",
	KeyDiffCodeType:       "content type changed",
	KeyDiffCodeError:      "request failed",
	KeyDiffCodeEcho:       "parameter reflected",
	KeyDiffCodeNoBaseline: "no baseline",

	KeyDiffNone:       "no difference",
	KeyDiffEmptyValue: "(empty)",
	KeyDiffElided:     "... (%d more lines omitted)",

	KeyCheckSecHeadersTitle: "Missing security response headers",
	KeyCheckSecHeadersDesc: "The response omits one or more headers that harden a browser against " +
		"cross-site scripting, clickjacking and protocol downgrade attacks. Their absence is not a " +
		"vulnerability on its own, but it removes a defence that would otherwise limit the impact of one.",
	KeyCheckSecHeadersFix: "Send the missing headers on every response: Content-Security-Policy, " +
		"Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and " +
		"Permissions-Policy. Tune the policy per application rather than copying a template.",

	KeyCheckCookieFlagsTitle: "Cookie without security attributes",
	KeyCheckCookieFlagsDesc: "A cookie is set without Secure, HttpOnly or a SameSite policy. " +
		"A cookie missing HttpOnly can be read by injected script; one missing Secure can leak over " +
		"plain HTTP; one missing SameSite is sent on cross-site requests.",
	KeyCheckCookieFlagsFix: "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies. " +
		"Use the __Host- or __Secure- prefix where the cookie's scope allows it.",

	KeyCheckCORSTitle: "Permissive cross-origin resource sharing",
	KeyCheckCORSDesc: "The response allows arbitrary origins to read it, either with a wildcard or by " +
		"reflecting the request's Origin. Combined with credentials, this lets any site read " +
		"authenticated data on the user's behalf.",
	KeyCheckCORSFix: "Return Access-Control-Allow-Origin only for an explicit allowlist of origins. " +
		"Never combine a reflected origin with Access-Control-Allow-Credentials: true.",

	KeyCheckInfoDisclosureTitle: "Technology and version disclosure",
	KeyCheckInfoDisclosureDesc: "The response advertises the server software, framework or a version " +
		"number. This gives an attacker a shortlist of known vulnerabilities to try and saves them " +
		"the work of fingerprinting.",
	KeyCheckInfoDisclosureFix: "Remove or genericise identifying headers such as Server, X-Powered-By " +
		"and X-AspNet-Version at the web server or reverse proxy.",

	KeyCheckMixedContentTitle: "Mixed content on an HTTPS page",
	KeyCheckMixedContentDesc: "An HTTPS page loads a subresource over plain HTTP. The insecure " +
		"resource can be modified in transit, which lets an attacker inject script into an " +
		"otherwise encrypted page.",
	KeyCheckMixedContentFix: "Load every subresource over HTTPS, and enable upgrade-insecure-requests " +
		"in the Content-Security-Policy as a safety net.",

	KeyCheckCacheTitle: "Sensitive response is cacheable",
	KeyCheckCacheDesc: "An authenticated response carries no Cache-Control directive, so a shared " +
		"cache or the browser's disk cache may retain it and serve it to another user of the same " +
		"device or proxy.",
	KeyCheckCacheFix: "Send Cache-Control: no-store on responses that contain user-specific or " +
		"sensitive data.",

	KeyCheckDirListingTitle: "Directory listing enabled",
	KeyCheckDirListingDesc: "The server returned an automatically generated index of a directory. " +
		"This exposes file names that were never linked, including backups and source files.",
	KeyCheckDirListingFix: "Disable automatic directory indexes (Options -Indexes in Apache, " +
		"autoindex off in nginx) and remove files that should not be served.",

	KeyCheckSRITitle: "Third-party subresources loaded without integrity checks",
	KeyCheckSRIDesc: "A script or stylesheet is loaded from another origin without a " +
		"Subresource Integrity hash. If that origin is compromised, or the file is replaced, " +
		"the browser runs whatever it is served and the page has no way to notice.",
	KeyCheckSRIFix: "Add an integrity attribute carrying a SHA-256 or stronger hash to every " +
		"script and stylesheet loaded from another origin, and mark it crossorigin so the " +
		"check is actually applied.",

	KeyCheckErrorDisclosureTitle: "Application error details exposed",
	KeyCheckErrorDisclosureDesc: "The response carries a stack trace or a framework error " +
		"message. It names internal components, file paths and library versions, and it often " +
		"shows exactly which input the application failed on.",
	KeyCheckErrorDisclosureFix: "Handle errors at the edge of the application and return a " +
		"generic message with a correlation id. Log the detail server-side, and turn framework " +
		"debug modes off in production.",

	KeyCheckContentDisclosureTitle: "Internal address, path or mailbox exposed",
	KeyCheckContentDisclosureDesc: "The response body contains something that describes the " +
		"deployment rather than the page: an internal IP address, a server-side file path or a " +
		"mailbox address. None of it belongs in a public response, and together it is enough to " +
		"aim an attack at the infrastructure behind the site.",
	KeyCheckContentDisclosureFix: "Strip deployment detail from everything a visitor can " +
		"read: customise error pages so they no longer print paths, and serve generated markup " +
		"through a build step that removes source comments.",

	KeyCheckPrivateKeyTitle: "Private key exposed",
	KeyCheckPrivateKeyDesc: "The response contains what looks like a PEM private key. Whoever " +
		"fetches this URL owns whatever the key protects: TLS sessions, signed tokens, or " +
		"access to another system entirely.",
	KeyCheckPrivateKeyFix: "Remove the file from the web root and rotate the key immediately — " +
		"a key that has been served must be treated as compromised. Keep private material " +
		"outside any directory the server publishes.",

	KeyCheckInsecureTransportTitle: "Password field served over plain HTTP",
	KeyCheckInsecureTransportDesc: "The page contains a password input and was served without " +
		"TLS, so the credential and the session that follows it travel where anyone on the path " +
		"can read or change them.",
	KeyCheckInsecureTransportFix: "Serve the application over HTTPS only and redirect plain " +
		"HTTP requests to it. Once the certificate is in place, send HSTS so the browser stops " +
		"trying HTTP at all.",

	KeyCheckLibraryTitle: "Front-end library with a known vulnerability",
	KeyCheckLibraryDesc: "The page loads a copy of this library at a version that has a " +
		"published vulnerability. The library is maintained by whoever ships the page, but " +
		"until it is upgraded the flaw is present on every page that loads it — including the " +
		"ones nobody thought to test, because the defect is not in their code.",
	KeyCheckLibraryFix: "Upgrade the library to a release that carries the fix, and track " +
		"front-end dependencies the way server-side ones are tracked, so the version is something " +
		"the build controls. Loading it from a CDN does not move the maintenance to the CDN.",

	KeyCheckSQLiErrorTitle: "SQL injection (error-based)",
	KeyCheckSQLiErrorDesc: "Injecting SQL syntax into this parameter made the database report a " +
		"syntax error. That means the value reaches a SQL statement without being parameterised, so " +
		"an attacker can read, modify or delete anything the application's database user can reach.",
	KeyCheckSQLiErrorFix: "Use parameterised queries (prepared statements) for every value that " +
		"reaches the database, and give the application a least-privilege database account.",

	KeyCheckSQLiBoolTitle: "SQL injection (boolean-based blind)",
	KeyCheckSQLiBoolDesc: "A condition injected into this parameter changed the response in a way " +
		"that tracks the condition's truth value. No error is shown, but the page's own content " +
		"becomes an oracle an attacker can use to extract data one bit at a time.",
	KeyCheckSQLiBoolFix: "Use parameterised queries for every value that reaches the database, and " +
		"do not build SQL by concatenating user input.",

	KeyCheckSQLiTimeTitle: "SQL injection (time-based blind)",
	KeyCheckSQLiTimeDesc: "A delay instruction injected into this parameter made the server pause. " +
		"This works even when the application shows no error and the page looks identical, which " +
		"makes it the most reliable way to confirm that the parameter reaches the database.",
	KeyCheckSQLiTimeFix: "Use parameterised queries for every value that reaches the database, and " +
		"investigate why the database is allowed to run long queries from user input at all.",

	KeyCheckXSSTitle: "Reflected cross-site scripting",
	KeyCheckXSSDesc: "The value sent in this parameter is written into the response without being " +
		"encoded, so it is interpreted as markup. An attacker who can get a victim to follow a " +
		"crafted link can run script in the victim's session on this origin.",
	KeyCheckXSSFix: "Encode output according to its context (HTML text, attribute, URL, script), " +
		"and add a Content-Security-Policy that forbids inline script.",

	KeyCheckPathTraversalTitle: "Path traversal / local file inclusion",
	KeyCheckPathTraversalDesc: "This parameter lets the requested path escape its directory: a " +
		"sequence of ../ walked out of the intended location and the server returned a system file. " +
		"An attacker can read configuration, credentials and source code.",
	KeyCheckPathTraversalFix: "Resolve the path against a fixed base directory and reject anything " +
		"that escapes it; prefer an allowlist of identifiers over accepting file names at all.",

	KeyCheckSSTITitle: "Server-side template injection",
	KeyCheckSSTIDesc: "A template expression injected into this parameter was evaluated by the " +
		"server rather than treated as text. Depending on the engine, this escalates from reading " +
		"server variables to running arbitrary code.",
	KeyCheckSSTIFix: "Never build templates from user input. Pass values as data into a fixed " +
		"template, and use the engine's sandboxed mode where one exists.",

	KeyCheckRedirectTitle: "Open redirect",
	KeyCheckRedirectDesc: "This parameter controls a redirect target and accepts an absolute URL, " +
		"so the application will forward a user to any site an attacker names. That is used to make " +
		"phishing links look like they belong to this domain.",
	KeyCheckRedirectFix: "Only redirect to a fixed allowlist of destinations, or accept a relative " +
		"path and reject anything with a scheme or an authority.",

	KeyCheckCRLFTitle: "CRLF injection / response header injection",
	KeyCheckCRLFDesc: "A carriage-return and line-feed sequence in this parameter was written into " +
		"the response headers, letting an injected header reach the client. Depending on the " +
		"response, this can enable response splitting, cookie fixation or cache poisoning.",
	KeyCheckCRLFFix: "Strip CR and LF from any value that ends up in a header, and reject requests " +
		"whose parameters contain them.",

	KeyCheckNoSQLTitle: "NoSQL injection",
	KeyCheckNoSQLDesc: "An operator or query fragment injected into this parameter changed how the " +
		"database interprets the query, which typically allows authentication to be bypassed or " +
		"records to be read that the caller should not see.",
	KeyCheckNoSQLFix: "Cast incoming parameters to the expected scalar type, and never pass request " +
		"data straight into a query document.",

	KeyCheckSSRFTitle: "Server-side request forgery",
	KeyCheckSSRFDesc: "This parameter makes the server issue a request to a destination an attacker " +
		"controls. From inside the network that reaches internal services, cloud metadata endpoints " +
		"and administrative interfaces that are unreachable from outside.",
	KeyCheckSSRFFix: "Validate destinations against an allowlist, block link-local and private " +
		"address ranges, and do not follow redirects on user-supplied URLs.",

	KeyCheckIDORTitle: "Insecure direct object reference (horizontal privilege escalation)",
	KeyCheckIDORDesc: "Two different authenticated sessions received the same protected content for " +
		"this object, while an unauthenticated request did not. The object is addressed by a value the " +
		"client controls and is not scoped to its owner, so any signed-in user can read another user's " +
		"data simply by changing that value.",
	KeyCheckIDORFix: "Resolve the object from the session's own identity instead of from the request: " +
		"look the record up by owner and id together, or check ownership before returning it. A " +
		"client-supplied identifier is never proof of authorisation.",

	KeyCheckAccessVariantsTitle: "Access rule bypassed by a different method or path spelling",
	KeyCheckAccessVariantsDesc: "The request was refused, but the same resource answered when it " +
		"was addressed slightly differently — another method, or the same path spelled another " +
		"way. The rule is enforced by one layer against one spelling while another layer serves " +
		"the resource, so the refusal is real for the request that was tested and absent for the " +
		"one that was not.",
	KeyCheckAccessVariantsFix: "Enforce the rule where the resource is served rather than at the " +
		"edge, and cover every spelling: normalise the path once, before any rule is evaluated, " +
		"and authorise the action rather than the method that carried it.",

	KeyEvidenceIDOR: "both authenticated sessions read the same object (%s of %s of the response " +
		"matched) while an anonymous request did not",

	KeyEvidenceAccessRule: "the original request was refused with %d, while the variant %q " +
		"was answered with %d",

	KeyCheckPaginationTitle: "Page size parameter does not bound the response",
	KeyCheckPaginationDesc: "Bounding the request to a single record and then asking with a value " +
		"outside the parameter's intended range changed how much came back, and by a lot. The " +
		"parameter is being read as a hint rather than enforced as a limit, so a caller can ask " +
		"for a whole collection in one response — which is how an endpoint that was meant to be " +
		"paged turns into a bulk export.",
	KeyCheckPaginationFix: "Clamp the page size server-side to a bounded maximum, and reject a " +
		"value outside it rather than interpreting it. Authorise the caller against the " +
		"collection before any of it is serialised, so the size of the response is never the " +
		"thing standing between a user and other people's data.",

	KeyEvidencePagination: "bounded to %d record(s) the response was %d bytes, while %q " +
		"returned %d bytes",

	KeyCheckTypeBypassTitle: "Input validation bypassed by wrapping the parameter",
	KeyCheckTypeBypassDesc: "A value refused on its own was accepted once the same parameter " +
		"was written in array form. The check on that value was written for a scalar while the " +
		"framework hands the handler something else, so the validation never sees what it was " +
		"meant to reject — the pattern behind a surprising share of authorization bypasses.",
	KeyCheckTypeBypassFix: "Validate the type the framework actually delivers before looking at " +
		"the value, and reject a parameter that arrives with the wrong shape rather than " +
		"coercing it. Authorise against the resolved value, not against the raw string.",

	KeyEvidenceTypeBypass: "the value %q was refused with %d, while the same value written as " +
		"%q was answered with %d",

	KeyCheckWebSocketTitle: "WebSocket handshake completed for any origin",
	KeyCheckWebSocketDesc: "The endpoint accepted a WebSocket handshake from an origin it does " +
		"not serve, with the caller's session attached. A WebSocket handshake is not subject to " +
		"the same-origin policy, so a page on any site can open this socket with the visitor's " +
		"credentials and read what it carries.",
	KeyCheckWebSocketFix: "Check the Origin header on the handshake against a list of the " +
		"origins that may connect, and refuse the rest before upgrading. Requiring a token in " +
		"the first message is a second option, but the origin is the check the browser cannot " +
		"be talked out of sending.",
	KeyCheckRefererBypassTitle: "Request protection resting on the Referer header",
	KeyCheckRefererBypassDesc: "With the request sent the way it is normally sent, a token the " +
		"server cannot have issued was refused. With the same forged token and the Referer " +
		"header removed — or naming another site — the request was accepted. The browser may " +
		"omit that header, and a page on another site sends its own address, so a guard that " +
		"only holds when the header is present and correct does not hold.",
	KeyCheckRefererBypassFix: "Protect state-changing requests with a token the caller has to " +
		"obtain from the application, and check it on every path that changes something. " +
		"Referer and Origin are supplementary signals at best: use them to reject, never to " +
		"permit on their own.",
	KeyCheckContentTypeBypassTitle: "Request protection attached to one Content-Type",
	KeyCheckContentTypeBypassDesc: "With the request sent the way it is normally sent, a token " +
		"the server cannot have issued was refused. With the body unchanged and a different " +
		"Content-Type, the same request was accepted — the guard lives in one branch, and a " +
		"caller picks the branch by labelling the body.",
	KeyCheckContentTypeBypassFix: "Check the token before dispatching on the body's type, or " +
		"reject any type the endpoint does not explicitly accept. A guard written inside one " +
		"branch protects that branch only.",
	KeyCheckJSONPTitle: "Response wrapped in a caller-supplied callback name",
	KeyCheckJSONPDesc: "The endpoint wrapped its response in the callback name the request " +
		"asked for, which is what a JSONP interface does: it can be loaded as a script by any " +
		"site, and the value it returns is read by that site. Whether that matters depends on " +
		"what the endpoint serves — an endpoint returning a session token this way is a " +
		"cross-site read of it.",
	KeyCheckJSONPFix: "Serve data under the same-origin policy and let a client send " +
		"credentials explicitly: use CORS with an allow-list rather than a callback, or if a " +
		"callback has to be supported, verify both the callback name and the caller's origin " +
		"against a list.",
	KeyCheckExposedPathTitle: "File served that was never meant to be served",
	KeyCheckExposedPathDesc: "A request for a well-known path that nothing links to returned a " +
		"file with the contents of one: an environment file with credentials in it, a git " +
		"directory with the whole history, a database dump, a configuration backup, a status " +
		"page. These are not reachable by crawling — they are found by asking for them by name, " +
		"which is exactly what an attacker does first.",
	KeyCheckExposedPathFix: "Serve only what the application needs: keep these files outside " +
		"the document root, deny them by name in the server configuration as a backstop, and " +
		"stop deploying backups and version-control metadata with the code.",
	KeyCheckCORSOriginTitle: "Cross-origin policy that trusts the origin it is given",
	KeyCheckCORSOriginDesc: "The response named the origin the request carried in " +
		"Access-Control-Allow-Origin, for an origin no correct configuration would accept. That " +
		"grant is what lets another site read this site's responses in a visitor's browser; with " +
		"Access-Control-Allow-Credentials it lets any site do so with the visitor's own " +
		"credentials attached. It usually comes from a hand-written comparison — a host name " +
		"matched as a prefix or a suffix, a scheme not compared, or `null` allowed because " +
		"sandboxed frames send it.",
	KeyCheckCORSOriginFix: "Compare the whole origin against a list, scheme included, and never " +
		"build it from the request. If several origins are needed, check each one in full; " +
		"`null` is not an origin to allow. Allow credentials only where they are required.",
	KeyCheckHTTPPutTitle: "Files written through the PUT method",
	KeyCheckHTTPPutDesc: "The server stored the body of a PUT request under the path that " +
		"request named, and served it back from the same address. That is an upload endpoint " +
		"nobody configured on purpose — a static host, a build output directory, a " +
		"half-configured WebDAV handler — and the caller chooses the file name, which means the " +
		"caller chooses the extension the server will run.",
	KeyCheckHTTPPutFix: "Refuse write methods at the server for anything that is not a " +
		"deliberate upload endpoint: disable WebDAV, and where a PUT is wanted, restrict it to " +
		"an authenticated path whose contents are never executed.",
	KeyCheckIPSpoofTitle: "Restricted endpoint opened by a spoofed client address",
	KeyCheckIPSpoofDesc: "The endpoint refused the request, and answered it once a header " +
		"naming a loopback or private address was added. That means the restriction is applied " +
		"to the address the caller claims rather than the one it connected from — and a claimed " +
		"address is one anybody can write. Headers like X-Forwarded-For are set by a front end " +
		"and are only worth trusting when it is known to have set them; an application reachable " +
		"directly cannot tell the difference.",
	KeyCheckIPSpoofFix: "Take the client address from the connection, not from a request " +
		"header. Where a proxy is in front, have it overwrite the header rather than append to " +
		"it, restrict the origin to the proxy's addresses, and make the application refuse " +
		"requests that did not come from it.",
	KeyCheckPathOverrideTitle: "Request path decided by a header",
	KeyCheckPathOverrideDesc: "A request header (X-Original-URL, X-Rewrite-URL or similar) " +
		"decided which path the application handled: asking for a path that does not exist " +
		"returned the response for another one. The header exists for deployments where a " +
		"proxy routes on the URL and passes the intended path along, and it is only safe while " +
		"the backend insists the request came through that proxy. When it does not, the access " +
		"control the proxy performs applies to one path while the application serves another.",
	KeyCheckPathOverrideFix: "Stop honouring path headers from the request, or have the edge " +
		"strip them before forwarding, and make the application reachable only through the " +
		"proxy — so a request that bypasses it cannot arrive at all.",
	KeyCheckCSPTitle: "Content-Security-Policy that does not restrict script",
	KeyCheckCSPDesc: "A Content-Security-Policy is sent, and it permits what the policy " +
		"exists to stop: inline script (`'unsafe-inline'`), dynamic evaluation " +
		"(`'unsafe-eval'`), any origin (`*`), or `data:` as a script source. The header being " +
		"present is what makes this easy to miss — a policy that allows inline script gives " +
		"no protection against the injected `<script>` it is meant to be the second line of " +
		"defence against. A policy sent only as `Content-Security-Policy-Report-Only` is not " +
		"enforced at all.",
	KeyCheckCSPFix: "Remove `'unsafe-inline'` and `'unsafe-eval'` from the script directive and " +
		"move the inline code into files, or keep it and pin it with a per-response nonce " +
		"(`'nonce-…'`) — a nonce makes the browser ignore `'unsafe-inline'`, so a policy that " +
		"already has one is doing better than it looks. Name the origins you need rather than " +
		"`*`, and send the policy as Content-Security-Policy rather than Report-Only once the " +
		"reports are quiet.",
	KeyCheckCSTITitle: "Client-side template injection",
	KeyCheckCSTIDesc: "A value from the address was handed to a template compiler in the " +
		"browser, and the compiler evaluated it as an expression. The server returns the same " +
		"bytes either way, so this is invisible to anything that reads responses: what changes " +
		"is what the page renders. It matters because the same input class that evaluates " +
		"arithmetic carries code in the compiler's own syntax, and a page that compiles its " +
		"address is a page whose address is code.",
	KeyCheckCSTIFix: "Never compile a value that came from the address. Pass it as data — " +
		"`ng-bind` or a text binding rather than a template — and keep the framework current, " +
		"since most of these flaws are fixed in the compiler itself.",
	KeyCheckPrototypePollutionTitle: "Prototype pollution through a query string",
	KeyCheckPrototypePollutionDesc: "The page's own code merged the query string into an object " +
		"without refusing `__proto__`, so a property named in the request was written onto " +
		"`Object.prototype`. Every object created afterwards — in the page, in every script it " +
		"loads, in every library it calls — inherits that property. What an attacker gains " +
		"depends on what reads it: a flag that disables a check, a default that redirects, a " +
		"gadget that reaches a DOM sink.",
	KeyCheckPrototypePollutionFix: "Reject `__proto__`, `constructor` and `prototype` as keys at " +
		"the point the query is parsed, and build objects with `Object.create(null)` or a Map " +
		"where a lookup table is needed. Freeze `Object.prototype` as a backstop, and keep the " +
		"parser libraries current — most prototype-pollution bugs are fixed in the library.",
	KeyCheckDOMXSSTitle: "Cross-site scripting through the page's own script",

	KeyCheckDOMXSSDesc: "The page took a value from the URL and put it into the document as " +
		"markup, and a browser running the page executed what was placed there. The server " +
		"never saw the payload — the value came from the address bar — so nothing server-side " +
		"could have filtered it, and no response body shows the flaw.",
	KeyCheckDOMXSSFix: "Build the DOM with text rather than markup: use textContent instead of " +
		"innerHTML, create elements and set attributes rather than assembling a string, and " +
		"treat every value from location, a postMessage or storage as untrusted input. A " +
		"Content-Security-Policy without unsafe-inline is the backstop, not the fix.",

	KeyCheckLDAPTitle: "LDAP injection",
	KeyCheckLDAPDesc: "A value carrying LDAP filter syntax reached a directory query: the " +
		"response contains the directory library's own complaint about a malformed filter. A " +
		"filter is a query language, so a value spliced into one stops being a value and " +
		"becomes a term — which is how a check that asks whether any entry matches turns into a " +
		"check that asks whether the filter parsed.",
	KeyCheckLDAPFix: "Pass the value as a filter argument rather than building the filter out of " +
		"it, or escape the characters LDAP gives meaning to — * ( ) \\ NUL — before it is used. " +
		"Resolve the user first and compare the credential afterwards, instead of asking the " +
		"directory to match both at once.",

	KeyCheckXPathTitle: "XPath injection",
	KeyCheckXPathDesc: "A value carrying XPath syntax reached an XPath expression: the response " +
		"contains the parser's own complaint. XPath has no parameter binding, so a value can " +
		"only be placed in an expression by quoting it — and a quote the value brings with it is " +
		"enough to close the literal its author opened.",
	KeyCheckXPathFix: "Use the XPath API's variable binding (an expression compiled with a " +
		"resolver) instead of assembling the expression from strings, or validate the value " +
		"against a strict allowlist first. Escaping is a fallback, not the fix.",

	KeyCheckODataTitle: "OData query injection",
	KeyCheckODataDesc: "A value carrying OData query syntax reached a service query: the response " +
		"contains the library's own complaint about a malformed query. The system query options — " +
		"$filter, $orderby, $expand — are a query language written into the URL, and a value " +
		"spliced into one can close the expression it was meant to be a term in.",
	KeyCheckODataFix: "Build the query through the library's typed API rather than concatenating " +
		"the value into it, and reject a value that carries query syntax where a literal is " +
		"expected.",

	KeyCheckGraphQLTitle: "GraphQL schema exposed by introspection",
	KeyCheckGraphQLDesc: "The endpoint answers a schema query, so anyone can read the whole type " +
		"system: every query, mutation and field, including the ones no client calls and the ones " +
		"that were never meant to be public. That is the map an attacker would otherwise have to " +
		"draw by hand.",
	KeyCheckGraphQLFix: "Turn introspection off in production, and keep it available only to " +
		"authenticated developers if the tooling needs it. Add a query allowlist as well, so a " +
		"schema that does leak still does not amount to a set of operations that can be run.",

	KeyEvidenceParser: "the response carries %q, which only %s produces when it is handed input " +
		"it cannot parse",

	KeyCheckCachePoisonTitle: "Cached response poisoned through a request header",
	KeyCheckCachePoisonDesc: "A value sent in a request header came back in the response, and " +
		"then came back again for a request that never sent it. That second response was served " +
		"from a cache: the value was written into a shared copy of the page, and every visitor " +
		"the cache serves that copy to will receive it. What the value does there depends on " +
		"where the page puts it — a link, a script, a redirect — and none of it requires the " +
		"victim to send anything.",
	KeyCheckCachePoisonFix: "Include every header that reaches the response in the cache key, " +
		"or drop the ones the application does not need at the edge. Do not build URLs or links " +
		"from a request header; derive them from configuration, or validate the header against " +
		"an allowlist of hosts you control. Caches that honour Cache-Control: private or " +
		"no-store on such responses are the backstop, not the fix.",

	KeyEvidenceCache: "a request carrying %s returned the value, and the same request without " +
		"it was then served the cached copy",

	KeyFlagSession: "An authenticated session as a 'Name: value' header, e.g. 'Cookie: sess=abc'; " +
		"repeat with at least two different sessions to enable the access-control check.",

	KeyMsgSessionsLoaded:    "loaded %d session(s) for access-control comparison",
	KeyMsgIDORNeedsSessions: "the access-control check needs at least two --session values and was skipped",

	KeyCheckCMDiTitle: "Command injection",
	KeyCheckCMDiDesc: "This parameter is passed to a shell without escaping, so an attacker can run " +
		"arbitrary operating-system commands with the web server's privileges. The finding is " +
		"proved one of two ways: the response carries the output of a command that was asked to " +
		"read a file, or the target called back to an address the scanner controls.",
	KeyCheckCMDiFix: "Avoid the shell entirely: use an API, or pass arguments as an array to an " +
		"exec call. If a shell is unavoidable, allowlist the permitted characters and values.",

	KeyEvidenceBoolean: "true branch matched the baseline (%s), false branch did not (%s); " +
		"the two branches differ (%s)",
	KeyEvidenceTiming:  "the response took %s against a baseline of %s",
	KeyEvidenceReflect: "the payload came back unencoded: %s",
	KeyEvidenceOOB:     "the target called back to %s (%s from %s)",

	KeyReportTitle:       "crackweb vulnerability report",
	KeyReportSubtitle:    "Traffic-driven DAST scan",
	KeyReportSummary:     "Summary",
	KeyReportTarget:      "Target",
	KeyReportStarted:     "Started",
	KeyReportFinished:    "Finished",
	KeyReportDuration:    "Duration",
	KeyReportHosts:       "Hosts",
	KeyReportEndpoints:   "Endpoints tested",
	KeyReportRequests:    "Requests sent",
	KeyReportFindings:    "Findings",
	KeyReportNoFindings:  "No vulnerabilities were identified.",
	KeyReportGeneratedBy: "Generated by %s",
	KeyReportDisclaimer: "This report describes the state of the target at the time of the scan. " +
		"An absent finding is not proof of absence. Use crackweb only against systems you are " +
		"authorised to test.",
	KeyReportFilter:      "Filter by severity, host, check or URL…",
	KeyReportExpandAll:   "Expand all",
	KeyReportCollapseAll: "Collapse all",

	KeyReportFieldCheck:       "Check",
	KeyReportFieldSeverity:    "Severity",
	KeyReportFieldConfidence:  "Confidence",
	KeyReportFieldURL:         "URL",
	KeyReportFieldParam:       "Parameter",
	KeyReportFieldPayload:     "Payload",
	KeyReportFieldDescription: "Description",
	KeyReportFieldRemediation: "Remediation",
	KeyReportFieldReferences:  "References",
	KeyReportFieldRequest:     "Request",
	KeyReportFieldResponse:    "Response",
	KeyReportFieldBaseline:    "Baseline response",
	KeyReportFieldEvidence:    "Evidence",
	KeyReportFieldDiff:        "Difference",
	KeyReportCurl:             "Reproduce with curl",
	KeyReportCWE:              "CWE",

	KeySeverityCritical: "Critical",
	KeySeverityHigh:     "High",
	KeySeverityMedium:   "Medium",
	KeySeverityLow:      "Low",
	KeySeverityInfo:     "Info",
	KeySeverityUnknown:  "Unknown",

	KeyConfidenceCertain:   "Certain",
	KeyConfidenceFirm:      "Firm",
	KeyConfidenceTentative: "Tentative",

	KeyMsgReportWritten: "report written to %s",
	KeyFlagTimeout:      "Per-request timeout, e.g. 10s or 500ms.",
	KeyFlagRate:         "Maximum outgoing requests per second; 0 means unlimited.",
	KeyFlagThreads:      "How many checks run at once.",
	KeyFlagInsecure:     "Skip TLS certificate verification when talking to targets.",
	KeyFlagUserAgent:    "User-Agent to send; by default crackweb identifies itself.",
	KeyFlagProxy:        "Route outgoing requests through this proxy (http:// or socks5://).",
	KeyFlagSensitivity:  "Difference sensitivity from 1 to 5; higher reports more, with more false positives.",
	KeyFlagSkipParams:   "Parameter names never to inject into; repeatable.",
	KeyFlagListChecks:   "List the available checks and exit.",
	KeyFlagVerbose:      "Print every request crackweb sends.",
	KeyFlagTemplates:    "Directory of nuclei-compatible YAML templates; repeatable.",
	KeyFlagExportCA:     "Write the CA certificate to this PEM file so it can be installed.",
	KeyFlagNoNormalize:  "Compare responses byte for byte instead of normalising dynamic content.",

	KeyMsgProxyListening: "crackweb proxy listening on %s",
	KeyMsgProxyCAHint: "Install the CA certificate (%s) in your browser or system trust store " +
		"to let crackweb read HTTPS traffic.",
	KeyMsgProxyStopped:            "proxy stopped",
	KeyMsgCAGenerated:             "generated a new CA at %s",
	KeyMsgCALoaded:                "loaded the CA from %s",
	KeyMsgScanStarted:             "scanning %s",
	KeyMsgScanFinished:            "scan finished: %d finding(s) from %d request(s) in %s",
	KeyMsgNoFindings:              "no vulnerabilities found",
	KeyMsgOOBListening:            "out-of-band server listening: http %s, dns %s",
	KeyMsgProxyCredentialsIgnored: "proxy forwards the browser's own traffic, so the identity is whatever the browser sends; --cookie and --header apply to scans crackweb initiates and are ignored here. Log in through the browser instead.",
	KeyMsgOOBInteractsh:           "out-of-band interactions collected at %s",
	KeyMsgUnknownChecks:           "unknown check or tag: %s",
	KeyMsgChecksLoaded:            "loaded %d check(s): %d passive, %d active",
	KeyMsgRequestError:            "request failed: %v",
	KeyMsgTemplateLoaded:          "loaded %d template(s) from %s",
	KeyMsgChecksListed:            "checks",
	KeyMsgOOBCallbackExample:      "callback URLs look like %s (one is minted per injection)",
	KeyMsgCAExported:              "CA certificate exported to %s",
	KeyMsgCrawlStats:              "crawl: %d page(s) fetched, %d URL(s) discovered, %d request(s) scanned",
	KeyMsgTemplateUnsupported:     "template %s uses features crackweb cannot run and was skipped: %s",
	KeyMsgNoBrowser:               "no Chromium-based browser found, so the headless crawler is unavailable; continuing with the HTTP engine. Install Chrome, Chromium or Edge, point CRACKWEB_CHROME at a browser binary, or choose --engine http to silence this.",

	KeyErrBadSensitivity: "sensitivity must be between 1 and 5",
	KeyErrNoChecks:       "none of the requested checks exist; use --list-checks to see them",
	KeyErrLoadCA:         "could not load or create the CA: %v",
	KeyErrReadRaw:        "could not read %s: %v",
	KeyErrStartProxy:     "could not start the proxy: %v",
	KeyEvidenceVariant:   "payload variant: %s (generation %d, transformations: %s)",
	KeyEvidenceCSRF: "Replaced the anti-CSRF field %s with %s — a value the server could not " +
		"have issued — and the request was still accepted (response %.0f%% identical to the " +
		"baseline). A token the server never checks is decoration.",
	KeyEvidenceWAF:            "the target is behind %s; payloads were escalated through %d mutation generation(s)",
	KeyReportBoundaryTitle:    "Coverage boundary",
	KeyReportUnanswered:       "Requests that never produced a response: %d",
	KeyReportProtectedTitle:   "Hosts where something answered for the application:",
	KeyReportProtectedNothing: "Nothing refused a request on this run.",

	KeyMsgUnanswered:          "%d request(s) never got a response",
	KeyMsgProtectedHost:       "something answered for %s",
	KeyMsgProtectedWithVendor: "something answered for %s (%s)",
	KeyMsgChecksOptIn:         "opt-in",
	KeyMsgProbing:             "asking each host for an API description, robots.txt and a sitemap",
	KeyMsgSelfDescribed:       "read %d description(s) and %d site file(s)",

	KeyFlagAPIDoc: "Also ask for an API description at this path, in addition to the common " +
		"ones. Sites publish them under names of their own — a version prefix, an internal " +
		"name — and no guess finds those. Repeatable.",
	KeyFlagAllowStateChange: "Also queue the endpoints a page's script only calls with POST, " +
		"PUT, PATCH or DELETE. They are skipped by default: the crawler fetches what it " +
		"discovers with GET, and a request to an address whose own script says \"delete\" is " +
		"not obviously harmless to whatever is behind it — an upload form among them. The " +
		"HTML forms a page declares are unaffected: they are submitted on their own path.",
	KeyFlagNoDiscovery: "Skip asking for an API description, robots.txt or a sitemap; test only what the crawl reaches.",
	KeyFlagNoAssumeWAF: "Keep WAF detection, but drop the assumption that a firewall is there: " +
		"the extra generations are sent only when a refusal was actually detected. By default they " +
		"are sent regardless, because a modern edge often rewrites a payload and answers 200 rather " +
		"than refusing it, which leaves detection nothing to see. Use this against a target you " +
		"know has nothing in front of it.",
	KeyFlagNoWAF: "Turn WAF detection off as well. No vendor fingerprint is looked for, so " +
		"a firewall that refuses in its own way goes unrecognised and its payloads are never " +
		"mutated. --no-assume-waf keeps the detection and drops only the assumption; this drops " +
		"both. A plainly worded refusal is still acted on either way.",
	KeyCheckXXETitle: "XML external entity injection",
	KeyCheckXXEDesc: "The XML parser resolved an external entity declared in the request. " +
		"A parser that has entity resolution enabled will fetch a URL the caller names, which turns " +
		"a document upload into a way to read local files or reach services behind the firewall.",
	KeyCheckXXEFix: "Disable external entity and DTD processing on every XML parser " +
		"(LIBXML_NOENT and friends), and prefer a format that does not carry a schema.",

	KeyCheckJWTTitle: "JSON Web Token accepted without a valid signature",
	KeyCheckJWTDesc: "A token whose signature was removed or whose algorithm was changed was " +
		"accepted by the application. Anyone can then mint a token claiming any identity, which " +
		"makes every authorisation decision downstream meaningless.",
	KeyCheckJWTFix: "Pin the accepted algorithm on the verifying side, reject alg:none outright, " +
		"and never let the token's own header choose which key or method to use.",

	KeyCheckCSRFTitle: "State-changing request without CSRF protection",
	KeyCheckCSRFDesc: "A request that changes server state was accepted without a token, and the " +
		"session cookie is sent on cross-site requests. Any page the victim visits can then submit " +
		"this request as them.",
	KeyCheckCSRFFix: "Require a per-session token on every state-changing request, validate it " +
		"server-side, and set SameSite=Lax on session cookies as a second line.",

	KeyCheckHostHeaderTitle: "Host header injection",
	KeyCheckHostHeaderDesc: "The application trusted the Host header: a value the attacker " +
		"supplied appeared in the response or in a generated link. That enables password-reset " +
		"poisoning and cache poisoning without touching the victim at all.",
	KeyCheckHostHeaderFix: "Build absolute URLs from a configured canonical host rather than from " +
		"the request, and reject requests whose Host is not in an allowlist.",
	KeyCheckUploadTitle: "Unsafe file upload handling",
	KeyCheckUploadDesc: "The upload endpoint accepted a file whose name is dangerous — an " +
		"executable extension, a double extension that a naive check passes, or a path that escapes " +
		"the upload directory. Acceptance is not exploitation: it means the server did not refuse " +
		"input that a hardened endpoint would have.",
	KeyCheckUploadFix: "Decide the file type from content rather than from the name, store uploads " +
		"outside the web root under a generated name, and reject any name containing a path separator.",

	KeyCheckDeserialTitle: "Untrusted data is being deserialised",
	KeyCheckDeserialDesc: "Sending a malformed serialised object produced a deserialisation error, " +
		"which means the application parses serialised data from a request. If an attacker can reach " +
		"a gadget chain for the runtime in use, that is remote code execution — the entry point is " +
		"confirmed here, the chain is not.",
	KeyCheckDeserialFix: "Do not accept serialised objects from clients. Use a data format such as " +
		"JSON with an explicit schema, and if a serialised format is unavoidable, restrict it to an " +
		"allowlist of types.",
	KeyEvidenceTimingStat: "over %d samples the median was %s against a baseline of %s " +
		"(variation %s); %s",
	KeyEvidenceHPP: "the payload was sent as a second occurrence of the same parameter, " +
		"so a filter reading the first one would not have seen it",
	KeyCheckSecondOrderTitle: "Stored injection (second-order)",
	KeyCheckSecondOrderDesc: "A value written through one request was later used unsafely by " +
		"another: a page that had returned normally started returning a database error after the " +
		"write. The request that stores the payload looks harmless on its own, which is what makes " +
		"these bugs survive testing that only inspects one request at a time.",
	KeyCheckSecondOrderFix: "Treat stored data as untrusted when it is read, not just when it is " +
		"written: parameterise the query that consumes it, and validate on the way out as well as " +
		"on the way in.",
	KeyFlagUnsafeChecks: "Also run the checks marked opt-in by --list-checks. Their probes do " +
		"more than send a request: a smuggling probe leaves bytes on the connection for the " +
		"next request to read, a DOM check runs every script the page carries, and a cache " +
		"probe writes into a shared cache. Use only against systems you own.",
	KeyMsgUnsafeChecks:          "running checks with side effects: %s",
	KeyCheckMethodOverrideTitle: "HTTP method override is honoured",
	KeyCheckMethodOverrideDesc: "The application accepted a request whose real method is harmless " +
		"but which asked, in a header, to be treated as a state-changing one. If access control is " +
		"written against the request line and not against the override, a method that was meant to " +
		"be refused is reachable.",
	KeyCheckMethodOverrideFix: "Do not honour method-override headers unless a front end strips " +
		"them, and never derive an authorisation decision from the request line alone.",

	KeyCheckSmugglingTitle: "HTTP request smuggling (desynchronisation)",
	KeyCheckSmugglingDesc: "A request whose framing headers disagree produced more than one " +
		"response, which means the front end and the back end disagree about where it ends. The " +
		"leftover bytes are then read as the beginning of the next request on that connection — " +
		"someone else's request. This check sends probes with side effects and is off by default.",
	KeyCheckSmugglingFix: "Make every hop agree: reject requests that carry both Content-Length " +
		"and Transfer-Encoding, normalise them at the edge, and use an HTTP/2 end to end where " +
		"possible.",
	KeyCheckSQLiUnionTitle: "SQL injection (UNION-based)",
	KeyCheckSQLiUnionDesc: "The result set of the query was extended with rows the caller chose. " +
		"The column count was found by trial, and each column was filled with a unique number so " +
		"that the injected values can be recognised in the page as data rather than as a reflection " +
		"of the input. Unlike an error-based finding, this needs no message from the database — the " +
		"page reports success by simply showing what was asked for.",
	KeyCheckSQLiUnionFix: "Parameterise the query. Where a UNION is genuinely needed, never " +
		"concatenate caller-supplied text into it.",
	KeyCheckCleartextPasswordTitle: "Password submitted over an unencrypted connection",
	KeyCheckCleartextPasswordDesc: "A credential was sent to the server over http://, where it " +
		"crosses the network in readable form. Anyone able to observe the traffic — a shared " +
		"switch, a conference network, anything upstream — can read it and use it. The value is " +
		"deliberately not reproduced in this report; the field name and the request line locate " +
		"the problem without spreading the secret.",
	KeyCheckCleartextPasswordFix: "Serve the whole application over HTTPS and redirect http:// to " +
		"it, with HSTS so the redirect cannot be stripped. Until then, treat any credential " +
		"submitted this way as compromised.",
	KeyFlagCookie:            "Session cookie(s) sent with every request, e.g. session=abc; csrf=xyz. Repeatable; a leading Cookie: is tolerated.",
	KeyFlagHeader:            "Extra header sent with every request, in Name: value form. Repeatable - use it for bearer tokens and API keys.",
	KeyFlagBasicAuth:         "HTTP Basic credentials as user:password; sent as an Authorization header.",
	KeyFlagRandomUA:          "Compose a fresh, plausible User-Agent for every request instead of identifying as crackweb. Use it when the tool's own name would pollute a log you are reviewing, or to keep a scan from being grouped by fingerprint.",
	KeyCheckSQLiOrderByTitle: "SQL injection (ORDER BY)",
	KeyCheckSQLiOrderByDesc: "A parameter that selects a sort column was concatenated into " +
		"the ORDER BY clause. This position cannot be fixed the way the others can — a column " +
		"name cannot be bound — which is why the flaw survives frameworks that parameterise " +
		"everything else, and why the other SQL checks do not see it: the clause takes no " +
		"quoted string and extends with no UNION. The finding rests on the clause's own " +
		"behaviour: a term in range was accepted with the page left alone, and a column " +
		"position past the end of the result set was refused.",
	KeyCheckSQLiOrderByFix: "Map the caller's value onto a fixed list of allowed column names " +
		"rather than passing it through. A row limit is a different position: bind it as an " +
		"integer, which is what the pagination-bypass check looks for.",
	KeyCheckXSSStoredTitle: "Stored cross-site scripting",
	KeyCheckXSSStoredDesc: "A value submitted to the application was saved and later served back " +
		"to a reader as markup, so the script runs in their browser. Unlike a reflected payload, " +
		"this one persists: it executes for every visitor who loads the page, without them having " +
		"to be lured into clicking anything.",
	KeyCheckXSSStoredFix: "Encode on output, not only on input — the value may be written through " +
		"one path and rendered by another. Use a templating engine that escapes by default, and " +
		"where rich text is required, sanitise it against a published allow-list.",
}
