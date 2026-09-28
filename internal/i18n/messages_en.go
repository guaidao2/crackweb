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

	KeyCmdProxySummary: "Run the intercepting proxy: browse through it and crackweb tests the traffic it sees.",
	KeyCmdCrawlSummary: "Crawl a target and scan every request it discovers.",
	KeyCmdScanSummary:  "Scan a single target, or a raw HTTP request saved from another tool.",
	KeyCmdOobSummary:   "Run the out-of-band interaction server (DNS and HTTP callbacks).",
	KeyCmdCaSummary:    "Manage the CA certificate used for HTTPS interception.",

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
	KeyFlagChecks:     "Comma-separated check names, or 'all'.",
	KeyFlagScanOutput: "Report path; the format follows the extension (.html, .json, .sarif, .md).",

	KeyFlagDNSAddr:   "Listen address for the DNS interaction server, e.g. 0.0.0.0:5353.",
	KeyFlagHTTPAddr:  "Listen address for the HTTP interaction server, e.g. 0.0.0.0:8081.",
	KeyFlagOOBToken:  "Shared secret used to correlate a callback with the request that triggered it.",
	KeyFlagOOBDomain: "Base domain pointing at this server, when running behind a delegation.",

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

	KeyEvidenceIDOR: "both authenticated sessions read the same object (%s of %s of the response " +
		"matched) while an anonymous request did not",

	KeyFlagSession: "An authenticated session as a 'Name: value' header, e.g. 'Cookie: sess=abc'; " +
		"repeat with at least two different sessions to enable the access-control check.",

	KeyMsgSessionsLoaded:    "loaded %d session(s) for access-control comparison",
	KeyMsgIDORNeedsSessions: "the access-control check needs at least two --session values and was skipped",

	KeyCheckCMDiTitle: "Command injection",
	KeyCheckCMDiDesc: "This parameter is passed to a shell without escaping, so an attacker can run " +
		"arbitrary operating-system commands with the web server's privileges.",
	KeyCheckCMDiFix: "Avoid the shell entirely: use an API, or pass arguments as an array to an " +
		"exec call. If a shell is unavoidable, allowlist the permitted characters and values.",

	KeyEvidenceBoolean: "true branch matched the baseline (%.3f), false branch did not (%.3f); " +
		"the two branches differ (%.3f)",
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
	KeyMsgProxyStopped:        "proxy stopped",
	KeyMsgCAGenerated:         "generated a new CA at %s",
	KeyMsgCALoaded:            "loaded the CA from %s",
	KeyMsgScanStarted:         "scanning %s",
	KeyMsgScanFinished:        "scan finished: %d finding(s) from %d request(s) in %s",
	KeyMsgNoFindings:          "no vulnerabilities found",
	KeyMsgOOBListening:        "out-of-band server listening: http %s, dns %s",
	KeyMsgUnknownChecks:       "unknown check or tag: %s",
	KeyMsgChecksLoaded:        "loaded %d check(s): %d passive, %d active",
	KeyMsgRequestError:        "request failed: %v",
	KeyMsgTemplateLoaded:      "loaded %d template(s) from %s",
	KeyMsgChecksListed:        "checks",
	KeyMsgOOBCallbackExample:  "callback URLs look like %s (one is minted per injection)",
	KeyMsgCAExported:          "CA certificate exported to %s",
	KeyMsgCrawlStats:          "crawl: %d page(s) fetched, %d URL(s) discovered, %d request(s) scanned",
	KeyMsgTemplateUnsupported: "template %s uses features crackweb cannot run and was skipped: %s",
	KeyMsgNoBrowser:           "no Chromium-based browser found, so the headless crawler is unavailable; continuing with the HTTP engine. Install Chrome, Chromium or Edge, point CRACKWEB_CHROME at a browser binary, or choose --engine http to silence this.",

	KeyErrBadSensitivity: "sensitivity must be between 1 and 5",
	KeyErrNoChecks:       "none of the requested checks exist; use --list-checks to see them",
	KeyErrLoadCA:         "could not load or create the CA: %v",
	KeyErrReadRaw:        "could not read %s: %v",
	KeyErrStartProxy:     "could not start the proxy: %v",
	KeyEvidenceVariant:   "payload variant: %s (generation %d, transformations: %s)",
	KeyEvidenceWAF:       "the target is behind %s; payloads were escalated through %d mutation generation(s)",
	KeyFlagNoWAF:         "Disable WAF detection and payload mutation; send each payload as written.",
	KeyCheckXXETitle:     "XML external entity injection",
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
	KeyFlagUnsafeChecks: "Also run checks whose probes can affect the target beyond the request " +
		"they send (request smuggling). Use only against systems you own.",
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
}
