package i18n

// Every user-facing message is addressed by one of these keys. Keeping them in
// a single block makes it obvious what still needs translating, and the
// catalogue tests fail the build when a language misses an entry or when the
// printf verbs of a translation drift away from the English original.
const (
	// Application banner and boilerplate.
	KeyAppTagline    Key = "app.tagline"
	KeyAppDisclaimer Key = "app.disclaimer"

	// Root help headings and framing.
	KeyHelpUsage           Key = "help.usage"
	KeyHelpUsageLine       Key = "help.usage-line"
	KeyHelpCommandsTitle   Key = "help.commands-title"
	KeyHelpOptionsTitle    Key = "help.options-title"
	KeyHelpSubjectsTitle   Key = "help.subjects.title"
	KeyHelpCmdOptionsTitle Key = "help.command-options-title"
	KeyHelpExamplesTitle   Key = "help.examples-title"
	KeyHelpExamples        Key = "help.examples"
	KeyHelpSubcommandHint  Key = "help.subcommand-hint"
	KeyHelpGlobalHint      Key = "help.global-hint"
	KeyHelpMoreInfoTitle   Key = "help.more-info-title"
	KeyHelpCommandUsageFmt Key = "help.command-usage-fmt"
	KeyRepoLabel           Key = "version.repo-label"

	// Global options.
	KeyFlagLang    Key = "flag.lang"
	KeyFlagHelp    Key = "flag.help"
	KeyFlagVersion Key = "flag.version"
	KeyFlagNoColor Key = "flag.no-color"
	KeyFlagQuiet   Key = "flag.quiet"

	// Command summaries, shown in the command list.
	KeyCmdProxySummary Key = "cmd.proxy.summary"
	KeyCmdCrawlSummary Key = "cmd.crawl.summary"
	KeyCmdScanSummary  Key = "cmd.scan.summary"
	KeyCmdOobSummary   Key = "cmd.oob.summary"
	KeyCmdCaSummary    Key = "cmd.ca.summary"

	// Command usage lines.
	KeyUsageProxy Key = "usage.proxy"
	KeyUsageCrawl Key = "usage.crawl"
	KeyUsageScan  Key = "usage.scan"
	KeyUsageOob   Key = "usage.oob"
	KeyUsageCa    Key = "usage.ca"

	// proxy options.
	KeyFlagListen      Key = "proxy.flag.listen"
	KeyFlagUpstream    Key = "proxy.flag.upstream"
	KeyFlagScope       Key = "proxy.flag.scope"
	KeyFlagPassiveOnly Key = "proxy.flag.passive-only"

	// crawl options.
	KeyFlagURL      Key = "crawl.flag.url"
	KeyFlagDepth    Key = "crawl.flag.depth"
	KeyFlagEngine   Key = "crawl.flag.engine"
	KeyFlagMaxPages Key = "crawl.flag.max-pages"

	// scan options.
	KeyFlagScanURL    Key = "scan.flag.url"
	KeyFlagScanMethod Key = "scan.flag.method"
	KeyFlagScanData   Key = "scan.flag.data"
	KeyFlagScanHeader Key = "scan.flag.header"
	KeyFlagRaw        Key = "scan.flag.raw"
	KeyFlagChecks     Key = "scan.flag.checks"
	KeyFlagScanOutput Key = "scan.flag.output"
	// KeyFlagScanForms also submits the forms the scanned page declares.
	KeyFlagScanForms Key = "scan.flag.forms"

	// oob options.
	KeyFlagDNSAddr  Key = "oob.flag.dns"
	KeyFlagHTTPAddr Key = "oob.flag.http"
	// KeyFlagOOBToken is the optional shared secret: it correlates callbacks with the
	// requests that triggered them, and is also the authorization value an interactsh
	// server may ask for.
	KeyFlagOOBToken  Key = "oob.flag.token"
	KeyFlagOOBDomain Key = "oob.flag.domain"
	// KeyFlagOOBInteractsh names a deployment that collects interactions elsewhere.
	KeyFlagOOBInteractsh Key = "oob.flag.interactsh"

	KeyFlagJWTSecret Key = "flag.jwt-secret"
	KeyMsgJWTSecrets Key = "msg.jwt-secrets"

	KeyCmdLocalJWTTitle          Key = "cmd.local.jwt"
	KeyCmdLocalHashTitle         Key = "cmd.local.hash"
	KeyUsageLocalJWT             Key = "usage.local.jwt"
	KeyUsageLocalHash            Key = "usage.local.hash"
	KeyFlagLocalSecret           Key = "local.flag.secret"
	KeyFlagLocalForge            Key = "local.flag.forge"
	KeyFlagLocalClaim            Key = "local.flag.claim"
	KeyErrLocalNoHash            Key = "local.err.no-hash"
	KeyErrLocalForgeNeedsSecret  Key = "local.err.forge-needs-secret"
	KeyErrLocalForgeNotSymmetric Key = "local.err.forge-not-symmetric"
	KeyErrLocalBadClaim          Key = "local.err.bad-claim"
	KeyMsgLocalSubjects          Key = "local.msg.subjects"
	KeyMsgLocalHashUnknown       Key = "local.msg.hash-unknown"
	KeyMsgLocalHashIdentified    Key = "local.msg.hash-identified"
	KeyMsgLocalHashNotCrackable  Key = "local.msg.hash-not-crackable"
	KeyMsgLocalHashTrying        Key = "local.msg.hash-trying"
	KeyMsgLocalHashNoPassword    Key = "local.msg.hash-no-password"
	KeyMsgLocalHashFound         Key = "local.msg.hash-found"

	// local (offline) options.
	KeyCmdLocalSummary            Key = "cmd.local.summary"
	KeyUsageLocal                 Key = "usage.local"
	KeyFlagLocalWordlist          Key = "local.flag.wordlist"
	KeyErrLocalNoSubject          Key = "local.err.no-subject"
	KeyErrLocalUnknownSubject     Key = "local.err.unknown-subject"
	KeyErrLocalNoToken            Key = "local.err.no-token"
	KeyErrLocalBadToken           Key = "local.err.bad-token"
	KeyErrLocalWordlist           Key = "local.err.wordlist"
	KeyMsgLocalHeader             Key = "local.msg.header"
	KeyMsgLocalClaims             Key = "local.msg.claims"
	KeyMsgLocalField              Key = "local.msg.field"
	KeyMsgLocalNoAlgorithm        Key = "local.msg.no-algorithm"
	KeyMsgLocalAlgorithm          Key = "local.msg.algorithm"
	KeyMsgLocalUnsigned           Key = "local.msg.unsigned"
	KeyMsgLocalExpired            Key = "local.msg.expired"
	KeyMsgLocalValidUntil         Key = "local.msg.valid-until"
	KeyMsgLocalNotSymmetric       Key = "local.msg.not-symmetric"
	KeyMsgLocalTrying             Key = "local.msg.trying"
	KeyMsgLocalNoSecret           Key = "local.msg.no-secret"
	KeyMsgLocalSecretFound        Key = "local.msg.secret-found"
	KeyMsgLocalSecretFromFile     Key = "local.msg.secret-from-file"
	KeyMsgLocalSecretFromDefaults Key = "local.msg.secret-from-defaults"
	KeyMsgLocalSecretDerived      Key = "local.msg.secret-derived"
	KeyMsgLocalSigned             Key = "local.msg.signed"

	// ca options.
	KeyFlagOutDir Key = "ca.flag.out"
	KeyFlagForce  Key = "ca.flag.force"

	// Errors and status messages.
	KeyErrUnknownCommand Key = "err.unknown-command"
	KeyErrUnknownFlag    Key = "err.unknown-flag"
	KeyErrFlagNeedsValue Key = "err.flag-needs-value"
	KeyErrInvalidValue   Key = "err.invalid-value"
	KeyErrBadLang        Key = "err.bad-lang"
	KeyErrNeedTarget     Key = "err.need-target"
	KeyErrURLRequired    Key = "err.url-required"
	KeyMsgNotImplemented Key = "msg.not-implemented-planned"
	KeyMsgPlannedFor     Key = "msg.planned-for"

	// Response-difference reasons: the detail template for each reason code.
	KeyDiffReasonStatus     Key = "diff.reason.status"
	KeyDiffReasonRedirect   Key = "diff.reason.redirect"
	KeyDiffReasonTitle      Key = "diff.reason.title"
	KeyDiffReasonLength     Key = "diff.reason.length"
	KeyDiffReasonBinaryLen  Key = "diff.reason.binary-length"
	KeyDiffReasonContent    Key = "diff.reason.content"
	KeyDiffReasonKeyword    Key = "diff.reason.keyword"
	KeyDiffReasonEmpty      Key = "diff.reason.empty"
	KeyDiffReasonType       Key = "diff.reason.type"
	KeyDiffReasonError      Key = "diff.reason.error"
	KeyDiffReasonBaseError  Key = "diff.reason.baseline-error"
	KeyDiffReasonEcho       Key = "diff.reason.echo"
	KeyDiffReasonNoBaseline Key = "diff.reason.no-baseline"

	// Response-difference reasons: the short caption for each reason code.
	KeyDiffCodeStatus     Key = "diff.code.status"
	KeyDiffCodeRedirect   Key = "diff.code.redirect"
	KeyDiffCodeTitle      Key = "diff.code.title"
	KeyDiffCodeLength     Key = "diff.code.length"
	KeyDiffCodeContent    Key = "diff.code.content"
	KeyDiffCodeKeyword    Key = "diff.code.keyword"
	KeyDiffCodeEmpty      Key = "diff.code.empty"
	KeyDiffCodeType       Key = "diff.code.type"
	KeyDiffCodeError      Key = "diff.code.error"
	KeyDiffCodeEcho       Key = "diff.code.echo"
	KeyDiffCodeNoBaseline Key = "diff.code.no-baseline"

	// Miscellaneous diff helpers.
	KeyDiffNone       Key = "diff.none"
	KeyDiffEmptyValue Key = "diff.empty-value"
	KeyDiffElided     Key = "diff.elided"

	// Passive check: missing security headers.
	KeyCheckSecHeadersTitle Key = "check.passive-security-headers.title"
	KeyCheckSecHeadersDesc  Key = "check.passive-security-headers.description"
	KeyCheckSecHeadersFix   Key = "check.passive-security-headers.remediation"

	// Passive check: cookie flags.
	KeyCheckCookieFlagsTitle Key = "check.passive-cookie-flags.title"
	KeyCheckCookieFlagsDesc  Key = "check.passive-cookie-flags.description"
	KeyCheckCookieFlagsFix   Key = "check.passive-cookie-flags.remediation"

	// Passive check: permissive CORS.
	KeyCheckCORSTitle Key = "check.passive-cors.title"
	KeyCheckCORSDesc  Key = "check.passive-cors.description"
	KeyCheckCORSFix   Key = "check.passive-cors.remediation"

	// Passive check: information disclosure through headers.
	KeyCheckInfoDisclosureTitle Key = "check.passive-info-disclosure.title"
	KeyCheckInfoDisclosureDesc  Key = "check.passive-info-disclosure.description"
	KeyCheckInfoDisclosureFix   Key = "check.passive-info-disclosure.remediation"

	// Passive check: mixed content on an HTTPS page.
	KeyCheckMixedContentTitle Key = "check.passive-mixed-content.title"
	KeyCheckMixedContentDesc  Key = "check.passive-mixed-content.description"
	KeyCheckMixedContentFix   Key = "check.passive-mixed-content.remediation"

	// Passive check: missing cache control on sensitive responses.
	KeyCheckCacheTitle Key = "check.passive-cache-control.title"
	KeyCheckCacheDesc  Key = "check.passive-cache-control.description"
	KeyCheckCacheFix   Key = "check.passive-cache-control.remediation"

	// Passive check: directory listing.
	KeyCheckDirListingTitle Key = "check.passive-directory-listing.title"
	KeyCheckDirListingDesc  Key = "check.passive-directory-listing.description"
	KeyCheckDirListingFix   Key = "check.passive-directory-listing.remediation"

	// Passive check: third-party assets loaded without subresource integrity.
	KeyCheckSRITitle Key = "check.passive-sri.title"
	KeyCheckSRIDesc  Key = "check.passive-sri.description"
	KeyCheckSRIFix   Key = "check.passive-sri.remediation"

	// Passive check: error messages and stack traces in a response body.
	KeyCheckErrorDisclosureTitle Key = "check.passive-error-disclosure.title"
	KeyCheckErrorDisclosureDesc  Key = "check.passive-error-disclosure.description"
	KeyCheckErrorDisclosureFix   Key = "check.passive-error-disclosure.remediation"

	// Passive check: internal addresses, file paths and mailboxes in a response body.
	KeyCheckContentDisclosureTitle Key = "check.passive-content-disclosure.title"
	KeyCheckContentDisclosureDesc  Key = "check.passive-content-disclosure.description"
	KeyCheckContentDisclosureFix   Key = "check.passive-content-disclosure.remediation"

	// Passive check: a private key served in a response body.
	KeyCheckPrivateKeyTitle Key = "check.passive-private-key.title"
	KeyCheckPrivateKeyDesc  Key = "check.passive-private-key.description"
	KeyCheckPrivateKeyFix   Key = "check.passive-private-key.remediation"

	// Passive check: a password field served over plain HTTP.
	KeyCheckInsecureTransportTitle Key = "check.passive-insecure-transport.title"
	KeyCheckInsecureTransportDesc  Key = "check.passive-insecure-transport.description"
	KeyCheckInsecureTransportFix   Key = "check.passive-insecure-transport.remediation"

	// Passive check: a front-end library at a version with a published vulnerability.
	KeyCheckLibraryTitle Key = "check.passive-vulnerable-library.title"
	KeyCheckLibraryDesc  Key = "check.passive-vulnerable-library.description"
	KeyCheckLibraryFix   Key = "check.passive-vulnerable-library.remediation"

	// Active check: error-based SQL injection.
	KeyCheckSQLiErrorTitle Key = "check.sqli-error.title"
	KeyCheckSQLiErrorDesc  Key = "check.sqli-error.description"
	KeyCheckSQLiErrorFix   Key = "check.sqli-error.remediation"

	// Active check: boolean-based SQL injection.
	KeyCheckSQLiBoolTitle Key = "check.sqli-boolean.title"
	KeyCheckSQLiBoolDesc  Key = "check.sqli-boolean.description"
	KeyCheckSQLiBoolFix   Key = "check.sqli-boolean.remediation"

	// Active check: time-based SQL injection.
	KeyCheckSQLiTimeTitle Key = "check.sqli-time.title"
	KeyCheckSQLiTimeDesc  Key = "check.sqli-time.description"
	KeyCheckSQLiTimeFix   Key = "check.sqli-time.remediation"

	// Active check: reflected cross-site scripting.
	KeyCheckXSSTitle Key = "check.xss-reflected.title"
	KeyCheckXSSDesc  Key = "check.xss-reflected.description"
	KeyCheckXSSFix   Key = "check.xss-reflected.remediation"

	// Active check: path traversal and local file inclusion.
	KeyCheckPathTraversalTitle Key = "check.path-traversal.title"
	KeyCheckPathTraversalDesc  Key = "check.path-traversal.description"
	KeyCheckPathTraversalFix   Key = "check.path-traversal.remediation"

	// Active check: server-side template injection.
	KeyCheckSSTITitle Key = "check.ssti.title"
	KeyCheckSSTIDesc  Key = "check.ssti.description"
	KeyCheckSSTIFix   Key = "check.ssti.remediation"

	// Active check: open redirect.
	KeyCheckRedirectTitle Key = "check.open-redirect.title"
	KeyCheckRedirectDesc  Key = "check.open-redirect.description"
	KeyCheckRedirectFix   Key = "check.open-redirect.remediation"

	// Active check: CRLF and response header injection.
	KeyCheckCRLFTitle Key = "check.crlf-injection.title"
	KeyCheckCRLFDesc  Key = "check.crlf-injection.description"
	KeyCheckCRLFFix   Key = "check.crlf-injection.remediation"

	// Active check: NoSQL injection.
	KeyCheckNoSQLTitle Key = "check.nosqli.title"
	KeyCheckNoSQLDesc  Key = "check.nosqli.description"
	KeyCheckNoSQLFix   Key = "check.nosqli.remediation"

	// Active check: server-side request forgery.
	KeyCheckSSRFTitle Key = "check.ssrf.title"
	KeyCheckSSRFDesc  Key = "check.ssrf.description"
	KeyCheckSSRFFix   Key = "check.ssrf.remediation"

	// Active check: insecure direct object reference.
	KeyCheckIDORTitle Key = "check.idor.title"
	KeyCheckIDORDesc  Key = "check.idor.description"
	KeyCheckIDORFix   Key = "check.idor.remediation"

	// Active check: a refusal that does not survive a change of method or path spelling.
	KeyCheckAccessVariantsTitle Key = "check.access-control-variants.title"
	KeyCheckAccessVariantsDesc  Key = "check.access-control-variants.description"
	KeyCheckAccessVariantsFix   Key = "check.access-control-variants.remediation"

	// Active check: a page-size parameter that does not bound the response.
	KeyCheckPaginationTitle Key = "check.pagination-bypass.title"
	KeyCheckPaginationDesc  Key = "check.pagination-bypass.description"
	KeyCheckPaginationFix   Key = "check.pagination-bypass.remediation"

	// Active check: a value refused as a scalar and accepted once it is wrapped.
	KeyCheckTypeBypassTitle Key = "check.parameter-type-bypass.title"
	KeyCheckTypeBypassDesc  Key = "check.parameter-type-bypass.description"
	KeyCheckTypeBypassFix   Key = "check.parameter-type-bypass.remediation"

	// Active check: a value the page's own script turns into running markup.
	KeyCheckDOMXSSTitle Key = "check.dom-xss.title"
	KeyCheckDOMXSSDesc  Key = "check.dom-xss.description"
	KeyCheckDOMXSSFix   Key = "check.dom-xss.remediation"
	// Prototype pollution: a query string that reaches an object merge.
	// Client-side template injection: a URL value that reaches a template compiler.
	// Content-Security-Policy that is present but ineffective.
	// Path override through a proxy header.
	// Spoofed client address against a restricted endpoint.
	// Write methods stored under the request's own path.
	// A CORS policy that names the origin it was asked with.
	// Files a web server serves that were never meant to be served.
	// An endpoint that wraps its response in a caller-supplied callback name.
	// A guard attached to one Content-Type.
	// A guard that trusts the Referer header.
	// A WebSocket handshake that completes for any origin.
	KeyCheckWebSocketTitle          Key = "check.websocket-origin.title"
	KeyCheckWebSocketDesc           Key = "check.websocket-origin.description"
	KeyCheckWebSocketFix            Key = "check.websocket-origin.remediation"
	KeyCheckRefererBypassTitle      Key = "check.referer-bypass.title"
	KeyCheckRefererBypassDesc       Key = "check.referer-bypass.description"
	KeyCheckRefererBypassFix        Key = "check.referer-bypass.remediation"
	KeyCheckContentTypeBypassTitle  Key = "check.content-type-bypass.title"
	KeyCheckContentTypeBypassDesc   Key = "check.content-type-bypass.description"
	KeyCheckContentTypeBypassFix    Key = "check.content-type-bypass.remediation"
	KeyCheckJSONPTitle              Key = "check.jsonp.title"
	KeyCheckJSONPDesc               Key = "check.jsonp.description"
	KeyCheckJSONPFix                Key = "check.jsonp.remediation"
	KeyCheckExposedPathTitle        Key = "check.exposed-path.title"
	KeyCheckExposedPathDesc         Key = "check.exposed-path.description"
	KeyCheckExposedPathFix          Key = "check.exposed-path.remediation"
	KeyCheckCORSOriginTitle         Key = "check.cors-origin.title"
	KeyCheckCORSOriginDesc          Key = "check.cors-origin.description"
	KeyCheckCORSOriginFix           Key = "check.cors-origin.remediation"
	KeyCheckHTTPPutTitle            Key = "check.http-put.title"
	KeyCheckHTTPPutDesc             Key = "check.http-put.description"
	KeyCheckHTTPPutFix              Key = "check.http-put.remediation"
	KeyCheckIPSpoofTitle            Key = "check.ip-spoof.title"
	KeyCheckIPSpoofDesc             Key = "check.ip-spoof.description"
	KeyCheckIPSpoofFix              Key = "check.ip-spoof.remediation"
	KeyCheckPathOverrideTitle       Key = "check.path-override.title"
	KeyCheckPathOverrideDesc        Key = "check.path-override.description"
	KeyCheckPathOverrideFix         Key = "check.path-override.remediation"
	KeyCheckCSPTitle                Key = "check.passive-csp.title"
	KeyCheckCSPDesc                 Key = "check.passive-csp.description"
	KeyCheckCSPFix                  Key = "check.passive-csp.remediation"
	KeyCheckCSTITitle               Key = "check.client-template-injection.title"
	KeyCheckCSTIDesc                Key = "check.client-template-injection.description"
	KeyCheckCSTIFix                 Key = "check.client-template-injection.remediation"
	KeyCheckPrototypePollutionTitle Key = "check.prototype-pollution.title"
	KeyCheckPrototypePollutionDesc  Key = "check.prototype-pollution.description"
	KeyCheckPrototypePollutionFix   Key = "check.prototype-pollution.remediation"

	// Active check: a value reaching an LDAP filter.
	KeyCheckLDAPTitle Key = "check.ldap-injection.title"
	KeyCheckLDAPDesc  Key = "check.ldap-injection.description"
	KeyCheckLDAPFix   Key = "check.ldap-injection.remediation"

	// Active check: a value reaching an XPath expression.
	KeyCheckXPathTitle Key = "check.xpath-injection.title"
	KeyCheckXPathDesc  Key = "check.xpath-injection.description"
	KeyCheckXPathFix   Key = "check.xpath-injection.remediation"

	// Active check: a value reaching an OData query.
	KeyCheckODataTitle Key = "check.odata-injection.title"
	KeyCheckODataDesc  Key = "check.odata-injection.description"
	KeyCheckODataFix   Key = "check.odata-injection.remediation"

	// Active check: a GraphQL endpoint answering schema queries.
	KeyCheckGraphQLTitle Key = "check.graphql-introspection.title"
	KeyCheckGraphQLDesc  Key = "check.graphql-introspection.description"
	KeyCheckGraphQLFix   Key = "check.graphql-introspection.remediation"

	// Active check: a cached response poisoned through an unkeyed header.
	KeyCheckCachePoisonTitle Key = "check.cache-poisoning.title"
	KeyCheckCachePoisonDesc  Key = "check.cache-poisoning.description"
	KeyCheckCachePoisonFix   Key = "check.cache-poisoning.remediation"

	// Active check: command injection.
	KeyCheckCMDiTitle Key = "check.command-injection.title"
	KeyCheckCMDiDesc  Key = "check.command-injection.description"
	KeyCheckCMDiFix   Key = "check.command-injection.remediation"

	// Active check: XML external entity injection.
	KeyCheckXXETitle Key = "check.xxe.title"
	KeyCheckXXEDesc  Key = "check.xxe.description"
	KeyCheckXXEFix   Key = "check.xxe.remediation"

	// Active check: JSON Web Token weaknesses.
	KeyEvidenceJWTWeakSecretSameKey  Key = "evidence.jwt.weak-secret.same-key"
	KeyEvidenceJWTWeakSecretReSigned Key = "evidence.jwt.weak-secret.re-signed"
	KeyCheckJWTKidTitle              Key = "check.jwt.kid.title"
	KeyCheckJWTKidDesc               Key = "check.jwt.kid.desc"
	KeyCheckJWTConfusionTitle        Key = "check.jwt.confusion.title"
	KeyCheckJWTConfusionDesc         Key = "check.jwt.confusion.desc"
	KeyCheckJWTKeyURLTitle           Key = "check.jwt.keyurl.title"
	KeyCheckJWTKeyURLDesc            Key = "check.jwt.keyurl.desc"
	KeyEvidencePoisonedURL           Key = "evidence.poisoned-url"
	KeyEvidenceRenderedText          Key = "evidence.rendered-text"
	KeyEvidencePrototypePollution    Key = "evidence.prototype-pollution"
	KeyCheckJWTWeakSecretTitle       Key = "check.jwt.weak-secret.title"
	KeyCheckJWTWeakSecretDesc        Key = "check.jwt.weak-secret.desc"
	KeyCheckJWTTitle                 Key = "check.jwt.title"
	KeyCheckJWTDesc                  Key = "check.jwt.description"
	KeyCheckJWTFix                   Key = "check.jwt.remediation"

	// Active check: missing CSRF protection.
	KeyCheckCSRFTitle Key = "check.csrf.title"
	KeyCheckCSRFDesc  Key = "check.csrf.description"
	KeyCheckCSRFFix   Key = "check.csrf.remediation"

	// Active check: Host header injection.
	KeyCheckHostHeaderTitle Key = "check.host-header.title"
	KeyCheckHostHeaderDesc  Key = "check.host-header.description"
	KeyCheckHostHeaderFix   Key = "check.host-header.remediation"

	// Active check: unsafe file upload handling.
	KeyCheckUploadTitle Key = "check.upload.title"
	KeyCheckUploadDesc  Key = "check.upload.description"
	KeyCheckUploadFix   Key = "check.upload.remediation"

	// Active check: stored cross-site scripting.
	KeyCheckXSSStoredTitle Key = "check.xss-stored.title"
	KeyCheckXSSStoredDesc  Key = "check.xss-stored.description"
	KeyCheckXSSStoredFix   Key = "check.xss-stored.remediation"

	// Active check: SQL injection into a sorting or limiting clause.
	KeyCheckSQLiOrderByTitle Key = "check.sqli-order-by.title"
	KeyCheckSQLiOrderByDesc  Key = "check.sqli-order-by.description"
	KeyCheckSQLiOrderByFix   Key = "check.sqli-order-by.remediation"

	// Active check: UNION-based SQL injection.
	KeyCheckSQLiUnionTitle Key = "check.sqli-union.title"
	KeyCheckSQLiUnionDesc  Key = "check.sqli-union.description"
	KeyCheckSQLiUnionFix   Key = "check.sqli-union.remediation"

	// Passive check: a credential sent over a cleartext connection.
	KeyCheckCleartextPasswordTitle Key = "check.cleartext-password.title"
	KeyCheckCleartextPasswordDesc  Key = "check.cleartext-password.description"
	KeyCheckCleartextPasswordFix   Key = "check.cleartext-password.remediation"

	// Active check: HTTP method override.
	KeyCheckMethodOverrideTitle Key = "check.method-override.title"
	KeyCheckMethodOverrideDesc  Key = "check.method-override.description"
	KeyCheckMethodOverrideFix   Key = "check.method-override.remediation"

	// Active check: HTTP request smuggling (opt-in).
	KeyCheckSmugglingTitle Key = "check.smuggling.title"
	KeyCheckSmugglingDesc  Key = "check.smuggling.description"
	KeyCheckSmugglingFix   Key = "check.smuggling.remediation"

	// Active check: stored (second-order) injection.
	KeyCheckSecondOrderTitle Key = "check.second-order-injection.title"
	KeyCheckSecondOrderDesc  Key = "check.second-order-injection.description"
	KeyCheckSecondOrderFix   Key = "check.second-order-injection.remediation"

	// Active check: unsafe deserialisation entry point.
	KeyCheckDeserialTitle Key = "check.deserialization.title"
	KeyCheckDeserialDesc  Key = "check.deserialization.description"
	KeyCheckDeserialFix   Key = "check.deserialization.remediation"

	// Evidence sentences shared by several active checks.
	KeyEvidenceBoolean    Key = "evidence.boolean-comparison"
	KeyEvidenceTiming     Key = "evidence.timing"
	KeyEvidenceReflect    Key = "evidence.reflection"
	KeyEvidenceOOB        Key = "evidence.out-of-band"
	KeyEvidenceIDOR       Key = "evidence.idor-comparison"
	KeyEvidenceVariant    Key = "evidence.payload-variant"
	KeyEvidenceAccessRule Key = "evidence.access-variant"
	KeyEvidencePagination Key = "evidence.pagination"
	KeyEvidenceTypeBypass Key = "evidence.type-bypass"
	KeyEvidenceParser     Key = "evidence.parser-complaint"
	KeyEvidenceCache      Key = "evidence.cache-poison"
	KeyEvidenceTimingStat Key = "evidence.timing-statistics"
	KeyEvidenceHPP        Key = "evidence.hpp"
	KeyEvidenceWAF        Key = "evidence.waf-detected"
	KeyEvidenceCSRF       Key = "evidence.csrf-token-forged"

	// Report headings and field labels.
	KeyReportTitle       Key = "report.title"
	KeyReportSubtitle    Key = "report.subtitle"
	KeyReportSummary     Key = "report.summary"
	KeyReportTarget      Key = "report.target"
	KeyReportStarted     Key = "report.started"
	KeyReportFinished    Key = "report.finished"
	KeyReportDuration    Key = "report.duration"
	KeyReportHosts       Key = "report.hosts"
	KeyReportEndpoints   Key = "report.endpoints"
	KeyReportRequests    Key = "report.requests"
	KeyReportFindings    Key = "report.findings"
	KeyReportNoFindings  Key = "report.no-findings"
	KeyReportGeneratedBy Key = "report.generated-by"
	KeyReportDisclaimer  Key = "report.disclaimer"
	KeyReportFilter      Key = "report.filter-placeholder"
	KeyReportExpandAll   Key = "report.expand-all"
	KeyReportCollapseAll Key = "report.collapse-all"

	// Report field labels.
	KeyReportFieldCheck       Key = "report.field.check"
	KeyReportFieldSeverity    Key = "report.field.severity"
	KeyReportFieldConfidence  Key = "report.field.confidence"
	KeyReportFieldURL         Key = "report.field.url"
	KeyReportFieldParam       Key = "report.field.parameter"
	KeyReportFieldPayload     Key = "report.field.payload"
	KeyReportFieldDescription Key = "report.field.description"
	KeyReportFieldRemediation Key = "report.field.remediation"
	KeyReportFieldReferences  Key = "report.field.references"
	KeyReportFieldRequest     Key = "report.field.request"
	KeyReportFieldResponse    Key = "report.field.response"
	KeyReportFieldBaseline    Key = "report.field.baseline"
	KeyReportFieldEvidence    Key = "report.field.evidence"
	KeyReportFieldDiff        Key = "report.field.diff"
	KeyReportCurl             Key = "report.curl"
	KeyReportCWE              Key = "report.cwe"

	// What stood between the scan and the target. A refusal and a clean result look the
	// same from the outside, so both are reported as facts a reader can weigh.
	KeyReportBoundaryTitle    Key = "report.boundary-title"
	KeyReportUnanswered       Key = "report.unanswered"
	KeyReportProtectedTitle   Key = "report.protected-title"
	KeyReportProtectedNothing Key = "report.protected-nothing"

	// Severity names.
	KeySeverityCritical Key = "severity.critical"
	KeySeverityHigh     Key = "severity.high"
	KeySeverityMedium   Key = "severity.medium"
	KeySeverityLow      Key = "severity.low"
	KeySeverityInfo     Key = "severity.info"
	KeySeverityUnknown  Key = "severity.unknown"

	// Confidence names.
	KeyConfidenceCertain   Key = "confidence.certain"
	KeyConfidenceFirm      Key = "confidence.firm"
	KeyConfidenceTentative Key = "confidence.tentative"

	// Write-out messages.
	KeyMsgReportWritten Key = "msg.report-written"

	// Options shared by several commands.
	KeyFlagTimeout          Key = "flag.timeout"
	KeyFlagRate             Key = "flag.rate"
	KeyFlagThreads          Key = "flag.threads"
	KeyFlagInsecure         Key = "flag.insecure"
	KeyFlagUserAgent        Key = "flag.user-agent"
	KeyFlagProxy            Key = "flag.proxy"
	KeyFlagSensitivity      Key = "flag.sensitivity"
	KeyFlagSkipParams       Key = "flag.skip-params"
	KeyFlagListChecks       Key = "flag.list-checks"
	KeyFlagVerbose          Key = "flag.verbose"
	KeyFlagTemplates        Key = "flag.templates"
	KeyFlagSession          Key = "flag.session"
	KeyFlagNoWAF            Key = "flag.no-waf"
	KeyFlagNoAssumeWAF      Key = "flag.no-assume-waf"
	KeyFlagNoDiscovery      Key = "flag.no-discovery"
	KeyFlagAllowStateChange Key = "flag.allow-state-change"
	KeyFlagAPIDoc           Key = "flag.api-doc"
	KeyFlagUnsafeChecks     Key = "flag.unsafe-checks"
	KeyFlagCookie           Key = "flag.cookie"
	KeyFlagHeader           Key = "flag.header"
	KeyFlagBasicAuth        Key = "flag.basic-auth"
	KeyFlagRandomUA         Key = "flag.random-ua"
	KeyMsgUnsafeChecks      Key = "msg.unsafe-checks"
	KeyFlagExportCA         Key = "flag.export-ca"
	KeyFlagNoNormalize      Key = "flag.no-normalize"

	// Runtime status messages.
	KeyMsgProxyListening Key = "msg.proxy-listening"
	KeyMsgProxyCAHint    Key = "msg.proxy-ca-hint"
	KeyMsgProxyStopped   Key = "msg.proxy-stopped"
	KeyMsgCAGenerated    Key = "msg.ca-generated"
	KeyMsgCALoaded       Key = "msg.ca-loaded"
	KeyMsgScanStarted    Key = "msg.scan-started"
	KeyMsgScanFinished   Key = "msg.scan-finished"
	KeyMsgNoFindings     Key = "msg.no-findings"
	KeyMsgOOBListening   Key = "msg.oob-listening"
	// KeyMsgProxyCredentialsIgnored explains why --cookie/--header do nothing under proxy.
	KeyMsgProxyCredentialsIgnored Key = "msg.proxy-credentials-ignored"
	KeyMsgOOBInteractsh           Key = "msg.oob-interactsh"
	KeyMsgUnknownChecks           Key = "msg.unknown-checks"
	KeyMsgChecksLoaded            Key = "msg.checks-loaded"
	KeyMsgRequestError            Key = "msg.request-error"
	KeyMsgUnanswered              Key = "msg.unanswered"
	KeyMsgProtectedHost           Key = "msg.protected-host"
	KeyMsgProtectedWithVendor     Key = "msg.protected-with-vendor"
	KeyMsgChecksOptIn             Key = "msg.checks-opt-in"
	KeyMsgProbing                 Key = "msg.probing"
	KeyMsgSelfDescribed           Key = "msg.self-described"
	KeyMsgTemplateLoaded          Key = "msg.templates-loaded"
	KeyMsgChecksListed            Key = "msg.checks-listed"
	KeyMsgOOBCallbackExample      Key = "msg.oob-callback-example"
	KeyMsgCAExported              Key = "msg.ca-exported"
	KeyMsgCrawlStats              Key = "msg.crawl-stats"
	KeyMsgTemplateUnsupported     Key = "msg.template-unsupported"
	KeyMsgTemplateTruncated       Key = "msg.template-truncated"
	KeyMsgNoBrowser               Key = "msg.no-browser"
	KeyMsgSessionsLoaded          Key = "msg.sessions-loaded"
	KeyMsgIDORNeedsSessions       Key = "msg.idor-needs-sessions"

	// Errors raised while running.
	KeyErrBadSensitivity Key = "err.bad-sensitivity"
	KeyErrNoChecks       Key = "err.no-checks"
	KeyErrLoadCA         Key = "err.load-ca"
	KeyErrReadRaw        Key = "err.read-raw"
	KeyErrStartProxy     Key = "err.start-proxy"
)
