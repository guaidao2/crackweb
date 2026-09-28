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

	// oob options.
	KeyFlagDNSAddr   Key = "oob.flag.dns"
	KeyFlagHTTPAddr  Key = "oob.flag.http"
	KeyFlagOOBToken  Key = "oob.flag.token"
	KeyFlagOOBDomain Key = "oob.flag.domain"

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

	// Active check: command injection.
	KeyCheckCMDiTitle Key = "check.command-injection.title"
	KeyCheckCMDiDesc  Key = "check.command-injection.description"
	KeyCheckCMDiFix   Key = "check.command-injection.remediation"

	// Active check: XML external entity injection.
	KeyCheckXXETitle Key = "check.xxe.title"
	KeyCheckXXEDesc  Key = "check.xxe.description"
	KeyCheckXXEFix   Key = "check.xxe.remediation"

	// Active check: JSON Web Token weaknesses.
	KeyCheckJWTTitle Key = "check.jwt.title"
	KeyCheckJWTDesc  Key = "check.jwt.description"
	KeyCheckJWTFix   Key = "check.jwt.remediation"

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
	KeyEvidenceTimingStat Key = "evidence.timing-statistics"
	KeyEvidenceHPP        Key = "evidence.hpp"
	KeyEvidenceWAF        Key = "evidence.waf-detected"

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
	KeyFlagTimeout      Key = "flag.timeout"
	KeyFlagRate         Key = "flag.rate"
	KeyFlagThreads      Key = "flag.threads"
	KeyFlagInsecure     Key = "flag.insecure"
	KeyFlagUserAgent    Key = "flag.user-agent"
	KeyFlagProxy        Key = "flag.proxy"
	KeyFlagSensitivity  Key = "flag.sensitivity"
	KeyFlagSkipParams   Key = "flag.skip-params"
	KeyFlagListChecks   Key = "flag.list-checks"
	KeyFlagVerbose      Key = "flag.verbose"
	KeyFlagTemplates    Key = "flag.templates"
	KeyFlagSession      Key = "flag.session"
	KeyFlagNoWAF        Key = "flag.no-waf"
	KeyFlagUnsafeChecks Key = "flag.unsafe-checks"
	KeyMsgUnsafeChecks  Key = "msg.unsafe-checks"
	KeyFlagExportCA     Key = "flag.export-ca"
	KeyFlagNoNormalize  Key = "flag.no-normalize"

	// Runtime status messages.
	KeyMsgProxyListening      Key = "msg.proxy-listening"
	KeyMsgProxyCAHint         Key = "msg.proxy-ca-hint"
	KeyMsgProxyStopped        Key = "msg.proxy-stopped"
	KeyMsgCAGenerated         Key = "msg.ca-generated"
	KeyMsgCALoaded            Key = "msg.ca-loaded"
	KeyMsgScanStarted         Key = "msg.scan-started"
	KeyMsgScanFinished        Key = "msg.scan-finished"
	KeyMsgNoFindings          Key = "msg.no-findings"
	KeyMsgOOBListening        Key = "msg.oob-listening"
	KeyMsgUnknownChecks       Key = "msg.unknown-checks"
	KeyMsgChecksLoaded        Key = "msg.checks-loaded"
	KeyMsgRequestError        Key = "msg.request-error"
	KeyMsgTemplateLoaded      Key = "msg.templates-loaded"
	KeyMsgChecksListed        Key = "msg.checks-listed"
	KeyMsgOOBCallbackExample  Key = "msg.oob-callback-example"
	KeyMsgCAExported          Key = "msg.ca-exported"
	KeyMsgCrawlStats          Key = "msg.crawl-stats"
	KeyMsgTemplateUnsupported Key = "msg.template-unsupported"
	KeyMsgNoBrowser           Key = "msg.no-browser"
	KeyMsgSessionsLoaded      Key = "msg.sessions-loaded"
	KeyMsgIDORNeedsSessions   Key = "msg.idor-needs-sessions"

	// Errors raised while running.
	KeyErrBadSensitivity Key = "err.bad-sensitivity"
	KeyErrNoChecks       Key = "err.no-checks"
	KeyErrLoadCA         Key = "err.load-ca"
	KeyErrReadRaw        Key = "err.read-raw"
	KeyErrStartProxy     Key = "err.start-proxy"
)
