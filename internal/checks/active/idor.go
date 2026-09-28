package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// accessControl detects insecure direct object references — the horizontal
// privilege escalation where one signed-in user can read another user's data by
// changing an identifier the client controls.
//
// The hard part is not sending the request, it is knowing the answer means
// something. A response that changes when you change an id is normal: article
// 2 differs from article 1 on any blog. What is *not* normal is two different
// users being handed the same object. So the check compares three responses:
//
//	anonymous  → should be refused. If it succeeds, the object is public and
//	             there is nothing to report.
//	session A  → what user A sees for this object.
//	session B  → what user B sees for the same object.
//
// A finding is raised only when A and B receive the same content *and* an
// anonymous request does not. That combination means the object is protected,
// yet not scoped to its owner — which is exactly the bug.
//
// This is the same shape commercial scanners use, and it is why the check needs
// two sessions: without a second identity there is no way to distinguish
// "you can read your own record" from "you can read anyone's".
type accessControl struct{}

func (accessControl) ID() string                 { return "idor" }
func (accessControl) TitleKey() i18n.Key         { return i18n.KeyCheckIDORTitle }
func (accessControl) DescriptionKey() i18n.Key   { return i18n.KeyCheckIDORDesc }
func (accessControl) RemediationKey() i18n.Key   { return i18n.KeyCheckIDORFix }
func (accessControl) Severity() finding.Severity { return finding.SeverityHigh }
func (accessControl) Tags() []string {
	return []string{"active", "authorization", "idor", "owasp-top10"}
}
func (accessControl) Passive() bool { return false }

// Similarity thresholds. They are deliberately tight: a false "you have an
// access control bug" costs a team a day of investigation.
const (
	// idorSameContent is how alike two sessions' responses must be.
	idorSameContent = 0.97
	// idorAnonymousDiffers is how different the anonymous response must be, so
	// that a shared login wall is not mistaken for a leak.
	idorAnonymousDiffers = 0.90
)

func (accessControl) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Request == nil {
		return nil
	}
	// Two identities are the minimum for a meaningful comparison.
	if len(c.Sessions) < 2 {
		return nil
	}

	// Only identifiers are worth this much traffic: injecting a payload into a
	// search box says nothing about access control.
	if !looksLikeIdentifier(*t.Param) {
		return nil
	}

	anonymous, err := c.DoWithoutSession(ctx, t.Request)
	if err != nil || anonymous == nil {
		return nil
	}

	first, err := c.DoWithSession(ctx, t.Request, c.Sessions[0])
	if err != nil || first == nil {
		return nil
	}
	second, err := c.DoWithSession(ctx, t.Request, c.Sessions[1])
	if err != nil || second == nil {
		return nil
	}

	// The object has to be protected in the first place.
	if isSuccess(anonymous) {
		return nil
	}
	if !isSuccess(first) || !isSuccess(second) {
		return nil
	}

	firstFp := c.Fingerprint(first)
	secondFp := c.Fingerprint(second)
	anonFp := c.Fingerprint(anonymous)

	// Both identities must be looking at the same object...
	sameBetween := diff.CompareFingerprints(firstFp, secondFp).Score
	if sameBetween < idorSameContent {
		return nil
	}
	// ...and an anonymous caller must not be able to see it.
	anonSimilarity := diff.CompareFingerprints(anonFp, firstFp).Score
	if anonSimilarity >= idorAnonymousDiffers {
		return nil
	}

	f := checks.NewFinding(accessControl{}, t,
		i18n.KeyCheckIDORTitle, i18n.KeyCheckIDORDesc, i18n.KeyCheckIDORFix)
	f.Severity = finding.SeverityHigh
	// Firm rather than certain: the evidence is a comparison, and a target that
	// serves the same page to everyone behind a login wall would look similar.
	f.Confidence = finding.ConfidenceFirm
	f.CWE = "CWE-639"
	f.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
		"https://cwe.mitre.org/data/definitions/639.html",
	}
	f.Evidence.Request = t.Request.Raw()
	f.Evidence.Response = truncate(first.Raw(), 8192)
	f.Evidence.Baseline = truncate(anonymous.Raw(), 4096)
	f.Evidence.Matches = []string{c.Bundle.T(i18n.KeyEvidenceIDOR,
		formatSimilarity(sameBetween), formatSimilarity(anonSimilarity))}
	f.Evidence.Diff = c.Bundle.T(i18n.KeyEvidenceIDOR,
		formatSimilarity(sameBetween), formatSimilarity(anonSimilarity))
	return []*finding.Finding{f}
}

// isSuccess reports whether a response looks like the request was served rather
// than refused.
func isSuccess(resp *httpmsg.Response) bool {
	if resp == nil || resp.Status >= 400 {
		return false
	}
	// A 200 with an empty body is a redirect stub or a placeholder, not data.
	return len(resp.Body) > 0
}

// identifierNames are parameter names that address an object rather than
// describe a query. The check only fires on these, which keeps its traffic —
// and its false positives — down.
var identifierNames = []string{
	"id", "uid", "user", "userid", "user_id", "account", "account_id", "acct",
	"order", "orderid", "order_id", "invoice", "invoice_id", "doc", "document",
	"file", "fileid", "file_id", "item", "itemid", "item_id", "record",
	"customer", "customerid", "customer_id", "member", "member_id", "profile",
	"profile_id", "report", "report_id", "ticket", "ticket_id", "msg", "message_id",
	"key", "token", "ref", "reference", "num", "no", "number",
}

// looksLikeIdentifier reports whether a parameter addresses an object.
//
// A name from the list is enough on its own; so is a value shaped like an
// identifier (a plain number or a UUID), because plenty of applications call the
// parameter something idiosyncratic.
func looksLikeIdentifier(param httpmsg.Param) bool {
	name := strings.ToLower(strings.Trim(param.Name, "[]"))
	for _, candidate := range identifierNames {
		if name == candidate || strings.HasSuffix(name, "_"+candidate) ||
			strings.HasPrefix(name, candidate+"_") {
			return true
		}
	}
	return isNumeric(param.Value) || isUUID(param.Value)
}

// isNumeric reports whether a value is a plain integer.
func isNumeric(value string) bool {
	if value == "" || len(value) > 19 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// isUUID reports whether a value is a UUID.
func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// formatSimilarity renders a similarity score for display.
func formatSimilarity(v float64) string { return round3(v) }
