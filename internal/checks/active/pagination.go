package active

import (
	"context"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// paginationBypass reports a page-size parameter that does not bound what comes back.
//
// A parameter that selects how many records to return has to be enforced, not read as a
// suggestion. When the value falls outside the range the code was written for, an
// unbounded read is a common fallback — and one request can then carry the whole
// collection, which is how an endpoint meant to be paged becomes a bulk export.
//
// The comparison is what makes this worth reporting. A large response on its own means
// nothing: plenty of endpoints return everything whatever you ask for, and there is no
// defect in that. Asking for a single record first gives the size a baseline, so whatever
// came back beyond that one record came back because the limit was not honoured.
type paginationBypass struct{}

func (paginationBypass) ID() string                 { return "pagination-bypass" }
func (paginationBypass) TitleKey() i18n.Key         { return i18n.KeyCheckPaginationTitle }
func (paginationBypass) DescriptionKey() i18n.Key   { return i18n.KeyCheckPaginationDesc }
func (paginationBypass) RemediationKey() i18n.Key   { return i18n.KeyCheckPaginationFix }
func (paginationBypass) Severity() finding.Severity { return finding.SeverityMedium }
func (paginationBypass) Tags() []string {
	return []string{"active", "authorization", "pagination", "owasp-top10"}
}
func (paginationBypass) Passive() bool { return false }

// pageSizeNames are the parameter names that select a number of records. The check only
// fires on these: a numeric parameter that happens to be called something else is a
// different question, and guessing at it would cost traffic for nothing.
var pageSizeNames = []string{
	"limit", "size", "count", "num", "rows", "length", "max", "top", "take", "first",
	"per_page", "perpage", "page_size", "pagesize", "pagecount",
}

// pageSizeVariants are the values a bounded read is tested with. Each is a value the code
// was probably not written for: a negative count, zero, and one far past any real
// collection.
var pageSizeVariants = []string{"-1", "0", "999999999"}

// Where a response stops looking like the limit was honoured.
const (
	// paginationGrowth is how many times larger the response has to be.
	paginationGrowth = 3
	// paginationFloor is the absolute difference below which the growth is noise: a
	// bounded response and its variant are never byte-identical, and a handful of extra
	// bytes is not a collection.
	paginationFloor = 2048
)

func (paginationBypass) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t.Param == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	if !isPageSizeParam(*t.Param) {
		return nil
	}
	if t.Param.In != httpmsg.LocQuery && t.Param.In != httpmsg.LocBody {
		return nil
	}
	if t.Response.Status >= 400 || len(t.Response.Body) == 0 {
		return nil
	}

	// The baseline the comparison rests on: one record, asked for explicitly.
	boundedRequest, bounded, err := c.Inject(ctx, t, "1")
	if err != nil || bounded == nil || bounded.Status >= 400 {
		return nil
	}
	boundedSize := len(bounded.Body)

	for _, value := range pageSizeVariants {
		mutated, response, err := c.Inject(ctx, t, value)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		if !exceedsBounded(len(response.Body), boundedSize) {
			continue
		}

		f := checks.NewFinding(paginationBypass{}, t,
			i18n.KeyCheckPaginationTitle, i18n.KeyCheckPaginationDesc, i18n.KeyCheckPaginationFix)
		f.Severity = finding.SeverityMedium
		// Firm rather than certain: the response grew far past what was asked for, which
		// a limit-aware endpoint would not do, but what the extra bytes contain is not
		// something this check reads.
		f.Confidence = finding.ConfidenceFirm
		f.Payload = value
		f.CWE = "CWE-770"
		f.References = []string{
			"https://cwe.mitre.org/data/definitions/770.html",
			"https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Raw(), 8192)
		f.Evidence.Baseline = truncate(boundedRequest.Raw(), 4096)
		f.Evidence.Matches = []string{c.Bundle.T(i18n.KeyEvidencePagination,
			1, boundedSize, value, len(response.Body))}
		return []*finding.Finding{f}
	}
	return nil
}

// isPageSizeParam reports whether a parameter selects a number of records.
func isPageSizeParam(param httpmsg.Param) bool {
	name := strings.ToLower(strings.Trim(param.Name, "[]"))
	for _, candidate := range pageSizeNames {
		if name == candidate {
			return true
		}
	}
	return false
}

// exceedsBounded reports whether a response grew enough to say the limit was not honoured.
func exceedsBounded(got, bounded int) bool {
	if got < bounded*paginationGrowth {
		return false
	}
	return got-bounded >= paginationFloor
}
