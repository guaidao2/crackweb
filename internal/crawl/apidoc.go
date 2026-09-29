package crawl

import (
	"context"
	"net/url"
	"regexp"

	"github.com/guaidao2/crackweb/internal/apidoc"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// An API description is the best input a scan can be handed: every path, every method, and
// the parameters of each one. What a crawler can reach by following links is a fraction of
// it — the rest are endpoints nothing links to, which is most of an API.
//
// Two things find one. The addresses a description is commonly published at are asked
// directly, and the ones a page or a script points at are followed. Waiting to stumble on
// one covers a small share of the targets that publish one at all, and the whole point of a
// description is that it is meant to be read.

// apiDocPaths are the addresses a description is commonly published at.
//
// The list is short on purpose. Each entry is a request to a host that may not have one, and
// a long list of guesses is how a scanner becomes a nuisance; these are the spellings the
// frameworks that publish a description actually use.
var apiDocPaths = []string{
	"/swagger.json",
	"/openapi.json",
	"/swagger/v1/swagger.json",
	"/v2/api-docs",
	"/v3/api-docs",
	"/api-docs",
	"/api/swagger.json",
	"/swagger-ui.html",
}

// apiDocRefRe finds a description a page or a script points at.
//
// The spelling is the signal: a file whose name says swagger, openapi or api-docs and ends
// in a data format. Swagger UI carries its own address this way — `url: "/swagger.json"` in
// the initialiser — which is why asking the common paths alone is not enough.
var apiDocRefRe = regexp.MustCompile(
	`(?i)["'` + "`" + `]([^"'` + "`" + `\s]*(?:swagger|openapi|api-docs)[^"'` + "`" + `\s]*\.(?:json|yaml|yml))["'` + "`" + `]`)

// seedAPIDocs returns the common description addresses for a seed, in scope.
func (c *Crawler) seedAPIDocs(seed *url.URL) []string {
	return c.seedWellKnown(seed, apiDocPaths)
}

// apiDocReferences returns the description addresses a document points at.
func apiDocReferences(body string, base *url.URL) []string {
	var out []string
	for _, match := range apiDocRefRe.FindAllStringSubmatch(body, 20) {
		if resolved := resolve(base, match[1]); resolved != "" {
			out = append(out, resolved)
		}
	}
	return out
}

// deliverDocument hands the operations a description lists to the scanner.
//
// The address each operation was written for is checked against the scope first: a
// description is free to name any host, and following it off the engagement would be
// exactly the mistake scope exists to prevent.
func (c *Crawler) deliverDocument(ctx context.Context, doc *apidoc.Document) int {
	delivered := 0
	for _, request := range doc.Requests {
		if _, ok := c.accept(request.URLString(), 0); !ok {
			continue
		}
		request.Origin = httpmsg.OriginCrawler
		c.deliver(ctx, request)
		delivered++
	}
	return delivered
}
