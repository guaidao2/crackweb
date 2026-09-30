package crawl

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Page is what a crawled document yielded.
type Page struct {
	// Links are the URLs the page points at, resolved to absolute form.
	Links []string
	// Forms are the forms found on the page, ready to be submitted.
	Forms []Form
}

// Form is a discovered HTML form.
type Form struct {
	// Action is the raw action attribute, which may be relative or empty.
	Action string
	// Method is the form method, upper-cased.
	Method string
	// Enctype is the form's encoding, lower-cased. It decides how the body has to be
	// built, and getting it wrong means the submission never reaches the code under test.
	Enctype string
	// Fields are the form's inputs.
	Fields []Field
}

// Field is one form control.
type Field struct {
	Name  string
	Value string
	Type  string
}

// URL resolves a form's action against the page it was found on.
func (f Form) URL(base *url.URL) string {
	action := strings.TrimSpace(f.Action)
	if action == "" {
		if base == nil {
			return ""
		}
		return base.String()
	}
	if base == nil {
		if strings.HasPrefix(action, "http") {
			return action
		}
		return ""
	}
	ref, err := url.Parse(action)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// EncodeBody renders the form's fields as an application/x-www-form-urlencoded
// body, which serves equally well as a query string for a GET form.
func (f Form) EncodeBody() string {
	values := url.Values{}
	for _, field := range f.Fields {
		if field.Name == "" {
			continue
		}
		// A file cannot go into a urlencoded body; an upload form is sent as multipart.
		//
		// Everything else is sent, including the submit button and unchecked boxes. A form
		// the application never sees as submitted is not tested at all: `isset($_POST['submit'])`
		// is how a great many PHP handlers decide whether to run, and an ASP.NET page wants its
		// `__EVENTTARGET` alongside. Omitting the control the page uses to recognise its own
		// submission turns the request into one the application ignores — which looks exactly
		// like a target with no vulnerabilities.
		if strings.EqualFold(field.Type, "file") {
			continue
		}
		values.Add(field.Name, field.Value)
	}
	return values.Encode()
}

// IsMultipart reports whether the form has to be submitted as multipart/form-data. A form
// that declares it does, and a form carrying a file input does whether it declares it or
// not — a server expecting an upload rejects a urlencoded body before it looks at
// anything in it, so submitting one that way tests nothing.
func (f Form) IsMultipart() bool {
	if strings.Contains(f.Enctype, "multipart/form-data") {
		return true
	}
	for _, field := range f.Fields {
		if strings.EqualFold(field.Type, "file") {
			return true
		}
	}
	return false
}

// EncodeMultipart renders the form as a multipart/form-data body and returns it with the
// Content-Type that goes with it.
//
// A file input is filled with a small placeholder. The crawler is not uploading anything
// real, and a field left empty is the one thing an upload endpoint refuses outright — an
// empty file part would hide the whole form behind a validation error, which is exactly
// the outcome that makes an upload endpoint look untestable.
func (f Form) EncodeMultipart() ([]byte, string) {
	boundary := "crackweb-" + randomBoundary()
	var body strings.Builder

	for _, field := range f.Fields {
		if field.Name == "" {
			continue
		}
		// Every control the form declares is sent, submit buttons and unchecked boxes
		// included, for the reason EncodeBody gives: the application may decide whether the
		// form was submitted at all from one of them.
		body.WriteString("--" + boundary + "\r\n")
		if strings.EqualFold(field.Type, "file") {
			body.WriteString("Content-Disposition: form-data; name=\"" + field.Name +
				"\"; filename=\"" + placeholderUploadName + "\"\r\n")
			// An upload endpoint that checks the media type is checking this header, and
			// it comes from the sender — so sending a picture's type is what gets the
			// submission as far as the code that handles it. `application/octet-stream`
			// is refused by anything that requires an image before it looks further.
			body.WriteString("Content-Type: image/png\r\n\r\n")
			body.WriteString(placeholderUploadBody)
			body.WriteString("\r\n")
			continue
		}
		body.WriteString("Content-Disposition: form-data; name=\"" + field.Name + "\"\r\n\r\n")
		body.WriteString(field.Value)
		body.WriteString("\r\n")
	}
	body.WriteString("--" + boundary + "--\r\n")

	return []byte(body.String()), "multipart/form-data; boundary=" + boundary
}

// The placeholder a crawled upload form is submitted with.
const (
	placeholderUploadName = "crackweb-upload.txt"
	placeholderUploadBody = "crackweb upload"
)

// randomBoundary returns a multipart boundary that will not collide with anything in the
// field values.
func randomBoundary() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "crackwebboundary"
	}
	return hex.EncodeToString(raw[:])
}

// jsURLRe finds absolute addresses written in inline script, which is where single-page
// applications keep the calls a link-only crawl never sees.
//
// Same-origin paths are deliberately left to scriptTargets. That one substitutes the
// interpolated segments a template literal carries, and — more to the point — splitting the
// read/write decision across two extractors is how one of them ends up queueing a path the
// other meant to skip.
var jsURLRe = regexp.MustCompile("[\"'`](https?://[^\"'`\\s<>]+)[\"'`]")

// Parse extracts links and forms from an HTML document.
//
// It is deliberately a scanner rather than a browser: it follows anchors,
// frames, form actions and the URL literals in scripts. That covers the
// server-rendered web well and the browser engine covers the rest.
func Parse(document string, base *url.URL, allowStateChange bool) (*Page, error) {
	root, err := html.Parse(strings.NewReader(document))
	if err != nil {
		return nil, err
	}

	page := &Page{}
	seenLinks := map[string]bool{}

	addLink := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") ||
			strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") ||
			strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "about:") {
			return
		}
		resolved := resolve(base, raw)
		if resolved == "" || seenLinks[resolved] {
			return
		}
		seenLinks[resolved] = true
		page.Links = append(page.Links, resolved)
	}

	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "a", "area":
				addLink(attr(node, "href"))
			case "link":
				// Stylesheet and preload links point at assets; icon and
				// alternate links point at real pages.
				if rel := strings.ToLower(attr(node, "rel")); rel == "icon" ||
					rel == "alternate" || rel == "canonical" || rel == "next" || rel == "prev" {
					addLink(attr(node, "href"))
				}
			case "iframe", "frame", "embed":
				addLink(attr(node, "src"))
			case "form":
				page.Forms = append(page.Forms, buildForm(node, base))
			case "meta":
				// http-equiv=refresh carries its target in the content attribute.
				if strings.EqualFold(attr(node, "http-equiv"), "refresh") {
					if target := refreshTarget(attr(node, "content")); target != "" {
						addLink(target)
					}
				}
			case "script":
				if src := attr(node, "src"); src != "" {
					addLink(src)
					break
				}
				if node.FirstChild != nil && node.FirstChild.Type == html.TextNode {
					script := node.FirstChild.Data
					// Absolute addresses the page names.
					for _, match := range jsURLRe.FindAllStringSubmatchIndex(script, 40*4) {
						if !allowStateChange && !safeMethodNear(script, match) {
							continue
						}
						addLink(script[match[2]:match[3]])
					}
					// And same-origin paths, which scriptTargets resolves and whose
					// interpolated segments it substitutes.
					for _, address := range scriptTargets(script, base, allowStateChange) {
						addLink(address)
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)

	return page, nil
}

// buildForm walks a form's controls.
func buildForm(node *html.Node, base *url.URL) Form {
	form := Form{
		Action:  attr(node, "action"),
		Method:  strings.ToUpper(strings.TrimSpace(attr(node, "method"))),
		Enctype: strings.ToLower(strings.TrimSpace(attr(node, "enctype"))),
	}
	if form.Method == "" {
		form.Method = "GET"
	}
	_ = base

	var collect func(*html.Node)
	collect = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				form.Fields = append(form.Fields, Field{
					Name:  attr(n, "name"),
					Value: attr(n, "value"),
					Type:  attr(n, "type"),
				})
			case "textarea":
				form.Fields = append(form.Fields, Field{
					Name:  attr(n, "name"),
					Value: textContent(n),
					Type:  "textarea",
				})
			case "select":
				name := attr(n, "name")
				value := ""
				// Prefer the selected option, else the first one: an empty value
				// for a required select usually fails validation before the
				// request reaches the code under test.
				var firstOption string
				for option := n.FirstChild; option != nil; option = option.NextSibling {
					if option.Type != html.ElementNode || option.Data != "option" {
						continue
					}
					optionValue := attr(option, "value")
					if optionValue == "" {
						optionValue = textContent(option)
					}
					if firstOption == "" {
						firstOption = optionValue
					}
					if _, hasSelected := attrOK(option, "selected"); hasSelected {
						value = optionValue
						break
					}
				}
				if value == "" {
					value = firstOption
				}
				form.Fields = append(form.Fields, Field{Name: name, Value: value, Type: "select"})
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			collect(child)
		}
	}
	collect(node)

	return form
}

// refreshTarget pulls the URL out of a meta refresh content value.
func refreshTarget(content string) string {
	lower := strings.ToLower(content)
	idx := strings.Index(lower, "url=")
	if idx < 0 {
		return ""
	}
	target := strings.TrimSpace(content[idx+4:])
	target = strings.Trim(target, `"'`)
	return target
}

// attr returns an attribute value, or "".
func attr(node *html.Node, name string) string {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

// attrOK reports whether an attribute is present, even when empty.
func attrOK(node *html.Node, name string) (string, bool) {
	for _, a := range node.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

// textContent concatenates a node's direct text children.
func textContent(node *html.Node) string {
	var b strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			b.WriteString(child.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

// resolve turns a possibly-relative reference into an absolute URL.
func resolve(base *url.URL, raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if base == nil {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	// Scheme-relative URLs (//host/path) keep the base scheme.
	return base.ResolveReference(ref).String()
}
