package active

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
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
var uploadTraversalNames = []string{
	"../../crackweb-upload-test.txt",
	"..\\..\\crackweb-upload-test.txt",
	"....//....//crackweb-upload-test.txt",
	"/tmp/crackweb-upload-test.txt",
}

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
	base := c.BaselineFingerprint(t)

	// Traversal first: it is the stronger claim, and reporting one finding is
	// more useful than reporting seventeen variations of "it accepted a name".
	for _, group := range []struct {
		names      []string
		confidence finding.Confidence
		kind       string
	}{
		{uploadTraversalNames, finding.ConfidenceFirm, "the file name escapes the upload directory"},
		{uploadExtensionNames, finding.ConfidenceTentative, "the file name carries an executable extension"},
	} {
		for _, filename := range group.names {
			mutated, response, err := sendUpload(ctx, c, t, form, filename)
			if err != nil || response == nil {
				continue
			}
			if response.Status >= 400 {
				continue
			}
			similarity := diff.CompareFingerprints(base, c.Fingerprint(response)).Score
			if similarity < uploadSimilarity {
				// The server answered differently, which is what a rejection
				// looks like from here.
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
	return nil
}

// uploadForm is the structure of a multipart request, kept so it can be rebuilt
// with a different filename.
type uploadForm struct {
	fields    []httpmsg.KV
	fileField string
	content   []byte
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

	part, err := writer.CreateFormFile(f.fileField, filename)
	if err == nil {
		_, _ = part.Write(f.content)
	}
	_ = writer.Close()
	return buf.Bytes(), writer.FormDataContentType()
}

// sendUpload rebuilds a multipart request with a new filename and sends it.
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
