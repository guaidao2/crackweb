package active

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
)

// zipSlipSite extracts the archive it is handed per entry. When `confined`, each entry is
// reduced to its base name, which is what confining the target path to the extraction
// directory amounts to; otherwise the entry name is used as it stands and a `../` entry
// lands one level up, where the site then serves it.
func zipSlipSite(t *testing.T, confined bool) *httptest.Server {
	t.Helper()
	files := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for _, headers := range r.MultipartForm.File {
				for _, header := range headers {
					// A hardened endpoint refuses the dangerous *names*, which is what
					// lets the archive defect be seen on its own rather than behind a
					// traversal.
					// Go's multipart reader returns the base name, so the name the
					// client wrote is read back out of the header — which is what a
					// runtime that does not strip it would see, and what this fixture
					// has to judge.
					name := header.Filename
					if raw := header.Header.Get("Content-Disposition"); raw != "" {
						if index := strings.Index(raw, "filename="); index >= 0 {
							name = strings.Trim(raw[index+len("filename="):], `"`)
						}
					}
					// The control group needs a name the endpoint cannot accept, or the
					// check concludes that this endpoint has no answers to tell apart.
					if len(name) > 200 || isDangerousUploadName(name) {
						w.WriteHeader(http.StatusUnprocessableEntity)
						fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
						return
					}
					file, err := header.Open()
					if err != nil {
						continue
					}
					data, _ := io.ReadAll(file)
					file.Close()
					reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
					if err != nil {
						continue
					}
					for _, entry := range reader.File {
						name := entry.Name
						if confined {
							// What confining does: the entry keeps only its last
							// segment and lands inside the extraction directory, so a
							// read from the web root does not find it.
							name = "up/" + path.Base(name)
						} else {
							// What the site's own routing does: the entry name builds a
							// path under the extraction directory, one level up included.
							// A `../` entry lands where the web server serves from; an
							// entry with no path stays inside.
							name = strings.TrimPrefix(path.Clean("/up/"+name), "/")
						}
						source, err := entry.Open()
						if err != nil {
							continue
						}
						content, _ := io.ReadAll(source)
						source.Close()
						files[name] = string(content)
					}
				}
			}
			fmt.Fprintf(w, "<html><body>Upload complete. %s</body></html>", strings.Repeat("thank you ", 30))
			return
		}
		if content, ok := files[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			fmt.Fprint(w, content)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadFiresOnZipSlip: the entry escaped, and the content the check chose is served
// from the path it escaped to.
func TestUploadFiresOnZipSlip(t *testing.T) {
	server := zipSlipSite(t, false)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.zip", "PK archive")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an archive whose entry escaped the extraction directory was not reported")
	}
	if findings[0].CWE != "CWE-22" {
		t.Errorf("CWE = %q (payload %q), want CWE-22", findings[0].CWE, findings[0].Payload)
	}
	if findings[0].Confidence != "certain" {
		t.Errorf("confidence = %q, want certain: the content came back", findings[0].Confidence)
	}
}

// TestUploadStaysQuietWhenEntriesAreConfined: the same archive against a site that keeps
// only the last path segment, which is what confining the target does.
func TestUploadStaysQuietWhenEntriesAreConfined(t *testing.T) {
	server := zipSlipSite(t, true)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.zip", "PK archive")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("a site that confined the entries was reported: %v", findings[0].Evidence.Matches)
	}
}

// mimeJudgingSite accepts a file only when it declares itself an image *and* begins with the
// bytes of one — the shape of an endpoint that has been hardened against the obvious, and
// not against the declaration the uploader writes himself.
func mimeJudgingSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fmt.Fprint(w, "<html><body>form</body></html>")
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, headers := range r.MultipartForm.File {
			for _, header := range headers {
				file, err := header.Open()
				if err != nil {
					continue
				}
				head := make([]byte, 6)
				n, _ := io.ReadFull(file, head)
				file.Close()
				declared := header.Header.Get("Content-Type")
				isImage := strings.HasPrefix(declared, "image/")
				isPicture := n == 6 && (string(head[:6]) == "GIF87a" || string(head[:6]) == "GIF89a")
				if !isImage || !isPicture {
					fmt.Fprint(w, "<html><body>Error: only images are allowed.</body></html>")
					return
				}
			}
		}
		fmt.Fprintf(w, "<html><body>Upload complete. %s</body></html>", strings.Repeat("thank you ", 30))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadFiresOnADisguisedFile: the name is unacceptable and the endpoint took it anyway,
// because the upload said it was an image and started with one.
func TestUploadFiresOnADisguisedFile(t *testing.T) {
	server := mimeJudgingSite(t)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint that accepted a disguised executable name was not reported")
	}
	if !strings.Contains(findings[0].Payload, "declared as") {
		t.Errorf("payload = %q, want the disguise described", findings[0].Payload)
	}
	if findings[0].CWE != "CWE-434" {
		t.Errorf("CWE = %q, want CWE-434", findings[0].CWE)
	}
}

// TestUploadStaysQuietWhenTheNameIsWhatCounts: the same disguise against an endpoint that
// refuses the extension, which is the endpoint that is doing its job.
func TestUploadStaysQuietWhenTheNameIsWhatCounts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fmt.Fprint(w, "<html><body>form</body></html>")
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, headers := range r.MultipartForm.File {
			for _, header := range headers {
				if isDangerousUploadName(header.Filename) {
					fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
					return
				}
			}
		}
		fmt.Fprintf(w, "<html><body>Upload complete. %s</body></html>", strings.Repeat("thank you ", 30))
	}))
	defer server.Close()

	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)
	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("an endpoint that refuses the extension was reported: %v", findings[0].Evidence.Matches)
	}
}

// splitJudgingSite validates the first entry of a repeated field and stores the last — the
// disagreement the duplicate-field probe is about.
func splitJudgingSite(t *testing.T, sameBothEnds bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fmt.Fprint(w, "<html><body>form</body></html>")
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for field, headers := range r.MultipartForm.File {
			if len(headers) == 0 {
				continue
			}
			name := headers[0].Filename
			if raw := headers[0].Header.Get("Content-Disposition"); raw != "" {
				if index := strings.Index(raw, "filename="); index >= 0 {
					name = strings.Trim(raw[index+len("filename="):], `"`)
				}
			}
			checked := name
			if sameBothEnds && len(headers) > 1 {
				// A sanitised endpoint normalises every entry, so the last one is checked too.
				last := headers[len(headers)-1].Filename
				if raw := headers[len(headers)-1].Header.Get("Content-Disposition"); raw != "" {
					if index := strings.Index(raw, "filename="); index >= 0 {
						last = strings.Trim(raw[index+len("filename="):], `"`)
					}
				}
				if isDangerousUploadName(last) {
					fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
					return
				}
			}
			if isDangerousUploadName(checked) {
				fmt.Fprint(w, "<html><body>Error: that file type is not allowed.</body></html>")
				return
			}
			_ = field
		}
		fmt.Fprintf(w, "<html><body>Upload complete. %s</body></html>", strings.Repeat("thank you ", 30))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestUploadFiresOnARepeatedField: the name is refused on its own and accepted when it
// arrives beside a harmless file, which is the bypass stated exactly.
func TestUploadFiresOnARepeatedField(t *testing.T) {
	server := splitJudgingSite(t, false)
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline})
	if len(findings) == 0 {
		t.Fatal("an endpoint whose validation and storage disagree was not reported")
	}
	if !strings.Contains(findings[0].Payload, "twice") {
		t.Errorf("payload = %q, want the repeated field described", findings[0].Payload)
	}
}

// TestUploadStaysQuietWhenEveryEntryIsChecked: the same body against an endpoint that checks
// what it stores, which is the endpoint that is doing its job.
func TestUploadStaysQuietWhenEveryEntryIsChecked(t *testing.T) {
	server := splitJudgingSite(t, false)
	// The first site judges the first entry; this one judges the last as well.
	server.Config.Handler = splitJudgingSite(t, true).Config.Handler
	request := multipartRequest(t, server.URL+"/upload", "avatar", "photo.png", "PNG data")
	h := newHarness(t)
	baseline, _ := h.client.Do(context.Background(), request)
	if findings := runRequestLevel(t, h, unsafeUpload{}, &checks.Target{Request: request, Response: baseline}); len(findings) != 0 {
		t.Errorf("an endpoint that checks every entry was reported: %v", findings[0].Evidence.Matches)
	}
}
