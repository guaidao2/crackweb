package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/guaidao2/crackweb/internal/ca"
	"github.com/guaidao2/crackweb/internal/i18n"
)

// caOptions is the parsed command line of "crackweb ca".
type caOptions struct {
	out    *string
	force  *bool
	export *string
}

// newCaCommand builds the CA management command: create the signing material,
// show where it is, and export it for installation.
func newCaCommand() *command {
	return newCommand("ca", i18n.KeyCmdCaSummary, i18n.KeyUsageCa,
		func(fs *FlagSet) *caOptions {
			return &caOptions{
				out:    fs.String("out", "", "", "<dir>", i18n.KeyFlagOutDir),
				force:  fs.Bool("force", "", i18n.KeyFlagForce),
				export: fs.String("export", "", "", "<file>", i18n.KeyFlagExportCA),
			}
		},
		runCA)
}

// runCA generates, inspects or exports the interception CA.
func runCA(app *App, opts *caOptions, _ []string) error {
	dir := *opts.out
	if dir == "" {
		dir = ca.DefaultDir("")
	}

	if *opts.force {
		// Regenerating means every certificate the user already installed
		// becomes invalid, so it has to be something they asked for.
		for _, name := range []string{ca.CertFileName, ca.KeyFileName} {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	authority, created, err := ca.LoadOrGenerate(dir)
	if err != nil {
		return fmt.Errorf(app.T(i18n.KeyErrLoadCA), err)
	}
	if created {
		app.Note(i18n.KeyMsgCAGenerated, dir)
	} else {
		app.Note(i18n.KeyMsgCALoaded, dir)
	}

	cert := authority.Certificate()
	app.Print("")
	app.Printf("  %-16s %s", app.T(i18n.KeyReportFieldCheck), cert.Subject.CommonName)
	app.Printf("  %-16s %s", "Serial", cert.SerialNumber.Text(16))
	app.Printf("  %-16s %s", "Expires", cert.NotAfter.Format("2006-01-02"))
	fingerprint := sha256.Sum256(cert.Raw)
	app.Printf("  %-16s %s", "SHA-256", shortFingerprint(fingerprint[:]))
	app.Printf("  %-16s %s", "Certificate", filepath.Join(dir, ca.CertFileName))
	app.Printf("  %-16s %s", "Key", filepath.Join(dir, ca.KeyFileName))
	app.Print("")

	if *opts.export != "" {
		if err := os.WriteFile(*opts.export, authority.CertPEM(), 0o644); err != nil {
			return err
		}
		app.Note(i18n.KeyMsgCAExported, *opts.export)
	} else {
		app.Note(i18n.KeyMsgProxyCAHint, filepath.Join(dir, ca.CertFileName))
	}
	return nil
}

// shortFingerprint renders a certificate fingerprint as colon-separated hex
// pairs, which is the form comparison tools accept.
func shortFingerprint(raw []byte) string {
	const shown = 8
	parts := make([]string, 0, shown*2)
	for i := 0; i < shown && i < len(raw); i++ {
		parts = append(parts, fmt.Sprintf("%02X", raw[i]))
	}
	if len(raw) > shown {
		parts = append(parts, "…")
	}
	return joinColon(parts)
}

// joinColon joins parts with colons.
func joinColon(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ":"
		}
		out += p
	}
	return out
}
