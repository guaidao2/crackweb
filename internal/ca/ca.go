// Package ca generates and caches the certificate authority crackweb uses to
// intercept TLS.
//
// The CA itself is created once and stored on disk; per-host leaf certificates
// are signed on demand and cached in memory. Leaf keys are 2048-bit RSA because
// interception has to work with whatever client is pointed at the proxy,
// including old ones that cannot handle ECDSA certificates.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File names inside the CA directory.
const (
	CertFileName = "crackweb-ca.crt"
	KeyFileName  = "crackweb-ca.key"
)

// leafKeyBits is the RSA key size for generated leaf certificates.
const leafKeyBits = 2048

// rootKeyBits is the RSA key size for the CA itself.
const rootKeyBits = 4096

// DefaultOrganisation names the CA in the certificate subject.
const DefaultOrganisation = "crackweb"

// CA is a certificate authority plus the cache of certificates it has signed.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey
	keyPEM  []byte

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// Generate creates a fresh CA.
func Generate(organisation string) (*CA, error) {
	if organisation == "" {
		organisation = DefaultOrganisation
	}
	key, err := rsa.GenerateKey(rand.Reader, rootKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   organisation + " interception CA",
			Organization: []string{organisation},
		},
		// Backdate slightly so a client with a skewed clock still accepts it.
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		leafs:   make(map[string]*tls.Certificate),
	}, nil
}

// Load reads a CA from a directory.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFileName))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFileName))
	if err != nil {
		return nil, err
	}
	return FromPEM(certPEM, keyPEM)
}

// FromPEM builds a CA from PEM-encoded material.
func FromPEM(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("ca: certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("ca: key is not valid PEM")
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:    cert,
		certPEM: certPEM,
		key:     key,
		keyPEM:  keyPEM,
		leafs:   make(map[string]*tls.Certificate),
	}, nil
}

// parsePrivateKey accepts the RSA key encodings in circulation: PKCS#1, and the
// generic PKCS#8 form that OpenSSL writes by default.
func parsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: key is %T, want an RSA private key", parsed)
	}
	return key, nil
}

// LoadOrGenerate loads the CA from dir, creating and saving one if the
// directory holds no CA yet.
func LoadOrGenerate(dir string) (*CA, bool, error) {
	authority, err := Load(dir)
	if err == nil {
		return authority, false, nil
	}
	if !os.IsNotExist(err) {
		// A CA that exists but cannot be read is a real problem: silently
		// replacing it would invalidate every certificate the user installed.
		return nil, false, fmt.Errorf("load CA from %s: %w", dir, err)
	}

	authority, err = Generate(DefaultOrganisation)
	if err != nil {
		return nil, false, err
	}
	if err := authority.Save(dir); err != nil {
		return nil, false, err
	}
	return authority, true, nil
}

// Save writes the CA certificate and key into dir, creating it if needed.
func (c *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create CA directory: %w", err)
	}
	// The key is written first and with tight permissions: if the process dies
	// half way, a certificate without a key is useless but harmless, whereas a
	// world-readable key is a lasting problem.
	if err := writeFile(filepath.Join(dir, KeyFileName), c.keyPEM, 0o600); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, CertFileName), c.certPEM, 0o644)
}

// writeFile writes a file with explicit permissions, replacing it atomically.
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// CertPEM returns the CA certificate in PEM form, ready to install in a browser
// or an operating-system trust store.
func (c *CA) CertPEM() []byte { return c.certPEM }

// KeyPEM returns the CA private key in PEM form.
func (c *CA) KeyPEM() []byte { return c.keyPEM }

// Certificate returns the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// LeafFor returns a certificate for host, signing a new one if the cache does
// not have it yet. host may carry a port, which is stripped: certificates are
// issued for names, not ports.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	name := stripPort(host)
	if name == "" {
		return nil, errors.New("ca: cannot issue a certificate for an empty host")
	}
	key := certCacheKey(host)

	c.mu.Lock()
	if cert, ok := c.leafs[key]; ok {
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	// Signing happens outside the lock so that a slow key generation does not
	// serialise every other connection.
	cert, err := c.sign(name)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Another goroutine may have won the race; either certificate is fine, and
	// reusing theirs keeps the cache to one entry per host.
	if existing, ok := c.leafs[key]; ok {
		return existing, nil
	}
	c.leafs[key] = cert
	return cert, nil
}

// sign issues a leaf certificate for one host.
func (c *CA) sign(name string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, leafKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate for %s: %w", name, err)
	}

	return &tls.Certificate{
		// The leaf goes first, the issuer after it, so clients that do not
		// fetch intermediates still build a chain.
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        mustParseCert(der),
	}, nil
}

// CachedLeafCount reports how many leaf certificates have been issued and kept.
func (c *CA) CachedLeafCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.leafs)
}

// DefaultDir returns the CA directory inside the crackweb workspace.
func DefaultDir(workspace string) string {
	if workspace == "" {
		workspace = defaultWorkspace()
	}
	return filepath.Join(workspace, "ca")
}

// defaultWorkspace is ~/.crackweb, overridable with CRACKWEB_HOME.
func defaultWorkspace() string {
	if dir := os.Getenv("CRACKWEB_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".crackweb"
	}
	return filepath.Join(home, ".crackweb")
}

// randomSerial produces a positive 128-bit serial number.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

// stripPort removes a trailing port from a host, leaving IPv6 literals intact.
func stripPort(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// No port, or a bare IPv6 literal.
	return strings.Trim(host, "[]")
}

// certCacheKey normalises a host for the certificate cache.
func certCacheKey(host string) string {
	return strings.ToLower(stripPort(host))
}

// mustParseCert parses a DER certificate, returning nil if it is malformed.
// CreateCertificate just produced the bytes, so a failure here is impossible in
// practice; a nil Leaf only costs a little laziness later.
func mustParseCert(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return cert
}
