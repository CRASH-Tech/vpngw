// Package tlsmgr provides the server certificate: an operator-supplied
// file (watched for changes), a certificate uploaded in the admin panel,
// Let's Encrypt via ACME HTTP-01, or a temporary self-signed certificate.
package tlsmgr

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"vpngw/internal/config"
)

// Sources of the active certificate.
const (
	SourceFile       = "file"
	SourceACME       = "acme"
	SourceSelfSigned = "self-signed"
)

// Info describes the active certificate.
type Info struct {
	Source      string
	Subject     string
	DNSNames    []string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
	Error       string
}

// Manager owns the certificate.
type Manager struct {
	cfg     *config.Config
	dataDir string

	mu        sync.RWMutex
	cert      *tls.Certificate
	leaf      *x509.Certificate
	chainPEM  []byte
	keyPEM    []byte
	source    string
	fileMod   time.Time
	lastErr   string
	listeners []func()

	acmeMu     sync.Mutex
	challenges map[string]string
}

// New creates a manager.
func New(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg, dataDir: cfg.Str("DATA_DIR"), challenges: map[string]string{}}
}

// CertFile returns the operator certificate path.
func (m *Manager) CertFile() string {
	if f := m.cfg.Str("TLS_CERT_FILE"); f != "" {
		return f
	}
	return filepath.Join(m.dataDir, "tls", "tls.crt")
}

// KeyFile returns the operator key path.
func (m *Manager) KeyFile() string {
	if f := m.cfg.Str("TLS_KEY_FILE"); f != "" {
		return f
	}
	return filepath.Join(m.dataDir, "tls", "tls.key")
}

// RuntimeCert and RuntimeKey are stable paths of the active certificate
// for the VPN servers.
func (m *Manager) RuntimeCert() string { return filepath.Join(m.dataDir, "run", "tls", "server.crt") }
func (m *Manager) RuntimeKey() string  { return filepath.Join(m.dataDir, "run", "tls", "server.key") }
func (m *Manager) RuntimeCA() string   { return filepath.Join(m.dataDir, "run", "tls", "chain.crt") }

// OnChange registers a callback invoked after the certificate changed.
func (m *Manager) OnChange(fn func()) {
	m.mu.Lock()
	m.listeners = append(m.listeners, fn)
	m.mu.Unlock()
}

// Init loads the best available certificate.
func (m *Manager) Init() error {
	if err := os.MkdirAll(filepath.Dir(m.RuntimeCert()), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(m.dataDir, "tls"), 0o700); err != nil {
		return err
	}
	if err := m.loadFile(false); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Error("certificate file unusable", "file", m.CertFile(), "err", err)
		m.setErr(err.Error())
	}
	if err := m.loadACMEStored(); err == nil {
		return nil
	}
	return m.selfSigned()
}

func (m *Manager) setErr(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

// GetCertificate implements tls.Config.GetCertificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("no certificate")
	}
	return m.cert, nil
}

// Info returns details about the active certificate.
func (m *Manager) Info() Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	i := Info{Source: m.source, Error: m.lastErr}
	if m.leaf != nil {
		i.Subject = m.leaf.Subject.CommonName
		i.DNSNames = m.leaf.DNSNames
		i.Issuer = m.leaf.Issuer.CommonName
		i.NotBefore, i.NotAfter = m.leaf.NotBefore, m.leaf.NotAfter
		sum := sha256.Sum256(m.leaf.Raw)
		i.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	return i
}

// ChainPEM returns the certificate chain.
func (m *Manager) ChainPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.chainPEM...)
}

// Uncovered returns VPN endpoints the certificate is not valid for.
func (m *Manager) Uncovered() []string {
	m.mu.RLock()
	leaf := m.leaf
	m.mu.RUnlock()
	var out []string
	for _, e := range m.cfg.Endpoints() {
		if leaf == nil || leaf.VerifyHostname(e.Host) != nil {
			out = append(out, e.Host)
		}
	}
	return out
}

// certNames are the DNS names a generated certificate must carry.
func (m *Manager) certNames() []string {
	names := []string{m.cfg.Str("VPN_HOSTNAME"), m.cfg.Str("PORTAL_HOSTNAME")}
	for _, e := range m.cfg.Endpoints() {
		if net.ParseIP(e.Host) == nil {
			names = append(names, e.Host)
		}
	}
	return uniq(names)
}

// IKEIdentity returns the IKEv2 identity of the server. strongSwan (and
// Apple) clients match it exactly against a certificate SAN, and strongSwan
// does not match wildcard SANs, so with a wildcard certificate a concrete
// SAN of the certificate is used instead of the host name.
func (m *Manager) IKEIdentity() string {
	host := m.cfg.Str("VPN_HOSTNAME")
	if id := m.cfg.Str("IKEV2_LOCAL_ID"); id != "" && id != "auto" {
		return id
	}
	m.mu.RLock()
	leaf := m.leaf
	m.mu.RUnlock()
	if leaf == nil {
		return host
	}
	for _, n := range leaf.DNSNames {
		if strings.EqualFold(n, host) {
			return host
		}
	}
	for _, n := range leaf.DNSNames {
		if !strings.HasPrefix(n, "*") {
			return n
		}
	}
	return host
}

// IsSelfSigned reports whether a temporary certificate is in use.
func (m *Manager) IsSelfSigned() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.source == SourceSelfSigned
}

// install validates and activates a certificate.
func (m *Manager) install(chainPEM, keyPEM []byte, source string) error {
	cert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	cert.Leaf = leaf
	for _, e := range m.cfg.Endpoints() {
		if e.Host != "" && leaf.VerifyHostname(e.Host) != nil {
			slog.Warn("certificate does not cover a VPN endpoint", "host", e.Host, "names", leaf.DNSNames)
		}
	}
	if time.Now().After(leaf.NotAfter) {
		slog.Warn("certificate has expired", "not_after", leaf.NotAfter)
	}
	// Normalised key (PKCS#8) for strongSwan and ocserv.
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	normKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	var normChain bytes.Buffer
	for _, c := range cert.Certificate {
		_ = pem.Encode(&normChain, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	var intermediates bytes.Buffer
	for _, c := range cert.Certificate[1:] {
		_ = pem.Encode(&intermediates, &pem.Block{Type: "CERTIFICATE", Bytes: c})
	}
	if err := writeAtomic(m.RuntimeKey(), normKey, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(m.RuntimeCert(), normChain.Bytes(), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(m.RuntimeCA(), intermediates.Bytes(), 0o644); err != nil {
		return err
	}
	m.mu.Lock()
	changed := m.leaf == nil || !bytes.Equal(m.leaf.Raw, leaf.Raw)
	m.cert, m.leaf, m.chainPEM, m.keyPEM, m.source = &cert, leaf, normChain.Bytes(), normKey, source
	m.lastErr = ""
	listeners := append([]func(){}, m.listeners...)
	m.mu.Unlock()
	if changed {
		slog.Info("certificate installed", "source", source, "subject", leaf.Subject.CommonName, "names", leaf.DNSNames,
			"not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
		for _, fn := range listeners {
			fn()
		}
	}
	return nil
}

// IntermediatesPEM returns the chain without the leaf.
func (m *Manager) IntermediatesPEM() []byte {
	b, _ := os.ReadFile(m.RuntimeCA())
	return b
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *Manager) loadFile(onlyIfChanged bool) error {
	st, err := os.Stat(m.CertFile())
	if err != nil {
		return err
	}
	kst, err := os.Stat(m.KeyFile())
	if err != nil {
		return err
	}
	mod := st.ModTime()
	if kst.ModTime().After(mod) {
		mod = kst.ModTime()
	}
	m.mu.RLock()
	same := m.source == SourceFile && mod.Equal(m.fileMod)
	m.mu.RUnlock()
	if onlyIfChanged && same {
		return nil
	}
	chain, err := os.ReadFile(m.CertFile())
	if err != nil {
		return err
	}
	key, err := os.ReadFile(m.KeyFile())
	if err != nil {
		return err
	}
	if err := m.install(chain, key, SourceFile); err != nil {
		return err
	}
	m.mu.Lock()
	m.fileMod = mod
	m.mu.Unlock()
	return nil
}

// Upload stores a certificate from the admin panel in the certificate file.
func (m *Manager) Upload(chainPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(chainPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate and key do not match: %w", err)
	}
	if err := writeAtomic(m.KeyFile(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(m.CertFile(), chainPEM, 0o644); err != nil {
		return err
	}
	return m.loadFile(false)
}

// Watch polls the certificate file and drives ACME renewal.
func (m *Manager) Watch(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	nextACME := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := m.loadFile(true); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			m.setErr(err.Error())
			slog.Warn("certificate file unusable", "err", err)
			continue
		}
		if time.Now().After(nextACME) && m.acmeEnabled() {
			if err := m.acmeRenewIfNeeded(ctx); err != nil {
				slog.Warn("ACME failed, retrying in 1h", "err", err)
				m.setErr("ACME: " + err.Error())
				nextACME = time.Now().Add(time.Hour)
			} else {
				nextACME = time.Now().Add(12 * time.Hour)
			}
		}
	}
}

// ACMEEnabled reports whether Let's Encrypt is used (needs port 80).
func (m *Manager) ACMEEnabled() bool { return m.acmeEnabled() }

func (m *Manager) acmeEnabled() bool {
	switch strings.ToLower(m.cfg.Str("ACME_ENABLED")) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return !m.cfg.Bool("DEV_MODE")
}

// --- self-signed ---

func (m *Manager) selfSigned() error {
	certPath := filepath.Join(m.dataDir, "tls", "selfsigned.crt")
	keyPath := filepath.Join(m.dataDir, "tls", "selfsigned.key")
	names := m.certNames()
	if c, err := os.ReadFile(certPath); err == nil {
		if k, err := os.ReadFile(keyPath); err == nil {
			if cert, err := tls.X509KeyPair(c, k); err == nil {
				if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil &&
					time.Until(leaf.NotAfter) > 30*24*time.Hour && sameNames(leaf.DNSNames, names) {
					return m.install(c, k, SourceSelfSigned)
				}
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"vpngw self-signed"}},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// iKEIntermediate, required by macOS/iOS for IKEv2 server certificates.
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 8, 2, 2}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return err
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	k := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	_ = writeAtomic(keyPath, k, 0o600)
	_ = writeAtomic(certPath, c, 0o644)
	slog.Warn("using a temporary self-signed certificate; Cisco and IKEv2 clients will not trust it", "names", names)
	return m.install(c, k, SourceSelfSigned)
}

func uniq(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		out = []string{"localhost"}
	}
	return out
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- ACME ---

// HTTPHandler serves ACME HTTP-01 challenges and redirects everything else to HTTPS.
func (m *Manager) HTTPHandler(redirect func(r *http.Request) string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if strings.HasPrefix(r.URL.Path, prefix) {
			m.acmeMu.Lock()
			v, ok := m.challenges[strings.TrimPrefix(r.URL.Path, prefix)]
			m.acmeMu.Unlock()
			if ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(v))
				return
			}
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, redirect(r), http.StatusMovedPermanently)
	})
}

// Present implements the lego HTTP-01 provider.
func (m *Manager) Present(_, token, keyAuth string) error {
	m.acmeMu.Lock()
	m.challenges[token] = keyAuth
	m.acmeMu.Unlock()
	return nil
}

// CleanUp implements the lego HTTP-01 provider.
func (m *Manager) CleanUp(_, token, _ string) error {
	m.acmeMu.Lock()
	delete(m.challenges, token)
	m.acmeMu.Unlock()
	return nil
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (m *Manager) acmeDir() string { return filepath.Join(m.dataDir, "tls", "acme") }

func (m *Manager) loadACMEStored() error {
	c, err := os.ReadFile(filepath.Join(m.acmeDir(), "cert.pem"))
	if err != nil {
		return err
	}
	k, err := os.ReadFile(filepath.Join(m.acmeDir(), "key.pem"))
	if err != nil {
		return err
	}
	return m.install(c, k, SourceACME)
}

func (m *Manager) acmeRenewIfNeeded(ctx context.Context) error {
	m.mu.RLock()
	src, leaf := m.source, m.leaf
	m.mu.RUnlock()
	names := m.certNames()
	if src == SourceACME && leaf != nil && time.Until(leaf.NotAfter) > 30*24*time.Hour && sameNames(leaf.DNSNames, names) {
		return nil
	}
	if err := os.MkdirAll(m.acmeDir(), 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(m.acmeDir(), "account.key")
	var key crypto.PrivateKey
	if b, err := os.ReadFile(keyPath); err == nil {
		key, err = certcrypto.ParsePEMPrivateKey(b)
		if err != nil {
			return err
		}
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		key = k
		if err := writeAtomic(keyPath, certcrypto.PEMEncode(k), 0o600); err != nil {
			return err
		}
	}
	user := &acmeUser{Email: m.cfg.Str("ACME_EMAIL"), key: key}
	lc := lego.NewConfig(user)
	if m.cfg.Bool("ACME_STAGING") {
		lc.CADirURL = lego.LEDirectoryStaging
	}
	lc.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(lc)
	if err != nil {
		return err
	}
	if err := client.Challenge.SetHTTP01Provider(m); err != nil {
		return err
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	user.Registration = reg
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: names, Bundle: true})
	if err != nil {
		return fmt.Errorf("obtain: %w", err)
	}
	if err := writeAtomic(filepath.Join(m.acmeDir(), "key.pem"), res.PrivateKey, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(m.acmeDir(), "cert.pem"), res.Certificate, 0o644); err != nil {
		return err
	}
	_ = ctx
	return m.install(res.Certificate, res.PrivateKey, SourceACME)
}
