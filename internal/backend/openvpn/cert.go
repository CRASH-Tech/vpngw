package openvpn

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// SystemRoots is the CA bundle searched for the root of the portal's
// certificate chain.
var SystemRoots = "/etc/ssl/certs/ca-certificates.crt"

// CertSource is the portal's certificate (tlsmgr.Manager).
type CertSource interface {
	RuntimeCert() string // leaf followed by intermediates
	RuntimeKey() string
	ChainPEM() []byte
	IsSelfSigned() bool
}

// trust is how the server authenticates itself to clients.
type trust struct {
	Public   bool   // the portal's publicly trusted certificate
	CAPEM    []byte // trust anchor embedded in client profiles
	CertFile string
	KeyFile  string
	Name     string // subject CN checked by clients (verify-x509-name)
	Note     string
}

func parseCert(data []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM data")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseCerts(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return out
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

// publicTrust finds the root of a certificate chain (its last element if
// self-signed, else its issuer in the system bundle) and checks that the
// chain verifies to it. OpenVPN clients do not use the system trust store,
// so profiles carry this root; verify-x509-name pins the subject CN.
func publicTrust(chainPEM []byte, rootsFile string) (rootPEM []byte, cn string, err error) {
	chain := parseCerts(chainPEM)
	if len(chain) == 0 {
		return nil, "", errors.New("no certificate")
	}
	leaf := chain[0]
	if leaf.Subject.CommonName == "" {
		return nil, "", errors.New("the certificate has no subject CN for clients to check")
	}
	last := chain[len(chain)-1]
	var root *x509.Certificate
	if len(chain) > 1 && selfSigned(last) {
		root, chain = last, chain[:len(chain)-1]
	} else {
		bundle, err := os.ReadFile(rootsFile)
		if err != nil {
			return nil, "", err
		}
		for _, c := range parseCerts(bundle) {
			if bytes.Equal(last.RawIssuer, c.RawSubject) && last.CheckSignatureFrom(c) == nil {
				root = c
				break
			}
		}
		if root == nil {
			return nil, "", fmt.Errorf("the root of %q is not in the system CA bundle", last.Issuer.CommonName)
		}
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), leaf.Subject.CommonName, nil
}
