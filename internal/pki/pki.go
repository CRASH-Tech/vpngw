// Package pki maintains the internal CA used by OpenVPN.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"vpngw/internal/secret"
	"vpngw/internal/store"
)

// CA is the internal certificate authority.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

const (
	kvCACert = "pki/ca.crt"
	kvCAKey  = "pki/ca.key" // encrypted with the master key
)

// LoadOrCreate returns the CA, creating it on first use.
func LoadOrCreate(st *store.Store, box *secret.Box) (*CA, error) {
	certPEM, err := st.GetKV(kvCACert)
	if err == nil {
		enc, err := st.GetKV(kvCAKey)
		if err != nil {
			return nil, err
		}
		keyDER, err := box.Open(enc, kvCAKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt CA key: %w", err)
		}
		key, err := x509.ParseECPrivateKey(keyDER)
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(certPEM)
		if blk == nil {
			return nil, errors.New("bad CA certificate")
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
	}
	if !store.IsNotFound(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "vpngw OpenVPN CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := st.PutKV(kvCAKey, box.Seal(keyDER, kvCAKey)); err != nil {
		return nil, err
	}
	if err := st.PutKV(kvCACert, certPEM); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

// IssueServer issues a server certificate; it returns PEM cert and key.
func (ca *CA) IssueServer(cn string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, key.Public(), ca.key)
	if err != nil {
		return nil, nil, err
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}
