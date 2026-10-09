package openvpn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func issue(t *testing.T, cn string, ca bool, parent *testCert, dns ...string) *testCert {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: dns,
		IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCert{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func TestPublicTrust(t *testing.T) {
	root := issue(t, "Test Root", true, nil)
	other := issue(t, "Other Root", true, nil)
	inter := issue(t, "Test Intermediate", true, root)
	leaf := issue(t, "vpn.example.com", false, inter, "vpn.example.com")
	bundle := filepath.Join(t.TempDir(), "bundle.crt")
	_ = os.WriteFile(bundle, append(append([]byte{}, other.pem...), root.pem...), 0o644)

	chain := append(append([]byte{}, leaf.pem...), inter.pem...)
	got, cn, err := publicTrust(chain, bundle)
	if err != nil || cn != "vpn.example.com" || !bytes.Equal(got, root.pem) {
		t.Fatalf("root from the bundle: %v %q", err, cn)
	}
	// A chain ending in a self-signed root needs no bundle.
	if got, _, err := publicTrust(append(chain, root.pem...), "/nonexistent"); err != nil || !bytes.Equal(got, root.pem) {
		t.Fatalf("root in the chain: %v", err)
	}
	if _, _, err := publicTrust(chain, filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("unknown root must fail")
	}
	_ = os.WriteFile(bundle, other.pem, 0o644)
	if _, _, err := publicTrust(chain, bundle); err == nil {
		t.Fatal("root missing from the bundle must fail")
	}
	noCN := issue(t, "", false, inter, "vpn.example.com")
	_ = os.WriteFile(bundle, root.pem, 0o644)
	if _, _, err := publicTrust(append(append([]byte{}, noCN.pem...), inter.pem...), bundle); err == nil {
		t.Fatal("a certificate without CN cannot be pinned by name")
	}
}
