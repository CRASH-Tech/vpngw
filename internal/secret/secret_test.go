package secret

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDerivePassword(t *testing.T) {
	master := bytes.Repeat([]byte{1}, KeySize)
	at := time.Unix(1700000000, 123)
	nonce := []byte("nonce-nonce-1234")
	p1 := DerivePassword(master, "sid-1", at, nonce)
	if len(p1) != PasswordLength || p1 != DerivePassword(master, "sid-1", at, nonce) {
		t.Fatalf("password %q must be deterministic and %d chars", p1, PasswordLength)
	}
	for _, other := range []string{
		DerivePassword(master, "sid-2", at, nonce),
		DerivePassword(master, "sid-1", at.Add(time.Nanosecond), nonce),
		DerivePassword(master, "sid-1", at, []byte("other")),
		DerivePassword(bytes.Repeat([]byte{2}, KeySize), "sid-1", at, nonce),
	} {
		if other == p1 {
			t.Fatal("every input must change the password")
		}
	}
	for _, r := range p1 {
		if !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') {
			t.Fatalf("not base32: %q", p1)
		}
	}
}

func TestArgon2(t *testing.T) {
	h := HashPassword("correct horse")
	if !VerifyPassword(h, "correct horse") || VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") {
		t.Fatal("argon2id verify")
	}
	if HashPassword("correct horse") == h {
		t.Fatal("salt must differ")
	}
}

func TestNTHash(t *testing.T) {
	// RFC 2759 section 9.2: "clientPass".
	if got := hex.EncodeToString(NTHash("clientPass")); got != "44ebba8d5312b8d611474411f56989ae" {
		t.Fatalf("NTHash = %s", got)
	}
}

func TestBox(t *testing.T) {
	box, err := NewBox(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	ct := box.Seal([]byte("refresh-token"), "rt:1")
	if pt, err := box.Open(ct, "rt:1"); err != nil || string(pt) != "refresh-token" {
		t.Fatalf("open: %q %v", pt, err)
	}
	if _, err := box.Open(ct, "rt:2"); err == nil {
		t.Fatal("ciphertext must be bound to its context")
	}
	ct[len(ct)-1] ^= 1
	if _, err := box.Open(ct, "rt:1"); err == nil {
		t.Fatal("tampering must be detected")
	}
}

func TestLoadMasterKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadMasterKey(dir, "")
	if err != nil || len(k1) != KeySize {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, "master.key"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("master.key mode %v", st.Mode())
	}
	k2, _ := LoadMasterKey(dir, "")
	if !bytes.Equal(k1, k2) {
		t.Fatal("key must persist")
	}
	if _, err := LoadMasterKey(dir, "short"); err == nil {
		t.Fatal("invalid env key must fail")
	}
	k3, err := LoadMasterKey(dir, hex.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil || k3[0] != 9 {
		t.Fatal("hex env key")
	}
}
