// Package secret contains the cryptographic primitives of the gateway:
// master key handling, authenticated encryption of stored secrets and VPN
// password derivation/hashing.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is mandated by MS-CHAPv2.
)

// KeySize is the master key length.
const KeySize = 32

// LoadMasterKey returns the key from env (base64 or hex) or from
// <dir>/master.key, generating the file when missing.
func LoadMasterKey(dir, env string) ([]byte, error) {
	if env != "" {
		return parseKey(env)
	}
	path := filepath.Join(dir, "master.key")
	if b, err := os.ReadFile(path); err == nil {
		return parseKey(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	return key, nil
}

func parseKey(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == KeySize {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == KeySize {
		return b, nil
	}
	return nil, errors.New("master key must be 32 bytes, base64 or hex encoded")
}

// Box encrypts small secrets with AES-256-GCM under a sub-key of the master key.
type Box struct {
	aead   cipher.AEAD
	master []byte
}

// NewBox derives an encryption key from the master key.
func NewBox(master []byte) (*Box, error) {
	k := SubKey(master, "vpngw/secret-box/v1")
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, master: master}, nil
}

// SubKey derives a purpose-bound 32-byte key from the master key.
func SubKey(master []byte, purpose string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(purpose))
	return m.Sum(nil)
}

// Seal encrypts plaintext; ad binds the ciphertext to its context (e.g. row id).
func (b *Box) Seal(plaintext []byte, ad string) []byte {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return b.aead.Seal(nonce, nonce, plaintext, []byte(ad))
}

// Open decrypts data produced by Seal.
func (b *Box) Open(data []byte, ad string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(data) < n+b.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	return b.aead.Open(nil, data[:n], data[n:], []byte(ad))
}

// MAC returns HMAC-SHA256 of data with a purpose-bound key.
func (b *Box) MAC(purpose string, data []byte) []byte {
	m := hmac.New(sha256.New, SubKey(b.master, purpose))
	m.Write(data)
	return m.Sum(nil)
}

// PasswordLength is the length of generated VPN passwords.
const PasswordLength = 24

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// DerivePassword implements
// base32(HMAC-SHA256(master, sid ‖ created_at ‖ nonce))[:24].
func DerivePassword(master []byte, sid string, createdAt time.Time, nonce []byte) string {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(sid))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(createdAt.UnixNano()))
	m.Write(ts[:])
	m.Write(nonce)
	return b32.EncodeToString(m.Sum(nil))[:PasswordLength]
}

// RandomBytes returns n random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandomToken returns a URL-safe random token with n bytes of entropy.
func RandomToken(n int) string {
	return base64.RawURLEncoding.EncodeToString(RandomBytes(n))
}

// Argon2id parameters (OWASP recommendation: m=19 MiB, t=2, p=1).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

// HashPassword returns a PHC-formatted Argon2id hash.
func HashPassword(pw string) string {
	salt := RandomBytes(16)
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword checks pw against a PHC Argon2id hash in constant time.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NTHash returns MD4(UTF-16LE(password)).
func NTHash(pw string) []byte {
	u := utf16.Encode([]rune(pw))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// Equal compares strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
