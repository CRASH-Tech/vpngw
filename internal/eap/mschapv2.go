// Package eap implements the server side of EAP-MSCHAPv2 carried in
// RADIUS: RFC 2759 (MS-CHAPv2), RFC 3079 (MPPE key derivation), RFC 2548
// (MS-MPPE-*-Key attribute encryption) and RFC 3579 (EAP over RADIUS).
//
// Only the NT hash of the password is needed; the plaintext password is
// never stored.
package eap

import (
	"crypto/des"  //nolint:gosec // DES is mandated by MS-CHAPv2.
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by MS-CHAPv2.
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is mandated by MS-CHAPv2.
)

// ChallengeHash implements RFC 2759 section 8.2.
func ChallengeHash(peerChallenge, authChallenge []byte, username string) []byte {
	h := sha1.New()
	h.Write(peerChallenge)
	h.Write(authChallenge)
	h.Write([]byte(StripDomain(username)))
	return h.Sum(nil)[:8]
}

// StripDomain removes a leading "DOMAIN\" from a user name (RFC 2759 §8.2).
func StripDomain(username string) string {
	if i := strings.LastIndexByte(username, '\\'); i >= 0 {
		return username[i+1:]
	}
	return username
}

// HashNTHash returns MD4(nt_hash) (PasswordHashHash).
func HashNTHash(ntHash []byte) []byte {
	h := md4.New()
	h.Write(ntHash)
	return h.Sum(nil)
}

// desKey expands 7 key bytes to an 8-byte DES key with parity bits.
func desKey(k []byte) []byte {
	out := make([]byte, 8)
	out[0] = k[0] >> 1
	out[1] = (k[0]&0x01)<<6 | k[1]>>2
	out[2] = (k[1]&0x03)<<5 | k[2]>>3
	out[3] = (k[2]&0x07)<<4 | k[3]>>4
	out[4] = (k[3]&0x0f)<<3 | k[4]>>5
	out[5] = (k[4]&0x1f)<<2 | k[5]>>6
	out[6] = (k[5]&0x3f)<<1 | k[6]>>7
	out[7] = k[6] & 0x7f
	for i := range out {
		out[i] <<= 1
	}
	return out
}

func desEncrypt(key7, clear []byte) []byte {
	block, err := des.NewCipher(desKey(key7))
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	block.Encrypt(out, clear)
	return out
}

// ChallengeResponse implements RFC 2759 section 8.5.
func ChallengeResponse(challenge, ntHash []byte) []byte {
	z := make([]byte, 21)
	copy(z, ntHash)
	resp := make([]byte, 0, 24)
	resp = append(resp, desEncrypt(z[0:7], challenge)...)
	resp = append(resp, desEncrypt(z[7:14], challenge)...)
	resp = append(resp, desEncrypt(z[14:21], challenge)...)
	return resp
}

// GenerateNTResponse implements RFC 2759 section 8.1.
func GenerateNTResponse(authChallenge, peerChallenge []byte, username string, ntHash []byte) []byte {
	return ChallengeResponse(ChallengeHash(peerChallenge, authChallenge, username), ntHash)
}

var (
	magic1 = []byte("Magic server to client signing constant")
	magic2 = []byte("Pad to make it do more than one iteration")
)

// GenerateAuthenticatorResponse implements RFC 2759 section 8.7 and
// returns the "S=<40 hex digits>" string.
func GenerateAuthenticatorResponse(ntHash, ntResponse, peerChallenge, authChallenge []byte, username string) string {
	h := sha1.New()
	h.Write(HashNTHash(ntHash))
	h.Write(ntResponse)
	h.Write(magic1)
	digest := h.Sum(nil)
	h = sha1.New()
	h.Write(digest)
	h.Write(ChallengeHash(peerChallenge, authChallenge, username))
	h.Write(magic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// RFC 3079 constants.
var (
	mppeMagic1 = []byte("This is the MPPE Master Key")
	mppeMagic2 = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	mppeMagic3 = []byte("On the client side, this is the receive key; on the server side, it is the send key.")
	shsPad1    = make([]byte, 40)
	shsPad2    = func() []byte {
		b := make([]byte, 40)
		for i := range b {
			b[i] = 0xf2
		}
		return b
	}()
)

// MasterKey implements RFC 3079 GetMasterKey.
func MasterKey(ntHash, ntResponse []byte) []byte {
	h := sha1.New()
	h.Write(HashNTHash(ntHash))
	h.Write(ntResponse)
	h.Write(mppeMagic1)
	return h.Sum(nil)[:16]
}

// AsymmetricStartKey implements RFC 3079 GetAsymmetricStartKey for the
// server side (IsServer = TRUE) with a 16-byte session key.
func AsymmetricStartKey(masterKey []byte, isSend bool) []byte {
	magic := mppeMagic2 // server receive key
	if isSend {
		magic = mppeMagic3 // server send key
	}
	h := sha1.New()
	h.Write(masterKey)
	h.Write(shsPad1)
	h.Write(magic)
	h.Write(shsPad2)
	return h.Sum(nil)[:16]
}

// ServerKeys returns the MS-MPPE-Send-Key and MS-MPPE-Recv-Key values
// (server perspective). The NAS derives the MSK as Recv ‖ Send.
func ServerKeys(ntHash, ntResponse []byte) (send, recv []byte) {
	mk := MasterKey(ntHash, ntResponse)
	return AsymmetricStartKey(mk, true), AsymmetricStartKey(mk, false)
}
