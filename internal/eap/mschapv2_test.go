package eap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"vpngw/internal/secret"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Test vectors from RFC 2759 section 9.2.
func TestRFC2759Vectors(t *testing.T) {
	user := "User"
	authChal := hx(t, "5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28")
	peerChal := hx(t, "21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E")
	ntHash := secret.NTHash("clientPass")
	if want := hx(t, "44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE"); !bytes.Equal(ntHash, want) {
		t.Fatalf("NtPasswordHash = %X, want %X", ntHash, want)
	}
	if got, want := ChallengeHash(peerChal, authChal, user), hx(t, "D0 2E 43 86 BC E9 12 26"); !bytes.Equal(got, want) {
		t.Fatalf("ChallengeHash = %X, want %X", got, want)
	}
	ntResp := GenerateNTResponse(authChal, peerChal, user, ntHash)
	if want := hx(t, "82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF"); !bytes.Equal(ntResp, want) {
		t.Fatalf("NT-Response = %X, want %X", ntResp, want)
	}
	if got, want := HashNTHash(ntHash), hx(t, "41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F"); !bytes.Equal(got, want) {
		t.Fatalf("PasswordHashHash = %X, want %X", got, want)
	}
	if got := GenerateAuthenticatorResponse(ntHash, ntResp, peerChal, authChal, user); got != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatalf("AuthenticatorResponse = %s", got)
	}
	// Domain prefix is ignored in the challenge hash.
	if !bytes.Equal(ChallengeHash(peerChal, authChal, `CORP\User`), ChallengeHash(peerChal, authChal, user)) {
		t.Fatal("domain not stripped")
	}
}

// Test vectors from RFC 3079 section 3.5.3 (128-bit keys).
func TestRFC3079Vectors(t *testing.T) {
	ntHash := secret.NTHash("clientPass")
	ntResp := hx(t, "82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF")
	mk := MasterKey(ntHash, ntResp)
	if want := hx(t, "FD EC E3 71 7A 8C 83 8C B3 88 E5 27 AE 3C DD 31"); !bytes.Equal(mk, want) {
		t.Fatalf("MasterKey = %X, want %X", mk, want)
	}
	send := AsymmetricStartKey(mk, true)
	if want := hx(t, "8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB"); !bytes.Equal(send, want) {
		t.Fatalf("SendStartKey128 = %X, want %X", send, want)
	}
}

func TestMPPEKeyRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 16)
	sec := []byte("radius-secret")
	auth := bytes.Repeat([]byte{1}, 16)
	enc := EncryptMPPEKey(key, sec, auth, [2]byte{0x12, 0x34})
	if len(enc) != 2+32 || enc[0]&0x80 == 0 {
		t.Fatalf("bad encrypted key %X", enc)
	}
	dec, err := DecryptMPPEKey(enc, sec, auth)
	if err != nil || !bytes.Equal(dec, key) {
		t.Fatalf("round trip failed: %X %v", dec, err)
	}
}

func TestPacketEncoding(t *testing.T) {
	chal := bytes.Repeat([]byte{7}, 16)
	p := ChallengeRequest(5, 5, chal, "vpngw")
	enc := p.Encode()
	q, err := Parse(enc)
	if err != nil || q.Type != TypeMSCHAPv2 || q.Identifier != 5 || q.Data[0] != OpChallenge {
		t.Fatalf("parse: %+v %v", q, err)
	}
	// Build a response as a peer would and parse it back.
	peer := bytes.Repeat([]byte{9}, 16)
	ntr := GenerateNTResponse(chal, peer, "bob", secret.NTHash("pw"))
	val := append(append(append([]byte{}, peer...), make([]byte, 8)...), ntr...)
	val = append(val, 0)
	body := append([]byte{49}, val...)
	body = append(body, "bob"...)
	data := mschapMsg(OpResponse, 5, body)
	r, err := ParseResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "bob" || !bytes.Equal(r.NTResponse, ntr) || !bytes.Equal(r.PeerChallenge, peer) {
		t.Fatalf("bad response %+v", r)
	}
	if got := len(SplitEAPMessage(make([]byte, 600))); got != 3 {
		t.Fatalf("split = %d", got)
	}
}
