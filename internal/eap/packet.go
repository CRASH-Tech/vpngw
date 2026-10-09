package eap

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // mandated by RADIUS.
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP codes (RFC 3748).
const (
	CodeRequest  = 1
	CodeResponse = 2
	CodeSuccess  = 3
	CodeFailure  = 4
)

// EAP types.
const (
	TypeIdentity = 1
	TypeNak      = 3
	TypeMSCHAPv2 = 26
)

// MS-CHAPv2 opcodes (draft-kamath-pppext-eap-mschapv2).
const (
	OpChallenge = 1
	OpResponse  = 2
	OpSuccess   = 3
	OpFailure   = 4
)

// Packet is an EAP packet.
type Packet struct {
	Code       byte
	Identifier byte
	Type       byte // only for Request/Response
	Data       []byte
}

// Parse decodes an EAP packet.
func Parse(b []byte) (*Packet, error) {
	if len(b) < 4 {
		return nil, errors.New("eap: packet too short")
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l < 4 || l > len(b) {
		return nil, errors.New("eap: bad length")
	}
	p := &Packet{Code: b[0], Identifier: b[1]}
	if p.Code == CodeRequest || p.Code == CodeResponse {
		if l < 5 {
			return nil, errors.New("eap: missing type")
		}
		p.Type = b[4]
		p.Data = append([]byte(nil), b[5:l]...)
	}
	return p, nil
}

// Encode serialises the packet.
func (p *Packet) Encode() []byte {
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		return []byte{p.Code, p.Identifier, 0, 4}
	}
	l := 5 + len(p.Data)
	b := make([]byte, l)
	b[0], b[1] = p.Code, p.Identifier
	binary.BigEndian.PutUint16(b[2:4], uint16(l))
	b[4] = p.Type
	copy(b[5:], p.Data)
	return b
}

// mschapMsg builds MS-CHAPv2 data: OpCode, MS-CHAPv2-ID, MS-Length, body.
func mschapMsg(op, id byte, body []byte) []byte {
	b := make([]byte, 4+len(body))
	b[0], b[1] = op, id
	binary.BigEndian.PutUint16(b[2:4], uint16(4+len(body)))
	copy(b[4:], body)
	return b
}

// ChallengeRequest builds an EAP-Request/MSCHAPv2 Challenge.
func ChallengeRequest(eapID, msID byte, challenge []byte, serverName string) *Packet {
	body := append([]byte{byte(len(challenge))}, challenge...)
	body = append(body, serverName...)
	return &Packet{Code: CodeRequest, Identifier: eapID, Type: TypeMSCHAPv2, Data: mschapMsg(OpChallenge, msID, body)}
}

// SuccessRequest builds an EAP-Request/MSCHAPv2 Success with the authenticator response.
func SuccessRequest(eapID, msID byte, authResp string) *Packet {
	return &Packet{Code: CodeRequest, Identifier: eapID, Type: TypeMSCHAPv2, Data: mschapMsg(OpSuccess, msID, []byte(authResp+" M=Welcome"))}
}

// FailureRequest builds an EAP-Request/MSCHAPv2 Failure (E=691, no retry).
func FailureRequest(eapID, msID byte, challenge []byte, msg string) *Packet {
	text := fmt.Sprintf("E=691 R=0 C=%X V=3 M=%s", challenge, msg)
	return &Packet{Code: CodeRequest, Identifier: eapID, Type: TypeMSCHAPv2, Data: mschapMsg(OpFailure, msID, []byte(text))}
}

// Response is a parsed MS-CHAPv2 Response.
type Response struct {
	MSID          byte
	PeerChallenge []byte
	NTResponse    []byte
	Flags         byte
	Name          string
}

// ParseResponse decodes the data of an EAP-Response/MSCHAPv2 Response.
func ParseResponse(data []byte) (*Response, error) {
	if len(data) < 4 || data[0] != OpResponse {
		return nil, errors.New("mschapv2: not a response")
	}
	msLen := int(binary.BigEndian.Uint16(data[2:4]))
	if msLen > len(data) || msLen < 4+1+49 {
		return nil, errors.New("mschapv2: bad response length")
	}
	if data[4] != 49 {
		return nil, errors.New("mschapv2: bad value size")
	}
	v := data[5 : 5+49]
	return &Response{
		MSID:          data[1],
		PeerChallenge: append([]byte(nil), v[0:16]...),
		NTResponse:    append([]byte(nil), v[24:48]...),
		Flags:         v[48],
		Name:          string(data[5+49 : msLen]),
	}, nil
}

// SplitEAPMessage splits an encoded EAP packet into RADIUS EAP-Message
// attribute chunks of at most 253 bytes.
func SplitEAPMessage(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 253 {
		out = append(out, b[:253])
		b = b[253:]
	}
	return append(out, b)
}

// MessageAuthenticator computes HMAC-MD5 over a RADIUS packet whose
// Message-Authenticator value is zeroed and whose authenticator field holds
// the request authenticator (RFC 3579 §3.2).
func MessageAuthenticator(packet, secret []byte) []byte {
	m := hmac.New(md5.New, secret)
	m.Write(packet)
	return m.Sum(nil)
}

// EncryptMPPEKey encrypts an MS-MPPE-Send/Recv-Key value (RFC 2548 §2.4.2).
func EncryptMPPEKey(key, secret, reqAuth []byte, salt [2]byte) []byte {
	salt[0] |= 0x80
	plain := append([]byte{byte(len(key))}, key...)
	if r := len(plain) % 16; r != 0 {
		plain = append(plain, make([]byte, 16-r)...)
	}
	out := append([]byte{}, salt[:]...)
	prev := append(append([]byte{}, reqAuth...), salt[:]...)
	for i := 0; i < len(plain); i += 16 {
		h := md5.New() //nolint:gosec
		h.Write(secret)
		h.Write(prev)
		b := h.Sum(nil)
		c := make([]byte, 16)
		for j := 0; j < 16; j++ {
			c[j] = plain[i+j] ^ b[j]
		}
		out = append(out, c...)
		prev = c
	}
	return out
}

// DecryptMPPEKey reverses EncryptMPPEKey (used in tests).
func DecryptMPPEKey(enc, secret, reqAuth []byte) ([]byte, error) {
	if len(enc) < 18 || (len(enc)-2)%16 != 0 {
		return nil, errors.New("mppe: bad length")
	}
	salt := enc[:2]
	prev := append(append([]byte{}, reqAuth...), salt...)
	var plain []byte
	for i := 2; i < len(enc); i += 16 {
		h := md5.New() //nolint:gosec
		h.Write(secret)
		h.Write(prev)
		b := h.Sum(nil)
		for j := 0; j < 16; j++ {
			plain = append(plain, enc[i+j]^b[j])
		}
		prev = enc[i : i+16]
	}
	n := int(plain[0])
	if n > len(plain)-1 {
		return nil, errors.New("mppe: bad key length")
	}
	return plain[1 : 1+n], nil
}
