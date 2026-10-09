package radius_test

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"

	"vpngw/internal/config"
	"vpngw/internal/eap"
	vr "vpngw/internal/radius"
	"vpngw/internal/secret"
	"vpngw/internal/testutil"
)

func start(t *testing.T) (*testutil.Env, *vr.Server, string) {
	e := testutil.NewEnv(t, nil)
	_, pw := e.Login(t)
	srv := vr.New(e.Core)
	srv.AuthAddr, srv.AcctAddr = "127.0.0.1:0", "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return e, srv, pw
}

func exchange(t *testing.T, srv *vr.Server, p *radius.Packet, addr string) *radius.Packet {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := radius.Exchange(ctx, p, addr)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestPAP(t *testing.T) {
	e, srv, pw := start(t)
	req := radius.New(radius.CodeAccessRequest, srv.Secret)
	_ = rfc2865.UserName_SetString(req, "alice@vpn-dc1")
	_ = rfc2865.UserPassword_SetString(req, pw)
	_ = rfc2865.NASIdentifier_SetString(req, vr.NASAnyConnect)
	_ = rfc2865.CallingStationID_SetString(req, "198.51.100.20")
	resp := exchange(t, srv, req, srv.AuthAddr)
	if resp.Code != radius.CodeAccessAccept {
		t.Fatalf("code %v: %s", resp.Code, rfc2865.ReplyMessage_GetString(resp))
	}
	ip := rfc2865.FramedIPAddress_Get(resp)
	if ip == nil || !e.Core.IPAM.Pool(config.AnyConnect).Prefix().Contains(mustAddr(ip.String())) {
		t.Fatalf("Framed-IP-Address %v", ip)
	}
	if routes, _ := rfc2865.FramedRoute_GetStrings(resp); len(routes) != 8 {
		t.Fatalf("Framed-Route %v", routes)
	}
	if v := resp.Get(80); len(v) != 16 {
		t.Fatal("Message-Authenticator missing")
	}
	// Accounting start/stop drive the session state.
	acct := radius.New(radius.CodeAccountingRequest, srv.Secret)
	_ = rfc2866.AcctStatusType_Set(acct, rfc2866.AcctStatusType_Value_Start)
	_ = rfc2865.FramedIPAddress_Set(acct, ip)
	_ = rfc2865.CallingStationID_SetString(acct, "198.51.100.20")
	exchange(t, srv, acct, srv.AcctAddr)
	time.Sleep(50 * time.Millisecond)
	if s, ok := e.Core.SessionByIP(mustAddr(ip.String())); !ok || s.State != "active" || s.ClientIP != "198.51.100.20" {
		t.Fatalf("session after accounting start: %+v", s)
	}
	acct = radius.New(radius.CodeAccountingRequest, srv.Secret)
	_ = rfc2866.AcctStatusType_Set(acct, rfc2866.AcctStatusType_Value_Stop)
	_ = rfc2865.FramedIPAddress_Set(acct, ip)
	_ = rfc2866.AcctInputOctets_Set(acct, 1000)
	exchange(t, srv, acct, srv.AcctAddr)
	time.Sleep(50 * time.Millisecond)
	if _, ok := e.Core.SessionByIP(mustAddr(ip.String())); ok {
		t.Fatal("session must end on accounting stop")
	}

	bad := radius.New(radius.CodeAccessRequest, srv.Secret)
	_ = rfc2865.UserName_SetString(bad, "alice@vpn-dc1")
	_ = rfc2865.UserPassword_SetString(bad, "wrong")
	if resp := exchange(t, srv, bad, srv.AuthAddr); resp.Code != radius.CodeAccessReject {
		t.Fatal("wrong password must be rejected")
	}
}

// eapRequest builds an Access-Request carrying an EAP message, signed with
// Message-Authenticator as a NAS would.
func eapRequest(srv *vr.Server, msg *eap.Packet, state []byte) *radius.Packet {
	p := radius.New(radius.CodeAccessRequest, srv.Secret)
	_ = rfc2865.UserName_SetString(p, "alice@vpn-dc1")
	_ = rfc2865.NASIdentifier_SetString(p, vr.NASIKEv2)
	for _, c := range eap.SplitEAPMessage(msg.Encode()) {
		p.Add(79, c)
	}
	if state != nil {
		_ = rfc2865.State_Set(p, state)
	}
	p.Add(80, make([]byte, 16))
	raw, _ := p.MarshalBinary()
	p.Set(80, eap.MessageAuthenticator(raw, srv.Secret))
	return p
}

func eapOf(t *testing.T, p *radius.Packet) *eap.Packet {
	var b []byte
	for _, a := range p.Attributes {
		if a.Type == 79 {
			b = append(b, a.Attribute...)
		}
	}
	m, err := eap.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func msVendor(p *radius.Packet, typ byte) []byte {
	for _, a := range p.Attributes {
		if a.Type != 26 {
			continue
		}
		if id, v, err := radius.VendorSpecific(a.Attribute); err == nil && id == 311 && len(v) > 2 && v[0] == typ {
			return v[2:]
		}
	}
	return nil
}

func TestEAPMSCHAPv2(t *testing.T) {
	e, srv, pw := start(t)
	login := "alice@vpn-dc1"

	// 1. Identity → MSCHAPv2 challenge.
	resp := exchange(t, srv, eapRequest(srv, &eap.Packet{Code: eap.CodeResponse, Identifier: 0, Type: eap.TypeIdentity, Data: []byte(login)}, nil), srv.AuthAddr)
	if resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("expected challenge, got %v", resp.Code)
	}
	state := rfc2865.State_Get(resp)
	ch := eapOf(t, resp)
	if ch.Type != eap.TypeMSCHAPv2 || ch.Data[0] != eap.OpChallenge || ch.Data[4] != 16 {
		t.Fatalf("bad challenge %+v", ch)
	}
	authChal := ch.Data[5:21]
	msID := ch.Data[1]

	// 2. Response computed like a Windows/strongSwan peer.
	peerChal := secret.RandomBytes(16)
	nt := secret.NTHash(pw)
	ntResp := eap.GenerateNTResponse(authChal, peerChal, login, nt)
	val := append(append(append([]byte{}, peerChal...), make([]byte, 8)...), ntResp...)
	val = append(val, 0)
	body := append([]byte{eap.OpResponse, msID, 0, 0, 49}, val...)
	body = append(body, login...)
	body[2], body[3] = byte(len(body)>>8), byte(len(body))
	resp = exchange(t, srv, eapRequest(srv, &eap.Packet{Code: eap.CodeResponse, Identifier: ch.Identifier, Type: eap.TypeMSCHAPv2, Data: body}, state), srv.AuthAddr)
	if resp.Code != radius.CodeAccessChallenge {
		t.Fatalf("expected success request, got %v", resp.Code)
	}
	succ := eapOf(t, resp)
	want := eap.GenerateAuthenticatorResponse(nt, ntResp, peerChal, authChal, login)
	if succ.Data[0] != eap.OpSuccess || !bytes.HasPrefix(succ.Data[4:], []byte(want)) {
		t.Fatalf("authenticator response %q, want %q", succ.Data[4:], want)
	}

	// 3. Peer acknowledges → Access-Accept with EAP-Success and MPPE keys.
	last := eapRequest(srv, &eap.Packet{Code: eap.CodeResponse, Identifier: succ.Identifier, Type: eap.TypeMSCHAPv2, Data: []byte{eap.OpSuccess}}, state)
	resp = exchange(t, srv, last, srv.AuthAddr)
	if resp.Code != radius.CodeAccessAccept || eapOf(t, resp).Code != eap.CodeSuccess {
		t.Fatalf("expected accept with EAP-Success, got %v", resp.Code)
	}
	wantSend, wantRecv := eap.ServerKeys(nt, ntResp)
	send, err1 := eap.DecryptMPPEKey(msVendor(resp, 16), srv.Secret, last.Authenticator[:])
	recv, err2 := eap.DecryptMPPEKey(msVendor(resp, 17), srv.Secret, last.Authenticator[:])
	if err1 != nil || err2 != nil || !bytes.Equal(send, wantSend) || !bytes.Equal(recv, wantRecv) {
		t.Fatalf("MS-MPPE keys do not match: %v %v", err1, err2)
	}
	if c := rfc2865.Class_GetString(resp); c == "" || c[:3] != "rp-" {
		t.Fatalf("Class %q", c)
	}
	ip := rfc2865.FramedIPAddress_Get(resp)
	if ip == nil || !e.Core.IPAM.Pool(config.IKEv2).Prefix().Contains(mustAddr(ip.String())) {
		t.Fatalf("Framed-IP-Address %v", ip)
	}

	// Wrong password: rejected with EAP-Failure.
	resp = exchange(t, srv, eapRequest(srv, &eap.Packet{Code: eap.CodeResponse, Type: eap.TypeIdentity, Data: []byte(login)}, nil), srv.AuthAddr)
	ch = eapOf(t, resp)
	bad := eap.GenerateNTResponse(ch.Data[5:21], peerChal, login, secret.NTHash("wrong"))
	val = append(append(append([]byte{}, peerChal...), make([]byte, 8)...), bad...)
	body = append([]byte{eap.OpResponse, ch.Data[1], 0, 0, 49}, append(val, 0)...)
	body = append(body, login...)
	body[2], body[3] = byte(len(body)>>8), byte(len(body))
	resp = exchange(t, srv, eapRequest(srv, &eap.Packet{Code: eap.CodeResponse, Identifier: ch.Identifier, Type: eap.TypeMSCHAPv2, Data: body}, rfc2865.State_Get(resp)), srv.AuthAddr)
	if resp.Code != radius.CodeAccessReject || eapOf(t, resp).Code != eap.CodeFailure {
		t.Fatalf("wrong password must be rejected, got %v", resp.Code)
	}
}

func TestMessageAuthenticatorRequired(t *testing.T) {
	_, srv, _ := start(t)
	p := radius.New(radius.CodeAccessRequest, srv.Secret)
	p.Add(79, (&eap.Packet{Code: eap.CodeResponse, Type: eap.TypeIdentity, Data: []byte("x")}).Encode())
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if _, err := radius.Exchange(ctx, p, srv.AuthAddr); err == nil {
		t.Fatal("EAP request without Message-Authenticator must be dropped")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
