// Package radius is the gateway's built-in RADIUS server. ocserv uses it
// with PAP, strongSwan with EAP-MSCHAPv2; both send accounting. It listens
// on 127.0.0.1 only.
package radius

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
	"layeh.com/radius/rfc2869"

	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/eap"
	"vpngw/internal/policy"
	"vpngw/internal/secret"
)

// NAS identifiers configured in the backends.
const (
	NASAnyConnect = "vpngw-anyconnect"
	NASIKEv2      = "vpngw-ikev2"
)

const (
	attrMessageAuthenticator = 80
	attrEAPMessage           = 79
	vendorMicrosoft          = 311
	msMPPESendKey            = 16
	msMPPERecvKey            = 17
	msPrimaryDNS             = 28
	msSecondaryDNS           = 29
)

// Server serves authentication and accounting.
type Server struct {
	Core     *core.Core
	Secret   []byte
	AuthAddr string
	AcctAddr string
	// ServerName is sent in MS-CHAPv2 challenges.
	ServerName string

	mu    sync.Mutex
	convs map[string]*conversation

	auth, acct *radius.PacketServer
}

type conversation struct {
	login     string
	clientIP  string
	challenge []byte
	eapID     byte
	msID      byte
	created   time.Time
	session   *core.Session
	ntHash    []byte
	ntResp    []byte
	accepted  bool
}

// New creates a server with a random shared secret.
func New(c *core.Core) *Server {
	return &Server{
		Core:       c,
		Secret:     []byte(secret.RandomToken(24)),
		AuthAddr:   "127.0.0.1:1812",
		AcctAddr:   "127.0.0.1:1813",
		ServerName: "vpngw",
		convs:      map[string]*conversation{},
	}
}

// Start begins serving; it returns once both sockets are bound.
func (s *Server) Start(ctx context.Context) error {
	src := radius.StaticSecretSource(s.Secret)
	quiet := log.New(&slogWriter{}, "", 0)
	s.auth = &radius.PacketServer{SecretSource: src, Handler: radius.HandlerFunc(s.handleAuth), ErrorLog: quiet}
	s.acct = &radius.PacketServer{SecretSource: src, Handler: radius.HandlerFunc(s.handleAcct), ErrorLog: quiet}
	for _, x := range []struct {
		srv  *radius.PacketServer
		addr *string
	}{{s.auth, &s.AuthAddr}, {s.acct, &s.AcctAddr}} {
		conn, err := net.ListenPacket("udp", *x.addr)
		if err != nil {
			return fmt.Errorf("radius listen %s: %w", *x.addr, err)
		}
		*x.addr = conn.LocalAddr().String()
		go func(srv *radius.PacketServer, conn net.PacketConn) {
			if err := srv.Serve(conn); err != nil && !errors.Is(err, radius.ErrServerShutdown) {
				slog.Error("radius server stopped", "err", err)
			}
		}(x.srv, conn)
	}
	go s.gcLoop(ctx)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.auth.Shutdown(sctx)
		_ = s.acct.Shutdown(sctx)
	}()
	return nil
}

type slogWriter struct{}

func (slogWriter) Write(p []byte) (int, error) {
	slog.Debug(strings.TrimSpace(string(p)), "component", "radius")
	return len(p), nil
}

func (s *Server) gcLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		for k, c := range s.convs {
			if time.Since(c.created) > 2*time.Minute {
				delete(s.convs, k)
			}
		}
		s.mu.Unlock()
	}
}

func protocolOf(p *radius.Packet) string {
	switch rfc2865.NASIdentifier_GetString(p) {
	case NASIKEv2:
		return config.IKEv2
	case NASAnyConnect:
		return config.AnyConnect
	}
	if hasEAP(p) {
		return config.IKEv2
	}
	return config.AnyConnect
}

// clientIP extracts the address from Calling-Station-Id ("1.2.3.4",
// "1.2.3.4[4500]" or "1.2.3.4:4500").
func clientIP(p *radius.Packet) string {
	s := rfc2865.CallingStationID_GetString(p)
	if i := strings.IndexByte(s, '['); i > 0 {
		s = s[:i]
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

func hasEAP(p *radius.Packet) bool {
	_, ok := p.Lookup(attrEAPMessage)
	return ok
}

func eapMessage(p *radius.Packet) []byte {
	var b []byte
	for _, a := range p.Attributes {
		if a.Type == attrEAPMessage {
			b = append(b, a.Attribute...)
		}
	}
	return b
}

// verifyMessageAuthenticator checks the request's Message-Authenticator.
// It is mandatory for EAP (RFC 3579) and verified whenever present.
func (s *Server) verifyMessageAuthenticator(p *radius.Packet, required bool) bool {
	ma, ok := p.Lookup(attrMessageAuthenticator)
	if !ok {
		return !required
	}
	if len(ma) != 16 {
		return false
	}
	raw, err := p.MarshalBinary()
	if err != nil {
		return false
	}
	// Zero the attribute value in the raw packet.
	off := 20
	for off+2 <= len(raw) {
		t, l := raw[off], int(raw[off+1])
		if l < 2 || off+l > len(raw) {
			return false
		}
		if t == attrMessageAuthenticator {
			for i := off + 2; i < off+l; i++ {
				raw[i] = 0
			}
		}
		off += l
	}
	return hmac.Equal(eap.MessageAuthenticator(raw, s.Secret), ma)
}

// write signs a response with Message-Authenticator and sends it.
func (s *Server) write(w radius.ResponseWriter, resp *radius.Packet) {
	resp.Attributes.Del(attrMessageAuthenticator)
	resp.Add(attrMessageAuthenticator, make([]byte, 16))
	raw, err := resp.MarshalBinary()
	if err != nil {
		slog.Error("radius marshal", "err", err)
		return
	}
	resp.Set(attrMessageAuthenticator, eap.MessageAuthenticator(raw, s.Secret))
	if err := w.Write(resp); err != nil {
		slog.Error("radius write", "err", err)
	}
}

func (s *Server) handleAuth(w radius.ResponseWriter, r *radius.Request) {
	p := r.Packet
	if p.Code != radius.CodeAccessRequest {
		return
	}
	isEAP := hasEAP(p)
	if !s.verifyMessageAuthenticator(p, isEAP) {
		slog.Warn("radius: bad Message-Authenticator, request dropped")
		return
	}
	if isEAP {
		s.handleEAP(w, p)
		return
	}
	s.handlePAP(w, p)
}

func (s *Server) handlePAP(w radius.ResponseWriter, p *radius.Packet) {
	proto := protocolOf(p)
	login := rfc2865.UserName_GetString(p)
	pw := rfc2865.UserPassword_GetString(p)
	cr := core.Credentials{Protocol: proto, Login: login, ClientIP: clientIP(p)}
	sess, err := s.Core.AuthenticatePassword(cr, pw)
	if err != nil {
		resp := p.Response(radius.CodeAccessReject)
		_ = rfc2865.ReplyMessage_SetString(resp, rejectMessage(err))
		s.write(w, resp)
		return
	}
	resp := p.Response(radius.CodeAccessAccept)
	s.addSessionAttrs(resp, sess, proto)
	s.write(w, resp)
}

func rejectMessage(err error) string {
	var de *core.DenyError
	if errors.As(err, &de) {
		return de.Reason
	}
	return "authentication failed"
}

// addSessionAttrs adds address, routes and DNS to an Access-Accept.
func (s *Server) addSessionAttrs(resp *radius.Packet, sess *core.Session, proto string) {
	_ = rfc2865.FramedIPAddress_Set(resp, net.IP(sess.VPNIP.AsSlice()))
	_ = rfc2865.ServiceType_Set(resp, rfc2865.ServiceType_Value_FramedUser)
	_ = rfc2869.AcctInterimInterval_Set(resp, 60)
	prof := sess.Profile
	if proto == config.AnyConnect {
		if pool := s.Core.IPAM.Pool(proto); pool != nil {
			mask := net.CIDRMask(pool.Prefix().Bits(), 32)
			_ = rfc2865.FramedIPNetmask_Set(resp, net.IP(mask))
		}
		// Routes travel as Framed-Route attributes of one RADIUS packet
		// (4096 bytes); keep them within 3000.
		routes, widened := policy.WidenTo(prof.Routes(), s.Core.Cfg.Int("ANYCONNECT_ROUTE_LIMIT"), 3000)
		if widened {
			slog.Warn("AnyConnect route limit exceeded, routes widened", "profile", prof.ID, "routes", len(prof.Routes()), "limit", len(routes))
		}
		for _, rt := range routes {
			_ = rfc2865.FramedRoute_AddString(resp, rt.String())
		}
	} else {
		_ = rfc2865.Class_AddString(resp, prof.ID)
	}
	for i, d := range prof.DNS {
		if i > 1 {
			break
		}
		typ := byte(msPrimaryDNS)
		if i == 1 {
			typ = msSecondaryDNS
		}
		addMS(resp, typ, d.AsSlice())
	}
}

func addMS(p *radius.Packet, typ byte, value []byte) {
	v := make([]byte, 2+len(value))
	v[0] = typ
	v[1] = byte(len(v))
	copy(v[2:], value)
	vsa, err := radius.NewVendorSpecific(vendorMicrosoft, v)
	if err == nil {
		p.Add(rfc2865.VendorSpecific_Type, vsa)
	}
}

// --- EAP-MSCHAPv2 ---

func (s *Server) handleEAP(w radius.ResponseWriter, p *radius.Packet) {
	msg, err := eap.Parse(eapMessage(p))
	if err != nil || msg.Code != eap.CodeResponse {
		s.eapReject(w, p, 0, nil)
		return
	}
	state := rfc2865.State_Get(p)
	s.mu.Lock()
	conv := s.convs[string(state)]
	s.mu.Unlock()

	switch {
	case msg.Type == eap.TypeIdentity:
		s.eapIdentity(w, p, msg)
	case conv == nil:
		s.eapReject(w, p, msg.Identifier, nil)
	case msg.Type == eap.TypeNak:
		slog.Warn("EAP peer refused MSCHAPv2", "login", conv.login)
		s.eapReject(w, p, msg.Identifier, conv)
	case msg.Type == eap.TypeMSCHAPv2 && len(msg.Data) > 0 && msg.Data[0] == eap.OpResponse:
		s.eapResponse(w, p, msg, conv, state)
	case msg.Type == eap.TypeMSCHAPv2 && len(msg.Data) > 0 && msg.Data[0] == eap.OpSuccess:
		s.eapSuccess(w, p, msg, conv, state)
	default:
		s.eapReject(w, p, msg.Identifier, conv)
	}
}

func (s *Server) eapIdentity(w radius.ResponseWriter, p *radius.Packet, msg *eap.Packet) {
	login := strings.TrimSpace(string(msg.Data))
	if login == "" {
		login = rfc2865.UserName_GetString(p)
	}
	conv := &conversation{
		login:     login,
		clientIP:  clientIP(p),
		challenge: secret.RandomBytes(16),
		eapID:     msg.Identifier + 1,
		msID:      msg.Identifier + 1,
		created:   time.Now(),
	}
	state := secret.RandomBytes(16)
	s.mu.Lock()
	s.convs[string(state)] = conv
	s.mu.Unlock()
	resp := p.Response(radius.CodeAccessChallenge)
	req := eap.ChallengeRequest(conv.eapID, conv.msID, conv.challenge, s.ServerName)
	for _, chunk := range eap.SplitEAPMessage(req.Encode()) {
		resp.Add(attrEAPMessage, chunk)
	}
	_ = rfc2865.State_Set(resp, state)
	s.write(w, resp)
}

func (s *Server) eapResponse(w radius.ResponseWriter, p *radius.Packet, msg *eap.Packet, conv *conversation, state []byte) {
	r, err := eap.ParseResponse(msg.Data)
	if err != nil || r.MSID != conv.msID {
		s.eapReject(w, p, msg.Identifier, conv)
		return
	}
	cr := core.Credentials{Protocol: config.IKEv2, Login: conv.login, ClientIP: conv.clientIP}
	if conv.session != nil {
		// Retransmission after we already authorized: repeat the success request.
		s.sendSuccessRequest(w, p, conv, state, msg.Identifier)
		return
	}
	principal, nt, err := s.Core.NTHashFor(cr)
	if err == nil {
		expected := eap.GenerateNTResponse(conv.challenge, r.PeerChallenge, r.Name, nt)
		if !hmac.Equal(expected, r.NTResponse) {
			err = &core.DenyError{Reason: "invalid username or password", BadCredentials: true}
		}
	}
	var sess *core.Session
	if err == nil {
		sess, err = s.Core.Authorize(cr, principal)
	}
	if err != nil {
		s.Core.RecordFailure(cr, err)
		s.eapReject(w, p, msg.Identifier, conv)
		return
	}
	conv.session = sess
	conv.ntHash = nt
	conv.ntResp = r.NTResponse
	conv.eapID = msg.Identifier + 1
	authResp := eap.GenerateAuthenticatorResponse(nt, r.NTResponse, r.PeerChallenge, conv.challenge, r.Name)
	conv.challenge = append(conv.challenge, []byte(authResp)...) // keep for retransmits
	s.sendSuccessRequest(w, p, conv, state, msg.Identifier)
}

func (s *Server) sendSuccessRequest(w radius.ResponseWriter, p *radius.Packet, conv *conversation, state []byte, _ byte) {
	authResp := string(conv.challenge[16:])
	resp := p.Response(radius.CodeAccessChallenge)
	req := eap.SuccessRequest(conv.eapID, conv.msID, authResp)
	for _, chunk := range eap.SplitEAPMessage(req.Encode()) {
		resp.Add(attrEAPMessage, chunk)
	}
	_ = rfc2865.State_Set(resp, state)
	s.write(w, resp)
}

func (s *Server) eapSuccess(w radius.ResponseWriter, p *radius.Packet, msg *eap.Packet, conv *conversation, state []byte) {
	if conv.session == nil {
		s.eapReject(w, p, msg.Identifier, conv)
		return
	}
	resp := p.Response(radius.CodeAccessAccept)
	succ := &eap.Packet{Code: eap.CodeSuccess, Identifier: msg.Identifier}
	resp.Add(attrEAPMessage, succ.Encode())
	_ = rfc2865.UserName_SetString(resp, conv.login)
	send, recv := eap.ServerKeys(conv.ntHash, conv.ntResp)
	var salt [2]byte
	copy(salt[:], secret.RandomBytes(2))
	addMS(resp, msMPPESendKey, eap.EncryptMPPEKey(send, s.Secret, p.Authenticator[:], salt))
	salt[1]++
	addMS(resp, msMPPERecvKey, eap.EncryptMPPEKey(recv, s.Secret, p.Authenticator[:], salt))
	s.addSessionAttrs(resp, conv.session, config.IKEv2)
	conv.accepted = true
	s.write(w, resp)
	s.mu.Lock()
	delete(s.convs, string(state))
	s.mu.Unlock()
}

func (s *Server) eapReject(w radius.ResponseWriter, p *radius.Packet, id byte, conv *conversation) {
	resp := p.Response(radius.CodeAccessReject)
	fail := &eap.Packet{Code: eap.CodeFailure, Identifier: id}
	resp.Add(attrEAPMessage, fail.Encode())
	s.write(w, resp)
	if conv != nil {
		s.mu.Lock()
		for k, c := range s.convs {
			if c == conv {
				delete(s.convs, k)
			}
		}
		s.mu.Unlock()
	}
}

// --- accounting ---

func (s *Server) handleAcct(w radius.ResponseWriter, r *radius.Request) {
	p := r.Packet
	if p.Code != radius.CodeAccountingRequest {
		return
	}
	// Accounting requests are authenticated by the request authenticator
	// (verified by the library); answer first, then process.
	resp := p.Response(radius.CodeAccountingResponse)
	if err := w.Write(resp); err != nil {
		slog.Warn("radius acct write", "err", err)
	}
	ipAttr := rfc2865.FramedIPAddress_Get(p)
	if ipAttr == nil {
		return
	}
	ip, ok := netip.AddrFromSlice(ipAttr.To4())
	if !ok {
		return
	}
	in := uint64(rfc2866.AcctInputOctets_Get(p)) | uint64(rfc2869.AcctInputGigawords_Get(p))<<32
	out := uint64(rfc2866.AcctOutputOctets_Get(p)) | uint64(rfc2869.AcctOutputGigawords_Get(p))<<32
	switch rfc2866.AcctStatusType_Get(p) {
	case rfc2866.AcctStatusType_Value_Start:
		s.Core.SessionStarted(ip, "", clientIP(p))
	case rfc2866.AcctStatusType_Value_Stop:
		reason := ""
		if c := rfc2866.AcctTerminateCause_Get(p); c != 0 {
			reason = terminateCause(c)
		}
		s.Core.SessionStopped(ip, reason, in, out)
	case rfc2866.AcctStatusType_Value_InterimUpdate:
		// Counters are polled from the backends; interim updates only
		// confirm the session is alive.
	}
}

func terminateCause(c rfc2866.AcctTerminateCause) string {
	switch c {
	case rfc2866.AcctTerminateCause_Value_UserRequest:
		return "user request"
	case rfc2866.AcctTerminateCause_Value_LostCarrier:
		return "lost carrier"
	case rfc2866.AcctTerminateCause_Value_IdleTimeout:
		return "idle timeout"
	case rfc2866.AcctTerminateCause_Value_SessionTimeout:
		return "session timeout"
	case rfc2866.AcctTerminateCause_Value_AdminReset:
		return "admin reset"
	case rfc2866.AcctTerminateCause_Value_NASRequest:
		return "NAS request"
	}
	return fmt.Sprintf("terminate cause %d", c)
}
