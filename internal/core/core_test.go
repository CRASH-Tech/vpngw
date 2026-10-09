package core_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/oidc"
	"vpngw/internal/store"
	"vpngw/internal/testutil"
)

func connect(t *testing.T, e *testutil.Env, proto, login, pw string) *core.Session {
	t.Helper()
	s, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: proto, Login: login, ClientIP: "203.0.113.7"}, pw)
	if err != nil {
		t.Fatalf("connect %s: %v", login, err)
	}
	e.Core.SessionStarted(s.VPNIP, "ref", "203.0.113.7")
	return s
}

func TestConnectPolicy(t *testing.T) {
	e := testutil.NewEnv(t, map[string]string{"SESSION_LIMIT": "2"})
	_, pw := e.Login(t)
	s := connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	if s.Profile.Gateway != "dc1" || len(s.Profile.Allow) != 8 || !e.Core.FW.HasSession(s.VPNIP) {
		t.Fatalf("profile %+v", s.Profile)
	}
	if !e.Core.IPAM.Pool(config.OpenVPN).Prefix().Contains(s.VPNIP) {
		t.Fatalf("address %s not from the OpenVPN pool", s.VPNIP)
	}
	cases := []struct{ login, pw, want string }{
		{"alice@vpn-dc1", "wrong", "invalid username or password"},
		{"alice@vpn-riga", pw, "not available"},
		{"nobody@vpn-dc1", pw, "invalid username or password"},
	}
	for _, c := range cases {
		_, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.AnyConnect, Login: c.login, ClientIP: "203.0.113.7"}, c.pw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.login, err, c.want)
		}
	}
	// Without a group: networks of all groups, never the internet.
	plain := connect(t, e, config.AnyConnect, "alice", pw)
	if plain.Profile.FullTunnel || plain.Profile.Gateway != "" || len(plain.Profile.Allow) == 0 {
		t.Fatalf("plain login profile %+v", plain.Profile)
	}
	for _, a := range plain.Profile.Allow {
		if a.Bits() == 0 {
			t.Fatalf("plain login must not get 0.0.0.0/0: %v", plain.Profile.Allow)
		}
	}
	e.Core.SessionStopped(plain.VPNIP, "test", 0, 0)
	connect(t, e, config.IKEv2, "alice@vpn-internet", pw)
	_, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.AnyConnect, Login: "alice@vpn-internet", ClientIP: "203.0.113.7"}, pw)
	if err == nil || !strings.Contains(err.Error(), "session limit") {
		t.Fatalf("limit: %v", err)
	}
}

func TestBruteForceBlock(t *testing.T) {
	e := testutil.NewEnv(t, map[string]string{"AUTH_FAIL_LIMIT": "3"})
	_, pw := e.Login(t)
	cr := core.Credentials{Protocol: config.OpenVPN, Login: "alice@vpn-dc1", ClientIP: "203.0.113.9"}
	for i := 0; i < 3; i++ {
		_, _ = e.Core.AuthenticatePassword(cr, "bad")
	}
	if _, err := e.Core.AuthenticatePassword(cr, pw); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected block, got %v", err)
	}
	e.Core.Limiter().Unblock("user:alice")
	e.Core.Limiter().Unblock("ip:203.0.113.9")
	if _, err := e.Core.AuthenticatePassword(cr, pw); err != nil {
		t.Fatalf("after unblock: %v", err)
	}
}

func TestReissue(t *testing.T) {
	e := testutil.NewEnv(t, nil)
	u, pw := e.Login(t)
	s := connect(t, e, config.AnyConnect, "alice@vpn-dc1", pw)
	oldSerial := u.TLSKeySerial
	newPw, err := e.Core.ReissuePassword(u.ID, "alice", "")
	if err != nil || newPw == pw {
		t.Fatal(err)
	}
	if e.Backends[config.AnyConnect].Killed() != 1 || e.Core.FW.HasSession(s.VPNIP) {
		t.Fatal("sessions must be terminated")
	}
	if _, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.AnyConnect, Login: "alice@vpn-dc1"}, pw); err == nil {
		t.Fatal("old password must fail")
	}
	if err := e.Core.VerifyTLSMeta(core.TLSMeta(u.ID, oldSerial)); err == nil {
		t.Fatal("old OpenVPN key must be revoked")
	}
	u2, _ := e.Store.UserByID(u.ID)
	if err := e.Core.VerifyTLSMeta(core.TLSMeta(u.ID, u2.TLSKeySerial)); err != nil {
		t.Fatalf("new key: %v", err)
	}
	connect(t, e, config.AnyConnect, "alice@vpn-dc1", newPw)
}

func TestRevalidateRefreshRotatesAndKeepsAccess(t *testing.T) {
	e := testutil.NewEnv(t, nil)
	u, pw := e.Login(t)
	connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	e.Core.RevalidateUser(context.Background(), u.ID)
	u2, _ := e.Store.UserByID(u.ID)
	rt, _ := e.Core.RefreshToken(u2)
	if !strings.HasPrefix(rt, "rt-2") || !u2.HasPassword() || len(e.Core.Sessions()) != 1 {
		t.Fatalf("refresh token not rotated or access lost: %q", rt)
	}
	if left := time.Until(u2.SessionExpiresAt); left < 23*time.Hour || left > 25*time.Hour {
		t.Fatalf("session expiry from refresh_expires_in: %v", u2.SessionExpiresAt)
	}
}

func TestRevalidateRevoked(t *testing.T) {
	e := testutil.NewEnv(t, nil)
	u, pw := e.Login(t)
	connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	// Without a group: networks of all groups, never the internet.
	plain := connect(t, e, config.AnyConnect, "alice", pw)
	if plain.Profile.FullTunnel || plain.Profile.Gateway != "" || len(plain.Profile.Allow) == 0 {
		t.Fatalf("plain login profile %+v", plain.Profile)
	}
	for _, a := range plain.Profile.Allow {
		if a.Bits() == 0 {
			t.Fatalf("plain login must not get 0.0.0.0/0: %v", plain.Profile.Allow)
		}
	}
	e.Core.SessionStopped(plain.VPNIP, "test", 0, 0)
	connect(t, e, config.IKEv2, "alice@vpn-internet", pw)
	e.IdP.Set("invalid_grant", nil)
	e.Core.RevalidateUser(context.Background(), u.ID)
	u2, _ := e.Store.UserByID(u.ID)
	if u2.HasPassword() || u2.Status != store.StatusRevoked || len(e.Core.Sessions()) != 0 {
		t.Fatalf("user must be revoked: %+v, sessions %d", u2.Status, len(e.Core.Sessions()))
	}
	if e.Backends[config.OpenVPN].Killed()+e.Backends[config.IKEv2].Killed() != 2 {
		t.Fatal("all backends must be told to disconnect")
	}
	if _, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.OpenVPN, Login: "alice@vpn-dc1"}, pw); err == nil {
		t.Fatal("password must be annulled")
	}
	// The next portal login issues a new password.
	e.IdP.Set("ok", nil)
	res, err := e.Core.PortalLogin(e.IdP.Identity(), "")
	if err != nil || res.NewPassword == "" || res.NewPassword == pw {
		t.Fatalf("relogin: %v", err)
	}
}

func TestGracePeriod(t *testing.T) {
	e := testutil.NewEnv(t, map[string]string{"OIDC_REVALIDATE_INTERVAL": "5m", "OIDC_GRACE_PERIOD": "15m"})
	u, pw := e.Login(t)
	connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	e.IdP.Set("down", nil)
	e.Core.RevalidateUser(context.Background(), u.ID)
	u2, _ := e.Store.UserByID(u.ID)
	if len(e.Core.Sessions()) != 1 || !u2.HasPassword() || u2.IdPFailSince.IsZero() {
		t.Fatal("sessions must survive within the grace period")
	}
	// A new connection is still accepted while the last check is fresh.
	connect(t, e, config.IKEv2, "alice@vpn-dc1", pw)
	// Simulate the grace period running out.
	u2.LastCheckOKAt = time.Now().Add(-21 * time.Minute)
	_ = e.Store.SaveUser(u2)
	e.Core.RevalidateUser(context.Background(), u.ID)
	if len(e.Core.Sessions()) != 0 {
		t.Fatal("sessions must be terminated after the grace period (fail closed)")
	}
	_, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.OpenVPN, Login: "alice@vpn-dc1"}, pw)
	var de *core.DenyError
	if !errors.As(err, &de) || !strings.Contains(de.Reason, "not verified") {
		t.Fatalf("new connections must be refused: %v", err)
	}
	// The emergency admin works without the IdP.
	if _, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.OpenVPN, Login: "root"}, "emergency-pass"); err != nil {
		t.Fatalf("emergency admin: %v", err)
	}
	// IdP back: access restored without a new password.
	e.IdP.Set("ok", nil)
	e.Core.RevalidateUser(context.Background(), u.ID)
	connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
}

func TestGroupChanges(t *testing.T) {
	e := testutil.NewEnv(t, nil)
	u, pw := e.Login(t)
	lat := connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	inet := connect(t, e, config.AnyConnect, "alice@vpn-internet", pw)

	// Widen vpn-internet? It is already 0/0. Widen vpn-dc1: firewall updated, session kept.
	e.IdP.Set("ok", func(c map[string]any) {
		c["vpn"] = map[string]any{
			"vpn-dc1":      map[string]any{"vpnRoutes": []string{"10.4.0.0/16", "10.6.0.0/16"}, "vpnGateway": "dc1"},
			"vpn-internet": map[string]any{"vpnRoutes": []string{"0.0.0.0/0"}},
		}
	})
	e.Core.RevalidateUser(context.Background(), u.ID)
	s, ok := e.Core.SessionByIP(lat.VPNIP)
	if !ok || !s.RoutesWidened || len(s.Profile.Allow) != 2 {
		t.Fatalf("widened session must stay with the new profile: %+v", s.Profile)
	}
	if !strings.Contains(strings.Join(e.Core.FW.Log, "\n"), "10.6.0.0/16") {
		t.Fatal("firewall must allow the new network immediately")
	}

	// Narrow vpn-dc1 and drop vpn-internet membership: both sessions end.
	e.IdP.Set("ok", func(c map[string]any) {
		c["groups"] = []string{"vpn-dc1"}
		c["vpn"] = map[string]any{"vpn-dc1": map[string]any{"vpnRoutes": []string{"10.4.0.0/24"}, "vpnGateway": "dc1"}}
	})
	e.Core.RevalidateUser(context.Background(), u.ID)
	if _, ok := e.Core.SessionByIP(lat.VPNIP); ok {
		t.Fatal("narrowed session must be terminated")
	}
	if _, ok := e.Core.SessionByIP(inet.VPNIP); ok {
		t.Fatal("session of a removed group must be terminated")
	}
}

func TestBackchannelLogout(t *testing.T) {
	e := testutil.NewEnv(t, nil)
	u, pw := e.Login(t)
	connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	lc, err := e.Core.OIDC.VerifyLogoutToken(context.Background(), e.IdP.LogoutToken("sid-1"))
	if err != nil {
		t.Fatal(err)
	}
	if n := e.Core.BackchannelLogout(lc); n != 1 {
		t.Fatalf("users logged out: %d", n)
	}
	u2, _ := e.Store.UserByID(u.ID)
	if u2.HasPassword() || len(e.Core.Sessions()) != 0 {
		t.Fatal("back-channel logout must revoke access")
	}
	if _, err := e.Core.OIDC.VerifyLogoutToken(context.Background(), "garbage"); err == nil {
		t.Fatal("invalid logout token must be rejected")
	}
}

func TestEmergencyAdmin(t *testing.T) {
	e := testutil.NewEnv(t, map[string]string{"EMERGENCY_ROUTES": "10.0.0.0/8"})
	s, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.IKEv2, Login: "root"}, "emergency-pass")
	if err != nil || !s.Emergency || s.Profile.Allow[0].String() != "10.0.0.0/8" {
		t.Fatalf("emergency: %+v %v", s, err)
	}
	if _, err := e.Core.AuthenticatePassword(core.Credentials{Protocol: config.IKEv2, Login: "root"}, "nope"); err == nil {
		t.Fatal("wrong emergency password must fail")
	}
	if _, err := e.Core.PortalLogin(&oidc.Tokens{Identity: oidc.Identity{Sub: "x", Username: "ROOT"}}, ""); err == nil {
		t.Fatal("IdP user must not take over the emergency name")
	}
}

func TestUserStats(t *testing.T) {
	e := testutil.NewEnv(t, nil)
	_, pw := e.Login(t)
	a := connect(t, e, config.OpenVPN, "alice@vpn-dc1", pw)
	e.Core.SessionStopped(a.VPNIP, "", 1000, 5000)
	b := connect(t, e, config.OpenVPN, "alice@vpn-internet", pw)
	_ = b
	c := connect(t, e, config.AnyConnect, "alice@vpn-dc1", pw)
	e.Core.SessionStopped(c.VPNIP, "", 10, 20)
	stats := e.Core.UserStats()
	if len(stats) != 2 {
		t.Fatalf("stats %+v", stats)
	}
	// Sorted by user, then protocol: anyconnect before openvpn.
	ac, ov := stats[0], stats[1]
	if ac.Protocol != config.AnyConnect || ac.Connections != 1 || ac.BytesIn != 10 || ac.BytesOut != 20 || ac.Active != 0 {
		t.Fatalf("anyconnect %+v", ac)
	}
	if ov.Protocol != config.OpenVPN || ov.Connections != 2 || ov.BytesIn != 1000 || ov.BytesOut != 5000 || ov.Active != 1 || ov.LastConnect.IsZero() {
		t.Fatalf("openvpn %+v", ov)
	}
}
