package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"vpngw/internal/firewall"
	"vpngw/internal/oidc"
	"vpngw/internal/policy"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

func rtAD(userID int64) string { return fmt.Sprintf("rt:%d", userID) }

// IsAdminIdentity reports whether groups contain the admin group.
func (c *Core) IsAdminIdentity(groups []string) bool {
	ag := c.Cfg.Str("ADMIN_GROUP")
	for _, g := range groups {
		if strings.EqualFold(g, ag) {
			return true
		}
	}
	return false
}

// LoginResult is returned after a successful portal login.
type LoginResult struct {
	User        *store.User
	NewPassword string // set when a password was issued during this login
}

// PortalLogin records an OIDC login, stores the refresh token and issues
// a VPN password on first login (or when the previous one was revoked or
// the IdP session changed).
func (c *Core) PortalLogin(tok *oidc.Tokens, ip string) (*LoginResult, error) {
	id := tok.Identity
	if c.IsEmergency(id.Username) {
		return nil, fmt.Errorf("the user name %q is reserved for the local emergency administrator", id.Username)
	}
	u, err := c.Store.UserBySub(id.Sub)
	if err != nil && !store.IsNotFound(err) {
		return nil, err
	}
	if u == nil {
		u = &store.User{Sub: id.Sub, Status: store.StatusNone}
	}
	prevGroups, prevClaim := u.Groups, u.VPNClaim
	c.applyIdentity(u, &id)
	now := time.Now()
	u.LastLoginAt = now
	u.LastCheckAt, u.LastCheckOKAt = now, now
	u.LastCheckError = ""
	u.IdPFailSince = time.Time{}
	if !id.AuthTime.IsZero() {
		u.AuthTime = id.AuthTime
	} else {
		u.AuthTime = now
	}
	sidChanged := id.SID != "" && u.OIDCSID != "" && id.SID != u.OIDCSID
	if u.OIDCSID == "" || sidChanged || u.SessionCreatedAt.IsZero() {
		u.SessionCreatedAt = now
	}
	if id.SID != "" {
		u.OIDCSID = id.SID
	}
	if err := c.Store.SaveUser(u); err != nil {
		return nil, err
	}
	u.RefreshToken = c.Box.Seal([]byte(tok.RefreshToken), rtAD(u.ID))
	u.SessionExpiresAt = c.sessionExpiry(tok, time.Time{}, true)
	res := &LoginResult{User: u}
	// A password is valid while the IdP session lives. A login with a new
	// IdP session keeps the existing password: the old session is replaced
	// by the new refresh token, so revalidation follows the new session.
	if !u.HasPassword() {
		pw, err := c.issuePassword(u)
		if err != nil {
			return nil, err
		}
		res.NewPassword = pw
		c.Audit("info", "password.issued", u.Username, u.Username, "", ip, "VPN password issued at portal login")
	}
	if err := c.Store.SaveUser(u); err != nil {
		return nil, err
	}
	c.Audit("info", "portal.login", u.Username, u.Username, "", ip, fmt.Sprintf("portal login (groups: %s)", strings.Join(u.Groups, ", ")))
	go c.SyncProfiles()
	if strings.Join(prevGroups, ",") != strings.Join(u.Groups, ",") || prevClaim != u.VPNClaim {
		c.applyPolicyChange(u)
	}
	return res, nil
}

func (c *Core) applyIdentity(u *store.User, id *oidc.Identity) {
	u.Username = id.Username
	u.Email = id.Email
	u.Name = id.Name
	u.Groups = id.Groups
	u.VPNClaim = string(id.RoutesClaim)
	u.IsAdmin = c.IsAdminIdentity(id.Groups)
}

// issuePassword derives a new password and stores its hashes. The caller saves the user.
func (c *Core) issuePassword(u *store.User) (string, error) {
	nonce := secret.RandomBytes(16)
	sid := u.OIDCSID
	if sid == "" {
		sid = u.Sub
	}
	pw := secret.DerivePassword(c.Master, sid, u.SessionCreatedAt, nonce)
	seed, _ := json.Marshal(pwSeed{SID: sid, Created: u.SessionCreatedAt.UnixNano(), Nonce: nonce})
	u.PwSeed = c.Box.Seal(seed, seedAD(u.ID))
	u.PwHash = secret.HashPassword(pw)
	u.NTHash = c.Box.Seal(secret.NTHash(pw), ntAD(u.ID))
	u.PwIssuedAt = time.Now()
	u.Status = store.StatusActive
	if u.TLSKeySerial > 0 {
		if err := c.Store.RevokeTLSKey(u.ID, u.TLSKeySerial); err != nil {
			return "", err
		}
	}
	u.TLSKeySerial = time.Now().UnixNano()
	return pw, nil
}

type pwSeed struct {
	SID     string `json:"s"`
	Created int64  `json:"c"`
	Nonce   []byte `json:"n"`
}

func seedAD(userID int64) string { return fmt.Sprintf("pwseed:%d", userID) }

// RevealPassword re-derives the current password for display on the portal.
func (c *Core) RevealPassword(u *store.User) (string, error) {
	if !u.HasPassword() || len(u.PwSeed) == 0 {
		return "", fmt.Errorf("no password")
	}
	raw, err := c.Box.Open(u.PwSeed, seedAD(u.ID))
	if err != nil {
		return "", err
	}
	var s pwSeed
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	pw := secret.DerivePassword(c.Master, s.SID, time.Unix(0, s.Created), s.Nonce)
	if !secret.VerifyPassword(u.PwHash, pw) {
		return "", fmt.Errorf("password seed does not match")
	}
	return pw, nil
}

// ReissuePassword replaces the password, revokes the old one and drops sessions.
func (c *Core) ReissuePassword(userID int64, actor, ip string) (string, error) {
	u, err := c.Store.UserByID(userID)
	if err != nil {
		return "", err
	}
	n := c.DisconnectUser(u.ID, false, "password reissued", "")
	pw, err := c.issuePassword(u)
	if err != nil {
		return "", err
	}
	if err := c.Store.SaveUser(u); err != nil {
		return "", err
	}
	c.Audit("info", "password.reissued", actor, u.Username, "", ip, fmt.Sprintf("VPN password reissued, %d session(s) terminated", n))
	return pw, nil
}

// RevokeUser annuls the password and terminates every session.
func (c *Core) RevokeUser(userID int64, reason, actor string) error {
	u, err := c.Store.UserByID(userID)
	if err != nil {
		return err
	}
	n := c.DisconnectUser(u.ID, false, reason, "")
	if u.TLSKeySerial > 0 {
		_ = c.Store.RevokeTLSKey(u.ID, u.TLSKeySerial)
	}
	u.Status = store.StatusRevoked
	u.PwHash = ""
	u.PwSeed = nil
	u.NTHash = nil
	u.RefreshToken = nil
	if err := c.Store.SaveUser(u); err != nil {
		return err
	}
	_ = c.Store.DeleteUserWebSessions(u.ID)
	c.Audit("warn", "user.revoked", actor, u.Username, "", "", fmt.Sprintf("access revoked: %s; %d session(s) terminated", reason, n))
	go c.SyncProfiles()
	return nil
}

// sessionExpiry returns when the IdP session behind tok ends: from the token
// response, else (when the refresh token changed or nothing is known yet)
// from introspection, else the previous value.
func (c *Core) sessionExpiry(tok *oidc.Tokens, prev time.Time, rtChanged bool) time.Time {
	if !tok.RefreshExpiry.IsZero() {
		return tok.RefreshExpiry
	}
	if !rtChanged && !prev.IsZero() {
		return prev
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exp, err := c.OIDC.RefreshTokenExpiry(ctx, tok.RefreshToken)
	if err != nil {
		slog.Debug("refresh token introspection", "err", err)
		return prev
	}
	return exp
}

// RefreshToken decrypts the stored refresh token.
func (c *Core) RefreshToken(u *store.User) (string, error) {
	if len(u.RefreshToken) == 0 {
		return "", fmt.Errorf("no refresh token")
	}
	b, err := c.Box.Open(u.RefreshToken, rtAD(u.ID))
	return string(b), err
}

// --- OpenVPN tls-crypt-v2 client key metadata ---

// TLSMeta returns the metadata embedded in a user's tls-crypt-v2 key.
func TLSMeta(userID, serial int64) string {
	return fmt.Sprintf("vpngw:%d:%d", userID, serial)
}

// EmergencyTLSSerial returns (creating) the serial of the emergency admin key.
func (c *Core) EmergencyTLSSerial(rotate bool) int64 {
	if !rotate {
		if b, err := c.Store.GetKV("emergency_tls_serial"); err == nil {
			if n, err := strconv.ParseInt(string(b), 10, 64); err == nil {
				return n
			}
		}
	}
	n := time.Now().UnixNano()
	_ = c.Store.PutKV("emergency_tls_serial", []byte(strconv.FormatInt(n, 10)))
	return n
}

// VerifyTLSMeta accepts only the current, non-revoked key of an active user.
func (c *Core) VerifyTLSMeta(meta string) error {
	parts := strings.Split(strings.TrimSpace(meta), ":")
	if len(parts) != 3 || parts[0] != "vpngw" {
		return fmt.Errorf("unknown key metadata")
	}
	uid, err1 := strconv.ParseInt(parts[1], 10, 64)
	serial, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("malformed key metadata")
	}
	if uid == 0 {
		if serial != c.EmergencyTLSSerial(false) {
			return fmt.Errorf("emergency key revoked")
		}
		return nil
	}
	if revoked, err := c.Store.TLSKeyRevoked(uid, serial); err != nil || revoked {
		return fmt.Errorf("key revoked")
	}
	u, err := c.Store.UserByID(uid)
	if err != nil {
		return fmt.Errorf("unknown user")
	}
	if !u.HasPassword() || u.TLSKeySerial != serial {
		return fmt.Errorf("key not current")
	}
	return nil
}

// applyPolicyChange recomputes profiles of live sessions after the user's
// groups or routes changed: firewall is updated immediately, sessions whose
// access shrank (or whose group disappeared) are terminated.
func (c *Core) applyPolicyChange(u *store.User) {
	for _, s := range c.UserSessions(u.ID, false) {
		newP, err := c.ProfileFor(u, s.Group)
		if err != nil {
			_ = c.Disconnect(s.VPNIP, "group access removed: "+err.Error(), "")
			continue
		}
		if newP.ID == s.Profile.ID {
			continue
		}
		if !policy.Covers(newP.Allow, s.Profile.Allow) || newP.Gateway != s.Profile.Gateway {
			c.Audit("info", "policy.narrowed", "", u.Username, s.Protocol, s.ClientIP,
				fmt.Sprintf("routes changed (%s → %s), session terminated", s.Profile.ID, newP.ID))
			_ = c.Disconnect(s.VPNIP, "access narrowed", "")
			continue
		}
		// Access widened: enforce the new profile now; clients get the new
		// routes when they reconnect.
		if pp, ok := c.Backend(s.Protocol).(ProfilePreparer); ok {
			if err := pp.PrepareProfile(newP); err != nil {
				slog.Warn("prepare profile", "err", err)
			}
		}
		if err := c.updateSessionProfile(s.VPNIP, newP); err != nil {
			slog.Error("update session profile", "err", err)
			continue
		}
		c.Audit("info", "policy.widened", "", u.Username, s.Protocol, s.ClientIP,
			fmt.Sprintf("routes widened (%s → %s), new routes apply after reconnect", s.Profile.ID, newP.ID))
	}
}

func (c *Core) updateSessionProfile(ip netip.Addr, p *policy.Profile) error {
	c.mu.Lock()
	s, ok := c.sessions[ip]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	s.Profile = p
	s.RoutesWidened = true
	c.mu.Unlock()
	return c.FW.AddSession(firewall.Session{IP: ip, Profile: p.ID, Allow: p.Allow, Gateway: p.Gateway})
}

// EmergencyPolicyChanged re-evaluates sessions of the emergency admin
// after EMERGENCY_ROUTES or EMERGENCY_GATEWAY changed.
func (c *Core) EmergencyPolicyChanged() {
	defer c.SyncProfiles()
	p, err := c.ProfileFor(nil, "")
	for _, s := range c.UserSessions(0, true) {
		if err != nil || !policy.Covers(p.Allow, s.Profile.Allow) || p.Gateway != s.Profile.Gateway {
			_ = c.Disconnect(s.VPNIP, "emergency routes changed", "")
		} else if p.ID != s.Profile.ID {
			_ = c.updateSessionProfile(s.VPNIP, p)
		}
	}
}

// ClaimJSON pretty-prints a raw claim for display.
func ClaimJSON(raw string) string {
	if raw == "" {
		return ""
	}
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
