package core

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"vpngw/internal/config"
	"vpngw/internal/firewall"
	"vpngw/internal/policy"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

// DenyError is an authorization refusal with a reason safe to log.
type DenyError struct {
	Reason string
	// BadCredentials marks failures that count towards brute-force limits.
	BadCredentials bool
}

func (e *DenyError) Error() string { return e.Reason }

func deny(format string, a ...any) error { return &DenyError{Reason: fmt.Sprintf(format, a...)} }

var errBadCredentials = &DenyError{Reason: "invalid username or password", BadCredentials: true}

// Credentials identify a user for a VPN connection.
type Credentials struct {
	Protocol string
	Login    string // user[@group]
	ClientIP string
}

// Principal is the authenticated identity behind a login.
type Principal struct {
	User      *store.User // nil for the emergency admin
	Username  string
	Group     string
	Emergency bool
}

func (c *Core) checkBlocked(cr Credentials) error {
	user, _ := policy.SplitLogin(cr.Login)
	for _, key := range []string{"user:" + strings.ToLower(user), "ip:" + cr.ClientIP} {
		if key == "ip:" {
			continue
		}
		if blocked, until := c.limiter.Blocked(key); blocked {
			return deny("too many failed attempts, blocked until %s", until.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// RecordFailure counts a failed login and audits the refusal.
func (c *Core) RecordFailure(cr Credentials, err error) {
	user, _ := policy.SplitLogin(cr.Login)
	var de *DenyError
	if errors.As(err, &de) && de.BadCredentials {
		for _, key := range []string{"user:" + strings.ToLower(user), "ip:" + cr.ClientIP} {
			if key == "ip:" {
				continue
			}
			if c.limiter.Fail(key) {
				c.Audit("warn", "auth.blocked", "", user, cr.Protocol, cr.ClientIP,
					fmt.Sprintf("blocked %s for %s after repeated failures", key, c.Cfg.Dur("AUTH_BLOCK_DURATION")))
			}
		}
	}
	c.Audit("warn", "vpn.denied", "", user, cr.Protocol, cr.ClientIP, "connection denied: "+err.Error())
}

func (c *Core) recordSuccess(cr Credentials) {
	user, _ := policy.SplitLogin(cr.Login)
	c.limiter.Success("user:" + strings.ToLower(user))
}

// resolvePrincipal finds the account behind a login without checking the password.
func (c *Core) resolvePrincipal(login string) (*Principal, error) {
	user, group := policy.SplitLogin(login)
	if user == "" {
		return nil, errBadCredentials
	}
	if c.IsEmergency(user) {
		return &Principal{Username: c.Cfg.Str("EMERGENCY_USER"), Group: group, Emergency: true}, nil
	}
	u, err := c.Store.UserByUsername(user)
	if err != nil {
		if store.IsNotFound(err) {
			return nil, errBadCredentials
		}
		return nil, err
	}
	return &Principal{User: u, Username: u.Username, Group: group}, nil
}

// VerifyPassword checks a plaintext password (PAP, OpenVPN).
func (c *Core) VerifyPassword(cr Credentials, password string) (*Principal, error) {
	if err := c.checkBlocked(cr); err != nil {
		return nil, err
	}
	p, err := c.resolvePrincipal(cr.Login)
	if err != nil {
		return nil, err
	}
	if p.Emergency {
		if !c.CheckEmergencyPassword(password) {
			return nil, errBadCredentials
		}
		return p, nil
	}
	if !p.User.HasPassword() {
		// Burn comparable time to avoid user enumeration.
		secret.VerifyPassword("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE", password)
		return nil, errBadCredentials
	}
	if !secret.VerifyPassword(p.User.PwHash, password) {
		return nil, errBadCredentials
	}
	return p, nil
}

// NTHashFor returns the NT hash of the password behind a login (MS-CHAPv2).
func (c *Core) NTHashFor(cr Credentials) (*Principal, []byte, error) {
	if err := c.checkBlocked(cr); err != nil {
		return nil, nil, err
	}
	p, err := c.resolvePrincipal(cr.Login)
	if err != nil {
		return nil, nil, err
	}
	if p.Emergency {
		return p, c.emergencyNT, nil
	}
	if !p.User.HasPassword() || len(p.User.NTHash) == 0 {
		return nil, nil, errBadCredentials
	}
	nt, err := c.Box.Open(p.User.NTHash, ntAD(p.User.ID))
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt NT hash: %w", err)
	}
	return p, nt, nil
}

func ntAD(userID int64) string { return fmt.Sprintf("nt:%d", userID) }

// Authorize checks policy for an authenticated principal and reserves a
// session: address, firewall entry and (for IKEv2) the backend profile.
func (c *Core) Authorize(cr Credentials, p *Principal) (*Session, error) {
	if !c.protocolEnabled(cr.Protocol) {
		return nil, deny("protocol %s is disabled", cr.Protocol)
	}
	var prof *policy.Profile
	var err error
	if p.Emergency {
		prof, err = c.ProfileFor(nil, p.Group)
		if err != nil {
			return nil, deny("emergency admin: %v", err)
		}
	} else {
		u := p.User
		if !u.HasPassword() {
			return nil, errBadCredentials
		}
		maxAge := c.Cfg.Dur("OIDC_REVALIDATE_INTERVAL") + c.Cfg.Dur("OIDC_GRACE_PERIOD")
		if u.LastCheckOKAt.IsZero() || time.Since(u.LastCheckOKAt) > maxAge {
			return nil, deny("identity provider session not verified since %s", fmtTime(u.LastCheckOKAt))
		}
		prof, err = c.ProfileFor(u, p.Group)
		if err != nil {
			return nil, deny("%v", err)
		}
	}
	for _, w := range prof.Warnings {
		slog.Warn("route profile warning", "user", p.Username, "profile", prof.ID, "warning", w)
	}
	if limit := c.Cfg.Int("SESSION_LIMIT"); limit > 0 {
		if n := c.countSessions(p); n >= limit {
			return nil, deny("session limit reached (%d of %d)", n, limit)
		}
	}
	if pp, ok := c.Backend(cr.Protocol).(ProfilePreparer); ok {
		if err := pp.PrepareProfile(prof); err != nil {
			return nil, fmt.Errorf("prepare profile: %w", err)
		}
	}
	pool := c.IPAM.Pool(cr.Protocol)
	if pool == nil {
		return nil, deny("no address pool for %s", cr.Protocol)
	}
	ip, err := pool.Allocate(cr.Protocol + ":" + cr.Login)
	if err != nil {
		return nil, deny("%v", err)
	}
	s := &Session{
		Username: p.Username, Login: cr.Login, Group: prof.Group, Emergency: p.Emergency, Protocol: cr.Protocol,
		VPNIP: ip, ClientIP: cr.ClientIP, Profile: prof, State: StatePending, CreatedAt: time.Now(),
	}
	if p.User != nil {
		s.UserID, s.Email = p.User.ID, p.User.Email
	}
	if err := c.FW.AddSession(firewall.Session{IP: ip, Profile: prof.ID, Allow: prof.Allow, Gateway: prof.Gateway}); err != nil {
		pool.Release(ip)
		return nil, fmt.Errorf("firewall: %w", err)
	}
	c.mu.Lock()
	c.sessions[ip] = s
	c.mu.Unlock()
	c.recordSuccess(cr)
	return s, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func (c *Core) protocolEnabled(proto string) bool {
	if !c.Cfg.VPNEnabled() {
		return false
	}
	switch proto {
	case config.AnyConnect:
		return c.Cfg.Bool("ENABLE_ANYCONNECT")
	case config.OpenVPN:
		return c.Cfg.Bool("ENABLE_OPENVPN")
	case config.IKEv2:
		return c.Cfg.Bool("ENABLE_IKEV2")
	}
	return false
}

func (c *Core) countSessions(p *Principal) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.sessions {
		if s.disconnecting {
			continue
		}
		if p.Emergency && s.Emergency || !p.Emergency && p.User != nil && s.UserID == p.User.ID {
			n++
		}
	}
	return n
}

// AuthenticatePassword is VerifyPassword followed by Authorize, with auditing.
func (c *Core) AuthenticatePassword(cr Credentials, password string) (*Session, error) {
	p, err := c.VerifyPassword(cr, password)
	if err == nil {
		var s *Session
		s, err = c.Authorize(cr, p)
		if err == nil {
			return s, nil
		}
	}
	c.RecordFailure(cr, err)
	return nil, err
}

// pendingTTL is how long an authorized session may wait for the backend
// to report it as established.
const pendingTTL = 2 * time.Minute

func (c *Core) expirePending() {
	var expired []*Session
	c.mu.Lock()
	for _, s := range c.sessions {
		if s.State == StatePending && time.Since(s.CreatedAt) > pendingTTL {
			expired = append(expired, s)
		}
	}
	c.mu.Unlock()
	for _, s := range expired {
		c.releaseSession(s.VPNIP, "not established", false)
	}
}

// AddrFromString parses an IPv4 address, returning the zero value on error.
func AddrFromString(s string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
