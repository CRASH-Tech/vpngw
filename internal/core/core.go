// Package core is the brain of the gateway: users and VPN passwords,
// connection authorization, IP allocation, firewall state, live sessions,
// revocation and periodic OIDC session revalidation.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"vpngw/internal/config"
	"vpngw/internal/firewall"
	"vpngw/internal/ipam"
	"vpngw/internal/oidc"
	"vpngw/internal/policy"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

// Backend is a VPN server managed by the gateway.
type Backend interface {
	Protocol() string
	// Disconnect terminates a live session.
	Disconnect(s *Session) error
	// Poll returns the live sessions known to the backend.
	Poll(ctx context.Context) ([]LiveSession, error)
}

// ProfilePreparer is implemented by backends that need per-profile state
// before a connection starts (strongSwan selects its connection by the
// RADIUS Class group, and only among connections loaded when IKE_AUTH began).
type ProfilePreparer interface {
	PrepareProfile(p *policy.Profile) error
	// SyncProfiles loads the wanted profiles and unloads all others.
	SyncProfiles(wanted map[string]*policy.Profile)
}

// LiveSession is a session as reported by a backend.
type LiveSession struct {
	VPNIP      netip.Addr
	BackendRef string
	ClientIP   string
	Username   string
	BytesIn    uint64 // from client
	BytesOut   uint64 // to client
	Since      time.Time
}

// Session states.
const (
	StatePending = "pending"
	StateActive  = "active"
)

// Session is a VPN connection known to the gateway.
type Session struct {
	ID         int64 // database row, 0 while pending
	UserID     int64 // 0 for the emergency admin
	Username   string
	Email      string
	Login      string
	Group      string
	Emergency  bool
	Protocol   string
	VPNIP      netip.Addr
	ClientIP   string
	Profile    *policy.Profile
	BackendRef string
	State      string
	CreatedAt  time.Time
	StartedAt  time.Time

	BytesIn, BytesOut uint64
	RateIn, RateOut   float64
	lastSample        time.Time
	savedIn, savedOut uint64
	missingPolls      int
	RoutesWidened     bool // profile grew; new routes after reconnect
	disconnecting     bool
	disconnectReason  string
}

// Snapshot returns a copy safe to read without the core lock.
func (s *Session) Snapshot() Session {
	c := *s
	return c
}

// Core ties everything together.
type Core struct {
	Cfg    *config.Config
	Store  *store.Store
	Box    *secret.Box
	Master []byte
	OIDC   *oidc.Client
	IPAM   *ipam.IPAM
	FW     *firewall.Manager

	limiter *Limiter

	mu       sync.Mutex
	backends map[string]Backend
	sessions map[netip.Addr]*Session

	emergencyNT []byte

	revalidateNow chan struct{}

	statsMu sync.Mutex
	stats   map[statKey]*UserStat // per user and protocol, since start
}

// New creates the core.
func New(cfg *config.Config, st *store.Store, master []byte, box *secret.Box, oc *oidc.Client, fw *firewall.Manager) *Core {
	c := &Core{
		Cfg:           cfg,
		Store:         st,
		Box:           box,
		Master:        master,
		OIDC:          oc,
		IPAM:          ipam.New(cfg.Pools()),
		FW:            fw,
		backends:      map[string]Backend{},
		sessions:      map[netip.Addr]*Session{},
		revalidateNow: make(chan struct{}, 1),
	}
	c.limiter = NewLimiter(func() int { return cfg.Int("AUTH_FAIL_LIMIT") },
		func() time.Duration { return cfg.Dur("AUTH_FAIL_WINDOW") },
		func() time.Duration { return cfg.Dur("AUTH_BLOCK_DURATION") })
	c.emergencyNT = secret.NTHash(cfg.Str("EMERGENCY_PASS"))
	return c
}

// Limiter exposes the brute-force limiter.
func (c *Core) Limiter() *Limiter { return c.limiter }

// RegisterBackend adds a backend.
func (c *Core) RegisterBackend(b Backend) {
	c.mu.Lock()
	c.backends[b.Protocol()] = b
	c.mu.Unlock()
}

// Backend returns the backend of a protocol.
func (c *Core) Backend(proto string) Backend {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backends[proto]
}

// Audit writes a journal entry and a log line.
func (c *Core) Audit(level, event, actor, username, proto, ip, msg string) {
	e := &store.AuditEntry{Level: level, Event: event, Actor: actor, Username: username, Protocol: proto, IP: ip, Message: msg}
	if err := c.Store.AddAudit(e); err != nil {
		slog.Error("audit write failed", "err", err)
	}
	attrs := []any{"event", event, "user", username}
	if actor != "" {
		attrs = append(attrs, "actor", actor)
	}
	if proto != "" {
		attrs = append(attrs, "protocol", proto)
	}
	if ip != "" {
		attrs = append(attrs, "ip", ip)
	}
	switch level {
	case "warn":
		slog.Warn(msg, attrs...)
	case "error":
		slog.Error(msg, attrs...)
	default:
		slog.Info(msg, attrs...)
	}
}

// IsEmergency reports whether a username is the local emergency admin.
func (c *Core) IsEmergency(username string) bool {
	return strings.EqualFold(username, c.Cfg.Str("EMERGENCY_USER"))
}

// CheckEmergencyPassword verifies the emergency admin password.
func (c *Core) CheckEmergencyPassword(pw string) bool {
	return secret.Equal(pw, c.Cfg.Str("EMERGENCY_PASS"))
}

// ProfileFor resolves the profile of a login for a user (nil user = emergency).
func (c *Core) ProfileFor(u *store.User, group string) (*policy.Profile, error) {
	dns := c.Cfg.DNS()
	domain := c.Cfg.Str("VPN_DNS_DOMAIN")
	if u == nil {
		if group != "" {
			return nil, fmt.Errorf("the emergency administrator has no groups; log in as %s", c.Cfg.Str("EMERGENCY_USER"))
		}
		p, err := policy.Build("", []policy.GroupRoutes{{Routes: c.Cfg.List("EMERGENCY_ROUTES"), Gateway: c.Cfg.Str("EMERGENCY_GATEWAY"),
			Domains: c.Cfg.List("EMERGENCY_DOMAINS")}}, dns, domain)
		if err != nil {
			return nil, err
		}
		return c.finish(p)
	}
	claim, err := policy.ParseClaim(json.RawMessage(u.VPNClaim))
	if err != nil {
		slog.Warn("invalid routes claim", "user", u.Username, "err", err)
	}
	p, err := policy.Resolve(group, claim, dns, domain)
	if err != nil {
		return nil, err
	}
	return c.finish(p)
}

// finish applies the gateway's own settings to a profile: a vpnGateway
// naming this node, full-tunnel DNS and the domain proxy pool.
func (c *Core) finish(p *policy.Profile) (*policy.Profile, error) {
	pool, dnsServer := c.Cfg.DomainPool()
	p = p.WithLocalGateway(c.Cfg.IsSelf).WithFullTunnelDNS(c.Cfg.Addrs("VPN_FULL_TUNNEL_DNS")).WithDomainProxy(pool, dnsServer)
	if len(p.Allow) == 0 {
		return nil, errors.New("no routes")
	}
	return p, nil
}

// AvailableLogins lists the VPN logins of a user with profiles: the plain
// login (all networks of all groups, without internet access) when it has
// networks, then user@group for every group.
func (c *Core) AvailableLogins(u *store.User) []LoginOption {
	claim, _ := policy.ParseClaim(json.RawMessage(u.VPNClaim))
	avail := policy.Available(claim)
	var out []LoginOption
	if claim.Default != nil || len(avail) > 0 {
		if p, err := c.ProfileFor(u, ""); err == nil {
			out = append(out, LoginOption{Login: u.Username, Profile: p, Plain: true})
		}
	}
	for _, g := range policy.GroupNames(avail) {
		p, err := c.ProfileFor(u, g)
		opt := LoginOption{Login: u.Username + "@" + g, Group: g, Profile: p}
		if err != nil {
			opt.Error = err.Error()
		}
		out = append(out, opt)
	}
	return out
}

// VPNGroups returns the user's IdP groups that carry VPN settings.
func (c *Core) VPNGroups(u *store.User) []string {
	claim, _ := policy.ParseClaim(json.RawMessage(u.VPNClaim))
	return policy.GroupNames(policy.Available(claim))
}

// LoginOption is a VPN login a user may use.
type LoginOption struct {
	Login   string
	Group   string
	Profile *policy.Profile
	Error   string
	Plain   bool // the login without @group
}

// Sessions returns snapshots of all sessions sorted by start time.
func (c *Core) Sessions() []Session {
	c.mu.Lock()
	out := make([]Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		out = append(out, s.Snapshot())
	}
	c.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// UserSessions returns sessions of a user.
func (c *Core) UserSessions(userID int64, emergency bool) []Session {
	var out []Session
	for _, s := range c.Sessions() {
		if emergency && s.Emergency || !emergency && !s.Emergency && s.UserID == userID {
			out = append(out, s)
		}
	}
	return out
}

// SessionByRow finds a live session by database id.
func (c *Core) SessionByRow(id int64) (Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		if s.ID == id {
			return s.Snapshot(), true
		}
	}
	return Session{}, false
}

// SessionByIP finds a session by VPN address.
func (c *Core) SessionByIP(ip netip.Addr) (Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[ip]
	if !ok {
		return Session{}, false
	}
	return s.Snapshot(), true
}

// ActiveProfiles returns profiles in use by a protocol.
func (c *Core) ActiveProfiles(proto string) map[string]*policy.Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]*policy.Profile{}
	for _, s := range c.sessions {
		if s.Protocol == proto && s.Profile != nil {
			out[s.Profile.ID] = s.Profile
		}
	}
	return out
}

// WantedProfiles returns every profile a user with a valid password (or the
// emergency admin) could connect with, plus profiles of live sessions.
func (c *Core) WantedProfiles(proto string) map[string]*policy.Profile {
	out := c.ActiveProfiles(proto)
	if users, err := c.Store.UsersWithPassword(); err == nil {
		for _, u := range users {
			for _, o := range c.AvailableLogins(u) {
				if o.Profile != nil {
					out[o.Profile.ID] = o.Profile
				}
			}
		}
	}
	if p, err := c.ProfileFor(nil, ""); err == nil {
		out[p.ID] = p
	}
	return out
}

// SyncProfiles pushes the wanted profiles to backends that need them.
func (c *Core) SyncProfiles() {
	c.mu.Lock()
	var pps []struct {
		proto string
		pp    ProfilePreparer
	}
	for proto, b := range c.backends {
		if pp, ok := b.(ProfilePreparer); ok {
			pps = append(pps, struct {
				proto string
				pp    ProfilePreparer
			}{proto, pp})
		}
	}
	c.mu.Unlock()
	for _, x := range pps {
		x.pp.SyncProfiles(c.WantedProfiles(x.proto))
	}
}

// Start launches background loops.
func (c *Core) Start(ctx context.Context) {
	go c.pollLoop(ctx)
	go c.persistLoop(ctx)
	if c.Cfg.VPNEnabled() {
		go c.revalidateLoop(ctx)
	}
	go c.housekeepingLoop(ctx)
}

func (c *Core) housekeepingLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	last := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.expirePending()
		c.SyncProfiles()
		c.limiter.GC()
		c.FW.Reconcile()
		if time.Since(last) > time.Hour {
			last = time.Now()
			days := c.Cfg.Int("AUDIT_RETENTION_DAYS")
			if err := c.Store.Cleanup(time.Duration(days) * 24 * time.Hour); err != nil {
				slog.Warn("cleanup failed", "err", err)
			}
		}
	}
}
