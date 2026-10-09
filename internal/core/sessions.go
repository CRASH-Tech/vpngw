package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"vpngw/internal/store"
)

// SessionStarted marks a pending session as established.
func (c *Core) SessionStarted(ip netip.Addr, backendRef, clientIP string) {
	c.mu.Lock()
	s, ok := c.sessions[ip]
	if !ok {
		c.mu.Unlock()
		slog.Warn("backend reported unknown session", "vpn_ip", ip, "ref", backendRef)
		return
	}
	if backendRef != "" {
		s.BackendRef = backendRef
	}
	if clientIP != "" {
		s.ClientIP = clientIP
	}
	if s.State == StateActive {
		c.mu.Unlock()
		return
	}
	s.State = StateActive
	s.StartedAt = time.Now()
	s.lastSample = s.StartedAt
	c.countConnect(s)
	rec := &store.SessionRecord{UserID: s.UserID, Username: s.Username, Login: s.Login, Protocol: s.Protocol, BackendRef: s.BackendRef,
		ProfileID: s.Profile.ID, VPNIP: ip.String(), ClientIP: s.ClientIP, StartedAt: s.StartedAt}
	snap := s.Snapshot()
	c.mu.Unlock()
	if err := c.Store.InsertSession(rec); err != nil {
		slog.Error("store session", "err", err)
	} else {
		c.mu.Lock()
		if s2, ok := c.sessions[ip]; ok && s2 == s {
			s.ID = rec.ID
		}
		c.mu.Unlock()
	}
	c.Audit("info", "vpn.connect", "", snap.Username, snap.Protocol, snap.ClientIP,
		fmt.Sprintf("connected as %s, address %s, profile %s", snap.Login, ip, snap.Profile.ID))
}

// SessionStopped is called by a backend when a session ended.
func (c *Core) SessionStopped(ip netip.Addr, reason string, in, out uint64) {
	c.mu.Lock()
	if s, ok := c.sessions[ip]; ok {
		if in > s.BytesIn {
			s.BytesIn = in
		}
		if out > s.BytesOut {
			s.BytesOut = out
		}
		if s.disconnecting {
			// The backend reports its own cause; keep the gateway's reason.
			reason = s.disconnectReason
		}
	}
	c.mu.Unlock()
	if reason == "" {
		reason = "client disconnected"
	}
	c.releaseSession(ip, reason, true)
}

// releaseSession frees address and firewall state and closes the record.
func (c *Core) releaseSession(ip netip.Addr, reason string, audit bool) {
	c.mu.Lock()
	s, ok := c.sessions[ip]
	if !ok {
		c.mu.Unlock()
		return
	}
	delete(c.sessions, ip)
	snap := s.Snapshot()
	c.mu.Unlock()
	c.countEnd(&snap)

	if err := c.FW.RemoveSession(ip); err != nil {
		slog.Error("firewall remove failed", "ip", ip, "err", err)
	}
	if p := c.IPAM.Pool(snap.Protocol); p != nil {
		p.Release(ip)
	}
	if snap.ID != 0 {
		c.saveTraffic(&snap)
		if err := c.Store.EndSession(snap.ID, int64(snap.BytesIn), int64(snap.BytesOut), reason, time.Now()); err != nil {
			slog.Error("end session", "err", err)
		}
	}
	if audit && snap.State == StateActive {
		c.Audit("info", "vpn.disconnect", "", snap.Username, snap.Protocol, snap.ClientIP,
			fmt.Sprintf("disconnected (%s), address %s, in %d B, out %d B", reason, ip, snap.BytesIn, snap.BytesOut))
	}
}

// Disconnect terminates one session.
func (c *Core) Disconnect(ip netip.Addr, reason, actor string) error {
	c.mu.Lock()
	s, ok := c.sessions[ip]
	if !ok {
		c.mu.Unlock()
		return errors.New("session not found")
	}
	s.disconnecting = true
	s.disconnectReason = reason
	snap := s.Snapshot()
	b := c.backends[s.Protocol]
	c.mu.Unlock()

	// Cut traffic first, then ask the backend to tear the tunnel down.
	if err := c.FW.RemoveSession(ip); err != nil {
		slog.Error("firewall remove failed", "ip", ip, "err", err)
	}
	var err error
	if b != nil && snap.State == StateActive {
		err = b.Disconnect(&snap)
	}
	if actor != "" {
		c.Audit("info", "vpn.kill", actor, snap.Username, snap.Protocol, snap.ClientIP, fmt.Sprintf("session %s terminated: %s", ip, reason))
	}
	c.releaseSession(ip, reason, true)
	return err
}

// DisconnectUser terminates every session of a user.
func (c *Core) DisconnectUser(userID int64, emergency bool, reason, actor string) int {
	n := 0
	for _, s := range c.UserSessions(userID, emergency) {
		if err := c.Disconnect(s.VPNIP, reason, actor); err != nil {
			slog.Warn("disconnect failed", "ip", s.VPNIP, "err", err)
		}
		n++
	}
	return n
}

// pollLoop refreshes counters from all backends every 5 seconds and
// reconciles state.
func (c *Core) pollLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		backends := make([]Backend, 0, len(c.backends))
		for _, b := range c.backends {
			backends = append(backends, b)
		}
		c.mu.Unlock()
		for _, b := range backends {
			pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			live, err := b.Poll(pctx)
			cancel()
			if err != nil {
				slog.Debug("backend poll failed", "protocol", b.Protocol(), "err", err)
				continue
			}
			c.reconcile(b, live)
		}
	}
}

func (c *Core) reconcile(b Backend, live []LiveSession) {
	proto := b.Protocol()
	now := time.Now()
	seen := map[netip.Addr]bool{}
	var unknown []LiveSession
	var started []LiveSession
	c.mu.Lock()
	for _, l := range live {
		seen[l.VPNIP] = true
		s, ok := c.sessions[l.VPNIP]
		if !ok || s.Protocol != proto {
			unknown = append(unknown, l)
			continue
		}
		if s.State == StatePending {
			started = append(started, l)
		}
		if l.BackendRef != "" {
			s.BackendRef = l.BackendRef
		}
		if l.ClientIP != "" && s.ClientIP == "" {
			s.ClientIP = l.ClientIP
		}
		if !s.lastSample.IsZero() {
			dt := now.Sub(s.lastSample).Seconds()
			if dt > 0 {
				if l.BytesIn >= s.BytesIn {
					s.RateIn = float64(l.BytesIn-s.BytesIn) / dt
				}
				if l.BytesOut >= s.BytesOut {
					s.RateOut = float64(l.BytesOut-s.BytesOut) / dt
				}
			}
		}
		if l.BytesIn >= s.BytesIn {
			s.BytesIn = l.BytesIn
		}
		if l.BytesOut >= s.BytesOut {
			s.BytesOut = l.BytesOut
		}
		s.lastSample = now
		s.missingPolls = 0
	}
	var lost []netip.Addr
	for ip, s := range c.sessions {
		if s.Protocol != proto || s.State != StateActive || seen[ip] {
			continue
		}
		s.missingPolls++
		if s.missingPolls >= 3 {
			lost = append(lost, ip)
		}
	}
	c.mu.Unlock()
	for _, l := range started {
		c.SessionStarted(l.VPNIP, l.BackendRef, l.ClientIP)
	}
	for _, ip := range lost {
		c.releaseSession(ip, "session vanished from backend", true)
	}
	for _, l := range unknown {
		// Fail closed: a tunnel the gateway did not authorize is torn down.
		slog.Warn("terminating unknown backend session", "protocol", proto, "vpn_ip", l.VPNIP, "ref", l.BackendRef)
		tmp := Session{Protocol: proto, VPNIP: l.VPNIP, BackendRef: l.BackendRef, Username: l.Username}
		_ = b.Disconnect(&tmp)
	}
}

// persistLoop stores counters and traffic deltas once a minute.
func (c *Core) persistLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, s := range c.Sessions() {
			if s.ID == 0 {
				continue
			}
			c.saveTraffic(&s)
			if err := c.Store.UpdateSessionCounters(s.ID, int64(s.BytesIn), int64(s.BytesOut), s.BackendRef, s.ClientIP); err != nil {
				slog.Warn("update counters", "err", err)
			}
		}
	}
}

// saveTraffic adds the not yet saved byte delta to traffic history.
func (c *Core) saveTraffic(snap *Session) {
	c.mu.Lock()
	s, ok := c.sessions[snap.VPNIP]
	var dIn, dOut uint64
	if ok && s.ID == snap.ID {
		dIn, dOut = s.BytesIn-s.savedIn, s.BytesOut-s.savedOut
		s.savedIn, s.savedOut = s.BytesIn, s.BytesOut
	} else {
		dIn, dOut = snap.BytesIn-snap.savedIn, snap.BytesOut-snap.savedOut
	}
	c.mu.Unlock()
	if snap.UserID == 0 || (dIn == 0 && dOut == 0) {
		return
	}
	if err := c.Store.AddTraffic(snap.UserID, time.Now(), int64(dIn), int64(dOut)); err != nil {
		slog.Warn("store traffic", "err", err)
	}
}

// Shutdown ends all sessions in the database (backends stop with the process).
func (c *Core) Shutdown() {
	for _, s := range c.Sessions() {
		c.releaseSession(s.VPNIP, "gateway shutdown", true)
	}
}
