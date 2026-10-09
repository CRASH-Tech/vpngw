package core

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"vpngw/internal/oidc"
	"vpngw/internal/store"
)

// RevalidateNow schedules an immediate revalidation round.
func (c *Core) RevalidateNow() {
	select {
	case c.revalidateNow <- struct{}{}:
	default:
	}
}

// jitter spreads checks evenly inside the interval based on the user id.
func jitter(userID int64, interval time.Duration) time.Duration {
	h := fnv.New32a()
	fmt.Fprint(h, userID)
	return time.Duration(uint64(h.Sum32()) % uint64(interval))
}

// due reports whether a user should be refreshed now.
func (c *Core) due(u *store.User, now time.Time) bool {
	interval := c.Cfg.Dur("OIDC_REVALIDATE_INTERVAL")
	if u.LastCheckAt.IsZero() {
		return true
	}
	if !u.IdPFailSince.IsZero() {
		// Exponential backoff while the IdP is unreachable: 15s, 30s, 1m … ≤ interval.
		fails := now.Sub(u.IdPFailSince)
		backoff := 15 * time.Second
		for backoff < interval && backoff < fails/2 {
			backoff *= 2
		}
		if backoff > interval {
			backoff = interval
		}
		return now.Sub(u.LastCheckAt) >= backoff
	}
	// Next check happens at a stable per-user phase within each interval,
	// but never later than one interval after the previous check.
	since := now.Sub(u.LastCheckAt)
	if since >= interval {
		return true
	}
	phase := jitter(u.ID, interval)
	slot := now.Truncate(interval).Add(phase)
	return !u.LastCheckAt.After(slot) && !now.Before(slot)
}

func (c *Core) revalidateLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.revalidateRound(ctx, false)
		case <-c.revalidateNow:
			c.revalidateRound(ctx, true)
		}
	}
}

func (c *Core) revalidateRound(ctx context.Context, all bool) {
	users, err := c.Store.UsersWithPassword()
	if err != nil {
		slog.Error("load users", "err", err)
		return
	}
	now := time.Now()
	active := map[int64]bool{}
	for _, s := range c.Sessions() {
		active[s.UserID] = true
	}
	var due []*store.User
	for _, u := range users {
		if all || c.due(u, now) {
			due = append(due, u)
		}
	}
	// Users with live VPN sessions first.
	sort.SliceStable(due, func(i, j int) bool { return active[due[i].ID] && !active[due[j].ID] })
	sem := make(chan struct{}, max(1, c.Cfg.Int("OIDC_MAX_CONCURRENCY")))
	var wg sync.WaitGroup
	for _, u := range due {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(u *store.User) {
			defer wg.Done()
			defer func() { <-sem }()
			c.revalidateUser(ctx, u.ID)
		}(u)
	}
	wg.Wait()
}

// revalidateUser refreshes one user against the IdP and applies the result.
func (c *Core) revalidateUser(ctx context.Context, userID int64) {
	u, err := c.Store.UserByID(userID)
	if err != nil || !u.HasPassword() {
		return
	}
	rt, err := c.RefreshToken(u)
	if err != nil {
		_ = c.RevokeUser(u.ID, "stored refresh token unusable", "")
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tok, err := c.OIDC.Refresh(rctx, rt)
	now := time.Now()
	if err == nil && c.Cfg.Bool("OIDC_INTROSPECTION") {
		var activeTok bool
		activeTok, err = c.OIDC.Introspect(rctx, tok.AccessToken)
		if err == nil && !activeTok {
			err = fmt.Errorf("%w (introspection: token inactive)", oidc.ErrRevoked)
		}
	}
	switch {
	case err == nil:
		c.revalidateOK(u, tok, now, rt)
	case errors.Is(err, oidc.ErrRevoked):
		c.Audit("warn", "oidc.revoked", "", u.Username, "", "", "IdP rejected the session: "+err.Error())
		_ = c.RevokeUser(u.ID, "identity provider session ended", "")
	case oidc.IsTransient(err):
		c.revalidateTransient(u, err, now)
	default:
		// Invalid tokens or claims: treat like an unreachable IdP so the
		// grace period applies, but log loudly.
		slog.Error("revalidation failed", "user", u.Username, "err", err)
		c.revalidateTransient(u, err, now)
	}
}

func (c *Core) revalidateOK(u *store.User, tok *oidc.Tokens, now time.Time, oldRT string) {
	if tok.Identity.Sub != u.Sub {
		_ = c.RevokeUser(u.ID, "IdP returned a different subject", "")
		return
	}
	prevGroups, prevClaim, prevAdmin := strings.Join(u.Groups, ","), u.VPNClaim, u.IsAdmin
	wasFailing := !u.IdPFailSince.IsZero()
	c.applyIdentity(u, &tok.Identity)
	u.RefreshToken = c.Box.Seal([]byte(tok.RefreshToken), rtAD(u.ID))
	u.SessionExpiresAt = c.sessionExpiry(tok, u.SessionExpiresAt, tok.RefreshToken != oldRT)
	u.LastCheckAt, u.LastCheckOKAt = now, now
	u.LastCheckError = ""
	u.IdPFailSince = time.Time{}
	if err := c.Store.SaveUser(u); err != nil {
		slog.Error("save user", "err", err)
		return
	}
	if wasFailing {
		c.Audit("info", "oidc.recovered", "", u.Username, "", "", "IdP session check succeeded again")
	}
	if prevAdmin != u.IsAdmin {
		c.Audit("info", "oidc.admin_changed", "", u.Username, "", "", fmt.Sprintf("admin flag changed to %v", u.IsAdmin))
	}
	if prevGroups != strings.Join(u.Groups, ",") || prevClaim != u.VPNClaim {
		c.Audit("info", "oidc.groups_changed", "", u.Username, "", "", "groups/routes changed: "+strings.Join(u.Groups, ", "))
		c.SyncProfiles()
		c.applyPolicyChange(u)
	}
}

func (c *Core) revalidateTransient(u *store.User, err error, now time.Time) {
	if u.IdPFailSince.IsZero() {
		u.IdPFailSince = now
		c.Audit("warn", "oidc.unreachable", "", u.Username, "", "", "IdP session check failed, grace period started: "+err.Error())
	}
	u.LastCheckAt = now
	u.LastCheckError = err.Error()
	if err := c.Store.SaveUser(u); err != nil {
		slog.Error("save user", "err", err)
	}
	grace := c.Cfg.Dur("OIDC_GRACE_PERIOD")
	if now.Sub(u.LastCheckOKAt) > c.Cfg.Dur("OIDC_REVALIDATE_INTERVAL")+grace {
		// Fail closed: drop tunnels. The password stays suspended (new
		// connections need a fresh successful check) until the IdP answers.
		if n := c.DisconnectUser(u.ID, false, "IdP unreachable beyond grace period", ""); n > 0 {
			c.Audit("warn", "oidc.grace_expired", "", u.Username, "", "", fmt.Sprintf("grace period expired, %d session(s) terminated", n))
		}
	}
}

// BackchannelLogout handles a verified logout token.
func (c *Core) BackchannelLogout(lc *oidc.LogoutClaims) int {
	var users []*store.User
	if lc.SID != "" {
		users, _ = c.Store.UsersBySID(lc.SID)
	}
	if len(users) == 0 && lc.Sub != "" {
		if u, err := c.Store.UserBySub(lc.Sub); err == nil {
			// With only sub, every session of the user ends.
			if lc.SID == "" || u.OIDCSID == lc.SID {
				users = append(users, u)
			}
		}
	}
	for _, u := range users {
		if u.HasPassword() {
			_ = c.RevokeUser(u.ID, "back-channel logout from IdP", "")
		}
	}
	return len(users)
}

// RevalidateUser checks one user against the IdP immediately.
func (c *Core) RevalidateUser(ctx context.Context, userID int64) { c.revalidateUser(ctx, userID) }
