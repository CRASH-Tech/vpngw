package core

import (
	"sort"
	"time"
)

// UserStat counts a user's VPN use on one protocol since the gateway
// started (Prometheus counters; they restart at zero with the process).
type UserStat struct {
	Username    string
	Protocol    string
	Connections uint64    // sessions established
	BytesIn     uint64    // received from the client (ended and live sessions)
	BytesOut    uint64    // sent to the client
	Active      int       // live sessions now
	LastConnect time.Time // last session established
}

type statKey struct{ user, proto string }

func (c *Core) stat(user, proto string) *UserStat {
	if c.stats == nil {
		c.stats = map[statKey]*UserStat{}
	}
	k := statKey{user, proto}
	st, ok := c.stats[k]
	if !ok {
		st = &UserStat{Username: user, Protocol: proto}
		c.stats[k] = st
	}
	return st
}

// countConnect records an established session.
func (c *Core) countConnect(s *Session) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	st := c.stat(s.Username, s.Protocol)
	st.Connections++
	st.LastConnect = s.StartedAt
}

// countEnd adds the traffic of an ended session.
func (c *Core) countEnd(s *Session) {
	if s.State != StateActive {
		return
	}
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	st := c.stat(s.Username, s.Protocol)
	st.BytesIn += s.BytesIn
	st.BytesOut += s.BytesOut
}

// UserStats returns the per-user counters including live sessions.
func (c *Core) UserStats() []UserStat {
	live := c.Sessions()
	c.statsMu.Lock()
	out := map[statKey]UserStat{}
	for k, st := range c.stats {
		out[k] = *st
	}
	c.statsMu.Unlock()
	for _, s := range live {
		if s.State != StateActive {
			continue
		}
		k := statKey{s.Username, s.Protocol}
		st := out[k]
		st.Username, st.Protocol = s.Username, s.Protocol
		st.BytesIn += s.BytesIn
		st.BytesOut += s.BytesOut
		st.Active++
		out[k] = st
	}
	list := make([]UserStat, 0, len(out))
	for _, st := range out {
		list = append(list, st)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Username != list[j].Username {
			return list[i].Username < list[j].Username
		}
		return list[i].Protocol < list[j].Protocol
	})
	return list
}
