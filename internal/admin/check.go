package admin

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"vpngw/internal/core"
	"vpngw/internal/firewall"
	"vpngw/internal/policy"
	"vpngw/internal/portal"
)

// counterLabels name the firewall's drop counters for people.
var counterLabels = map[string]string{
	"dropped":           "Blocked by profile",
	"c2c_dropped":       "Blocked client to client",
	"inbound_dropped":   "Blocked inbound to clients",
	"tunnel_in_dropped": "Blocked from sites",
	"domain_unmapped":   "Domain addresses not resolved",
	"local_dropped":     "Blocked to this gateway",
}

func (a *Admin) counters() map[string][2]uint64 {
	out := map[string][2]uint64{}
	if a.Hooks.FirewallCounters == nil {
		return out
	}
	for k, v := range a.Hooks.FirewallCounters() {
		if l, ok := counterLabels[k]; ok {
			k = l
		}
		out[k] = v
	}
	return out
}

// destCheck is how one destination of a session is handled.
type destCheck struct {
	Addr    netip.Addr   // address the route is looked up for
	Net     netip.Prefix // network shown (zero: the address itself)
	Label   string
	Domain  string // a vpnDomains name; Addr is its real address
	Allowed bool
	Route   firewall.RouteDiag
	Site    string // tunnel site the route uses
	SiteUp  bool
	SiteRx  time.Time // last packet from the site
	OK      bool
	Verdict string // the problem, if any
	Path    string // where the packet goes, in words
	Note    string // detail under the path
	Tech    string // kernel route, as a tooltip
}

// sessionCheck shows, for one live session, the kernel's firewall entry
// and where its traffic to a few destinations goes, with a verdict each.
func (a *Admin) sessionCheck(w http.ResponseWriter, r *http.Request) {
	ip := core.AddrFromString(r.URL.Query().Get("ip"))
	s, ok := a.Core.SessionByIP(ip)
	if !ok {
		a.Error(w, r, http.StatusNotFound, "No active session with this address.")
		return
	}
	fw := a.Core.FW.DiagnoseSession(ip)
	var dests []destCheck
	if d := core.AddrFromString(r.URL.Query().Get("dst")); d.IsValid() && d.Is4() {
		dests = append(dests, destCheck{Addr: d, Label: "requested"})
	}
	if s.Profile.FullTunnel {
		dests = append(dests, destCheck{Addr: netip.MustParseAddr("1.1.1.1"), Net: netip.MustParsePrefix("0.0.0.0/0"), Label: "internet"})
	}
	// The networks of this login, shown as networks and tested with their
	// first address: this site's own, then those behind each site.
	within := func(p netip.Prefix) []netip.Prefix {
		return policy.Subtract([]netip.Prefix{p}, policy.Subtract([]netip.Prefix{p}, s.Profile.Allow))
	}
	add := func(p netip.Prefix, label string) {
		if len(dests) >= 16 {
			return
		}
		for _, d := range dests {
			if d.Net == p {
				return
			}
		}
		if len(dests) > 0 && dests[0].Label == "requested" && p.Contains(dests[0].Addr) {
			dests[0].Label = "requested, " + label
		}
		dests = append(dests, destCheck{Addr: p.Addr().Next(), Net: p, Label: label})
	}
	for _, ln := range a.Core.FW.LocalNets() {
		for _, p := range within(ln) {
			add(p, "network of this site")
		}
	}
	if a.Hooks.Tunnels != nil {
		for _, rt := range a.Hooks.Tunnels.Routes() {
			if rt.Prefix.Bits() == 32 {
				continue // a site's tunnel address
			}
			for _, p := range within(rt.Prefix) {
				add(p, "behind site "+rt.Peer)
			}
		}
	}
	// Names of vpnDomains the gateway resolved for this login's gateway.
	if len(s.Profile.Domains) > 0 && a.Hooks.DomainMappings != nil {
		ms := a.Hooks.DomainMappings()
		sort.Slice(ms, func(i, j int) bool { return ms[i].Used.After(ms[j].Used) })
		n := 0
		for _, m := range ms {
			if n >= 10 || m.Gateway != s.Profile.Gateway || !m.Real.IsValid() || !policy.MatchDomain(s.Profile.Domains, m.Name) {
				continue
			}
			dests = append(dests, destCheck{Addr: m.Real, Domain: m.Name, Label: m.Addr.String() + " → " + m.Real.String()})
			n++
		}
	}
	sites := map[string]struct {
		name string
		up   bool
		rx   time.Time
	}{}
	if a.Hooks.Tunnels != nil {
		for _, p := range a.Hooks.Tunnels.Status().Peers {
			var rx time.Time
			for _, l := range p.Links {
				if l.LastRx != nil && l.LastRx.After(rx) {
					rx = *l.LastRx
				}
			}
			sites[p.Interface()] = struct {
				name string
				up   bool
				rx   time.Time
			}{p.Name, p.Connected && !p.Disabled, rx}
		}
	}
	for i := range dests {
		d := &dests[i]
		for _, p := range s.Profile.Allow {
			if p.Contains(d.Addr) {
				d.Allowed = true
			}
		}
		if d.Domain != "" {
			d.Allowed = true // through its domain pool address
		}
		d.Route = a.Core.FW.DiagnoseRoute(d.Addr, fw.Mark)
		if st, ok := sites[d.Route.Dev]; ok {
			d.Site, d.SiteUp, d.SiteRx = st.name, st.up, st.rx
		}
		via := d.Route.Dev
		if d.Route.Via != "" {
			via = d.Route.Via + " (" + d.Route.Dev + ")"
		}
		d.Tech = "dev " + d.Route.Dev
		if d.Route.Via != "" {
			d.Tech += " via " + d.Route.Via
		}
		if d.Route.Table != "" {
			d.Tech += ", table " + d.Route.Table
		}
		if fw.Mark != "" {
			d.Tech += ", mark " + fw.Mark
		}
		switch {
		case d.Route.Error != "":
			d.Path = "nowhere"
		case d.Site != "":
			d.Path = "tunnel to site " + d.Site
			if d.Label == "internet" {
				d.Note = d.Site + " must allow 0.0.0.0/0 for this gateway"
			}
		case strings.HasPrefix(d.Route.Dev, "gp-"):
			d.Path = "tunnel " + d.Route.Dev
		case d.Route.Local:
			d.Path, d.Note = "this site's network", "host route via "+via
		default:
			d.Path, d.Note = "this gateway's internet", "via "+via
		}
		switch {
		case !d.Allowed:
			d.Verdict = "not in the networks of this login"
		case !fw.InFirewall:
			d.Verdict = "the session is missing in the firewall"
		case d.Route.Error != "":
			d.Verdict = "no route (" + d.Route.Error + "): exit site down or not found"
		case d.Site != "" && !d.SiteUp:
			d.Verdict = "site " + d.Site + " is not connected"
		default:
			d.OK = true
		}
	}
	gw := "host default gateway"
	if s.Profile.Gateway != "" {
		gw = a.gatewayInfo(s.Profile.Gateway).Desc
	}
	a.Render(w, r, http.StatusOK, "admin_session_check", &portal.Page{Title: "Check " + ip.String(), Nav: "sessions", Data: map[string]any{
		"S": s, "FW": fw, "Dests": dests, "Gateway": gw, "Counters": a.counters(), "Dst": r.URL.Query().Get("dst"),
	}})
}
