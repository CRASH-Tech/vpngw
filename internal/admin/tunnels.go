package admin

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"vpngw/internal/config"
	"vpngw/internal/policy"
	"vpngw/internal/portal"
	"vpngw/internal/tunnels"
)

func (a *Admin) registerTunnels() {
	m := a.Mux
	m.HandleFunc("GET /admin/tunnels", a.RequireAdmin(a.tunnelsPage))
	m.HandleFunc("POST /admin/tunnels", a.RequireAdmin(a.tunnelSave))
	m.HandleFunc("POST /admin/tunnels/delete", a.RequireAdmin(a.tunnelDelete))
	m.HandleFunc("POST /admin/tunnels/toggle", a.RequireAdmin(a.tunnelToggle))
	m.HandleFunc("POST /admin/tunnels/restart", a.RequireAdmin(a.tunnelRestart))
	m.HandleFunc("POST /admin/tunnels/regenerate-key", a.RequireAdmin(a.tunnelRegenerateKey))
	m.HandleFunc("POST /admin/tunnels/transit-gateway", a.RequireAdmin(a.tunnelTransitGateway))
}

// peerForm holds the add/edit form, also to show it again after an error.
type peerForm struct {
	Edit      bool // editing a saved peer (name is fixed)
	Name      string
	PublicKey string
	Endpoint  string
	Transport string
	Subnets   string // networks behind the site
	Allow     string // networks of ours the site may reach
	Address   string // tunnel address for an incoming site; empty = automatic
	PSK       string
	Keepalive string
	Exit      bool
	NAT       bool
	Disabled  bool
}

func formFromRequest(r *http.Request) peerForm {
	return peerForm{
		Edit:      r.FormValue("edit") == "1",
		Name:      strings.TrimSpace(r.FormValue("name")),
		PublicKey: strings.TrimSpace(r.FormValue("public_key")),
		Endpoint:  strings.TrimSpace(r.FormValue("endpoint")),
		Transport: r.FormValue("transport"),
		Subnets:   strings.TrimSpace(r.FormValue("subnets")),
		Allow:     strings.TrimSpace(r.FormValue("allow")),
		Address:   strings.TrimSpace(r.FormValue("address")),
		PSK:       r.FormValue("psk"),
		Keepalive: strings.TrimSpace(r.FormValue("keepalive")),
		Exit:      r.FormValue("exit") == "1",
		NAT:       r.FormValue("nat") == "1",
		Disabled:  r.FormValue("disabled") == "1",
	}
}

func (a *Admin) pools() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range a.Cfg.Pools() {
		out = append(out, p)
	}
	return out
}

func (a *Admin) tunnelsPage(w http.ResponseWriter, r *http.Request) {
	a.renderTunnels(w, r, http.StatusOK, nil, "")
}

// renderTunnels shows the page; form (if not nil) refills the peer form.
func (a *Admin) renderTunnels(w http.ResponseWriter, r *http.Request, status int, form *peerForm, formErr string) {
	t := a.Hooks.Tunnels
	st := t.Status()
	nodeAddr, nodeAuto := t.NodeAddress()
	data := map[string]any{"Status": st, "Transports": []string{"", "udp", "aead", "tls"},
		"KeyConfigured": t.KeyConfigured(), "SiteName": t.SiteName(), "Listen": a.Cfg.Str("TUNNEL_LISTEN"), "Address": nodeAddr.String(), "AddressAuto": nodeAuto, "Transport": a.Cfg.Str("TUNNEL_TRANSPORT"),
		"Gateways": a.gatewayUsage(), "TransitSources": prefixesString(a.Cfg.TransitSources()),
		"TransitGateway": a.Cfg.Str("TUNNEL_TRANSIT_GATEWAY")}
	_, data["TransitFixed"] = a.Cfg.EnvValue("TUNNEL_TRANSIT_GATEWAY")
	if doms := a.Cfg.TransitDomains(); len(doms) > 0 {
		dp := &policy.Profile{Domains: doms}
		labels := dp.DomainLabels()
		data["TransitExcept"] = dp.ExceptLabels()
		via := "the host's default gateway"
		if gw := a.Cfg.TransitDomainsGateway(); gw != "" {
			via = a.describeGateway(gw)
		}
		_, dnsServer := a.Cfg.DomainPool()
		data["TransitDomains"], data["TransitDomainsVia"], data["DomainDNS"] = labels, via, dnsServer
	}
	var exits []string
	for _, p := range st.Peers {
		if p.Exit && !p.Disabled {
			exits = append(exits, p.Name)
		}
	}
	data["Exits"] = exits
	if gw := a.Cfg.Str("TUNNEL_TRANSIT_GATEWAY"); gw != "" {
		data["TransitGatewayInfo"] = a.gatewayInfo(gw)
	}
	if form == nil {
		form = &peerForm{NAT: true}
		if name := r.URL.Query().Get("edit"); name != "" {
			for _, p := range st.Peers {
				if strings.EqualFold(p.Name, name) && p.Source == "admin" {
					form = &peerForm{Edit: true, Name: p.Name, PublicKey: p.PublicKey, Endpoint: p.Endpoint, Transport: p.Transport,
						Subnets: prefixesString(p.Subnets), Allow: prefixesString(p.Allow), Keepalive: strconv.Itoa(p.Keepalive),
						Exit: p.Exit, NAT: p.NAT, Disabled: p.Disabled}
					if p.Address.IsValid() && !p.AutoAddress {
						form.Address = p.Address.String()
					}
				}
			}
		}
	}
	data["Form"] = form
	if formErr != "" {
		data["FormError"] = formErr
	}
	if name := r.URL.Query().Get("config"); name != "" {
		for _, p := range st.Peers {
			if strings.EqualFold(p.Name, name) {
				endpoint := ""
				if l := a.Cfg.Str("TUNNEL_LISTEN"); l != "" {
					if _, port, ok := strings.Cut(l, ":"); ok {
						endpoint = a.Cfg.Str("VPN_HOSTNAME") + ":" + port
					}
				}
				data["ConfigPeer"] = p.Name
				data["RemoteConfig"] = t.RemoteConfig(p.Peer, endpoint)
			}
		}
	}
	a.Render(w, r, status, "admin_tunnels", &portal.Page{Title: "Tunnels", Nav: "tunnels", Data: data})
}

// gatewayInfo describes a vpnGateway value; Missing: nothing by that name
// exists here, so the traffic it should carry is dropped.
type gatewayInfo struct {
	Desc    string
	Missing bool
}

// gatewayUsage lists vpnGateway values used by IdP groups (of users with a
// password) and the emergency admin, with what they resolve to.
func (a *Admin) gatewayUsage() map[string]gatewayInfo {
	out := map[string]gatewayInfo{}
	add := func(gw string) {
		if gw != "" {
			out[gw] = a.gatewayInfo(gw)
		}
	}
	add(a.Cfg.Str("EMERGENCY_GATEWAY"))
	if users, err := a.Store.UsersWithPassword(); err == nil {
		for _, u := range users {
			for _, o := range a.Core.AvailableLogins(u) {
				if o.Profile != nil {
					add(o.Profile.Gateway)
				}
			}
		}
	}
	return out
}

func (a *Admin) gatewayInfo(gw string) gatewayInfo {
	if a.Cfg.IsSelf(gw) {
		return gatewayInfo{Desc: "this gateway (host default gateway)"}
	}
	if a.Hooks.Tunnels != nil {
		if p, ok := a.Hooks.Tunnels.Find(gw); ok {
			return gatewayInfo{Desc: "site " + p.Name + " (" + p.Interface() + ")"}
		}
	}
	if _, err := netip.ParseAddr(gw); err == nil {
		return gatewayInfo{Desc: "next hop " + gw}
	}
	if _, err := net.InterfaceByName(gw); err == nil {
		return gatewayInfo{Desc: "interface " + gw}
	}
	return gatewayInfo{Desc: "no site or interface " + gw + " on this gateway: this traffic is dropped", Missing: true}
}

func (a *Admin) describeGateway(gw string) string { return a.gatewayInfo(gw).Desc }

func prefixesString(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, " ")
}

func (a *Admin) tunnelSave(w http.ResponseWriter, r *http.Request) {
	t := a.Hooks.Tunnels
	f := formFromRequest(r)
	fail := func(msg string) {
		a.renderTunnels(w, r, http.StatusUnprocessableEntity, &f, msg)
	}
	p := tunnels.Peer{Name: f.Name, PublicKey: f.PublicKey, Endpoint: f.Endpoint, Transport: f.Transport, PSK: f.PSK,
		Exit: f.Exit, NAT: f.NAT, Disabled: f.Disabled, Source: "admin"}
	if f.Keepalive != "" {
		n, err := strconv.Atoi(f.Keepalive)
		if err != nil || n < 0 {
			fail("Keepalive must be a number of seconds.")
			return
		}
		p.Keepalive = n
	}
	var ok bool
	if p.Subnets, ok = formPrefixes(f.Subnets, "Networks behind the site", fail); !ok {
		return
	}
	if p.Allow, ok = formPrefixes(f.Allow, "May reach here", fail); !ok {
		return
	}
	if f.Address != "" && f.Address != "auto" {
		addr, err := netip.ParseAddr(f.Address)
		if err != nil || !addr.Is4() {
			fail("Tunnel address: use an IPv4 address, or leave it empty for automatic.")
			return
		}
		p.Address = addr
	}
	if p.PSK == "" && f.Edit {
		if old, ok := findPeer(t, p.Name); ok {
			p.PSK = old.PSK
		}
	}
	if err := t.Validate(p, a.pools()); err != nil {
		fail("Site not saved: " + err.Error())
		return
	}
	if err := t.Save(p); err != nil {
		fail(err.Error())
		return
	}
	a.Core.Audit("info", "admin.tunnels", a.actor(r), "", "", portal.ClientIP(r),
		fmt.Sprintf("tunnel peer %s saved: endpoint %q, behind %s, exit %v, may reach %s", p.Name, p.Endpoint,
			prefixesString(p.Subnets), p.Exit, prefixesString(p.Allow)))
	portal.Flash(w, "ok", "Site "+p.Name+" saved and applied.")
	http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
}

// formPrefixes parses a list of IPv4 networks from a form field.
func formPrefixes(v, field string, fail func(string)) ([]netip.Prefix, bool) {
	var out []netip.Prefix
	for _, s := range config.SplitList(v) {
		pfx, err := netip.ParsePrefix(s)
		if err != nil || !pfx.Addr().Is4() {
			fail(field + ": " + s + " is not a network; use IPv4 CIDR notation, e.g. 10.6.0.0/16.")
			return nil, false
		}
		out = append(out, pfx.Masked())
	}
	return policy.Aggregate(out), true
}

// tunnelRegenerateKey replaces this node's generated key pair.
func (a *Admin) tunnelRegenerateKey(w http.ResponseWriter, r *http.Request) {
	pub, err := a.Hooks.Tunnels.RegenerateKey()
	if err != nil {
		portal.Flash(w, "bad", "Key not regenerated: "+err.Error())
		http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		return
	}
	a.Core.Audit("warn", "admin.tunnels", a.actor(r), "", "", portal.ClientIP(r), "regenerated the tunnel node key, new public key "+pub)
	portal.Flash(w, "warn", "New public key "+pub+". Tunnels stay down until every site has it (Edit site → Public key, or TUNNEL_PEER_<NAME>_PUBLIC_KEY).")
	http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
}

func findPeer(t *tunnels.Manager, name string) (tunnels.Peer, bool) {
	for _, p := range t.Peers() {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return tunnels.Peer{}, false
}

func (a *Admin) tunnelDelete(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if err := a.Hooks.Tunnels.Delete(name); err != nil {
		portal.Flash(w, "bad", err.Error())
	} else {
		a.Core.Audit("info", "admin.tunnels", a.actor(r), "", "", portal.ClientIP(r), "tunnel peer "+name+" deleted")
		portal.Flash(w, "ok", "Peer "+name+" deleted.")
	}
	http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
}

func (a *Admin) tunnelToggle(w http.ResponseWriter, r *http.Request) {
	t := a.Hooks.Tunnels
	p, ok := findPeer(t, r.FormValue("name"))
	if !ok || p.Source != "admin" {
		portal.Flash(w, "bad", "Only peers added in the panel can be changed here.")
		http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		return
	}
	p.Disabled = !p.Disabled
	if err := t.Validate(p, a.pools()); err != nil {
		portal.Flash(w, "bad", err.Error())
	} else if err := t.Save(p); err != nil {
		portal.Flash(w, "bad", err.Error())
	} else {
		state := "enabled"
		if p.Disabled {
			state = "disabled"
		}
		a.Core.Audit("info", "admin.tunnels", a.actor(r), "", "", portal.ClientIP(r), "tunnel peer "+p.Name+" "+state)
		portal.Flash(w, "ok", "Peer "+p.Name+" "+state+".")
	}
	http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
}

// tunnelTransitGateway sets TUNNEL_TRANSIT_GATEWAY: the internet exit for
// hosts that route through this node.
func (a *Admin) tunnelTransitGateway(w http.ResponseWriter, r *http.Request) {
	gw := strings.TrimSpace(r.FormValue("gateway"))
	if _, env := a.Cfg.EnvValue("TUNNEL_TRANSIT_GATEWAY"); env {
		portal.Flash(w, "bad", "TUNNEL_TRANSIT_GATEWAY is set in the environment and cannot be changed here.")
		http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		return
	}
	if gw != "" {
		if p, ok := a.Hooks.Tunnels.Find(gw); !ok || !p.Exit {
			portal.Flash(w, "bad", "Choose a site marked as internet exit.")
			http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
			return
		}
	}
	if err := a.Store.SetSetting("TUNNEL_TRANSIT_GATEWAY", &gw, a.actor(r)); err != nil {
		a.Error(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.Cfg.Apply(map[string]*string{"TUNNEL_TRANSIT_GATEWAY": &gw}); err != nil {
		portal.Flash(w, "bad", err.Error())
		http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		return
	}
	desc := "the host's default gateway"
	if gw != "" {
		desc = "site " + gw
	}
	a.Core.Audit("info", "admin.tunnels", a.actor(r), "", "", portal.ClientIP(r), "internet of routed hosts via "+desc)
	portal.Flash(w, "ok", "Routed hosts now reach the internet via "+desc+".")
	http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
}

func (a *Admin) tunnelRestart(w http.ResponseWriter, r *http.Request) {
	a.Hooks.Tunnels.Restart()
	a.Core.Audit("info", "admin.restart", a.actor(r), "", "", portal.ClientIP(r), "restarted the tunnel node")
	portal.Flash(w, "ok", "Tunnel node is restarting; tunnels reconnect in a few seconds.")
	http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
}

// profileTunnels describes how a profile's traffic leaves: subnets behind
// peers it may use, and its default route.
func (a *Admin) profileTunnels(p *policy.Profile) (via []string, def string) {
	if a.Hooks.Tunnels != nil {
		for _, rt := range a.Hooks.Tunnels.Routes() {
			inter := policy.Subtract([]netip.Prefix{rt.Prefix}, policy.Subtract([]netip.Prefix{rt.Prefix}, p.Allow))
			if len(inter) > 0 {
				via = append(via, fmt.Sprintf("%s → peer %s (%s)", prefixesString(inter), rt.Peer, rt.Dev))
			}
		}
	}
	sort.Strings(via)
	def = "host default gateway"
	if p.Gateway != "" {
		def = a.describeGateway(p.Gateway)
	}
	return via, def
}
