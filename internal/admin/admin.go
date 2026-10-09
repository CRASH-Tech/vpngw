// Package admin implements the admin panel: live sessions, users,
// journal, tunnels, status, settings and backend configs.
package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/dnsproxy"
	"vpngw/internal/policy"
	"vpngw/internal/portal"
	"vpngw/internal/store"
	"vpngw/internal/supervisor"
	"vpngw/internal/tunnels"
)

// Hooks are actions the admin panel triggers in the rest of the system.
type Hooks struct {
	// RestartBackend restarts the process of a protocol after config changes.
	RestartBackend func(proto string)
	// FirewallStatus returns counters, gateways and the ruleset.
	FirewallCounters func() map[string][2]uint64
	FirewallRuleset  func() string
	Gateways         func() map[string]bool
	EgressIface      func() string
	StrongswanConns  func() []string
	// Tunnels manages links to remote sites; PeerRoutes returns the
	// installed peer subnets (prefix → interface or "unreachable").
	Tunnels    *tunnels.Manager
	PeerRoutes func() map[string]string
	// DomainMappings lists the names the domain proxy has resolved.
	DomainMappings func() []dnsproxy.Mapping
}

// Admin holds the admin handlers.
type Admin struct {
	*portal.Server
	Hooks Hooks
}

// Register adds admin routes to the portal mux.
func Register(s *portal.Server, h Hooks) *Admin {
	a := &Admin{Server: s, Hooks: h}
	m := s.Mux
	m.HandleFunc("GET /admin", s.RequireAdmin(a.sessions))
	m.HandleFunc("GET /admin/sessions/stream", s.RequireAdmin(a.sessionsStream))
	m.HandleFunc("GET /admin/sessions/check", s.RequireAdmin(a.sessionCheck))
	m.HandleFunc("POST /admin/sessions/disconnect", s.RequireAdmin(a.disconnect))
	m.HandleFunc("GET /admin/users", s.RequireAdmin(a.users))
	m.HandleFunc("GET /admin/users/{id}", s.RequireAdmin(a.user))
	m.HandleFunc("POST /admin/users/{id}/revoke", s.RequireAdmin(a.revoke))
	m.HandleFunc("POST /admin/users/{id}/revalidate", s.RequireAdmin(a.revalidate))
	m.HandleFunc("GET /admin/audit", s.RequireAdmin(a.audit))
	m.HandleFunc("GET /admin/audit.csv", s.RequireAdmin(a.auditCSV))
	m.HandleFunc("GET /admin/status", s.RequireAdmin(a.status))
	m.HandleFunc("POST /admin/processes/{name}/restart", s.RequireAdmin(a.restartProcess))
	m.HandleFunc("POST /admin/blocks/unblock", s.RequireAdmin(a.unblock))
	m.HandleFunc("POST /admin/certificate", s.RequireAdmin(a.uploadCert))
	m.HandleFunc("GET /admin/settings", s.RequireAdmin(a.settings))
	m.HandleFunc("POST /admin/settings", s.RequireAdmin(a.settingsSave))
	m.HandleFunc("GET /admin/configs", s.RequireAdmin(a.configs))
	m.HandleFunc("GET /admin/configs/{name}", s.RequireAdmin(a.configEdit))
	m.HandleFunc("POST /admin/configs/{name}", s.RequireAdmin(a.configSave))
	if h.Tunnels != nil {
		a.registerTunnels()
	}
	return a
}

func (a *Admin) actor(r *http.Request) string {
	if s := a.CurrentSession(r); s != nil {
		return s.Username
	}
	return "?"
}

// --- sessions ---

type sessionTotals struct {
	Count           int
	In, Out         uint64
	RateIn, RateOut float64
}

func (a *Admin) filteredSessions(r *http.Request) ([]core.Session, sessionTotals) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	proto := r.URL.Query().Get("protocol")
	var out []core.Session
	var t sessionTotals
	for _, s := range a.Core.Sessions() {
		if q != "" && !strings.Contains(strings.ToLower(s.Username+" "+s.Email+" "+s.Login), q) {
			continue
		}
		if proto != "" && s.Protocol != proto {
			continue
		}
		out = append(out, s)
		t.Count++
		t.In += s.BytesIn
		t.Out += s.BytesOut
		t.RateIn += s.RateIn
		t.RateOut += s.RateOut
	}
	return out, t
}

func (a *Admin) sessions(w http.ResponseWriter, r *http.Request) {
	if !a.Cfg.VPNEnabled() {
		http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		return
	}
	list, totals := a.filteredSessions(r)
	a.Render(w, r, http.StatusOK, "admin_sessions", &portal.Page{Title: "Sessions", Nav: "sessions", Data: map[string]any{
		"Sessions": list, "Totals": totals, "User": r.URL.Query().Get("user"), "Protocol": r.URL.Query().Get("protocol"),
		"Protocols": config.Protocols,
	}})
}

func (a *Admin) sessionsStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	csrf := a.CurrentSession(r).Web.CSRF
	send := func() bool {
		list, totals := a.filteredSessions(r)
		rows, err := a.RenderPartial("session-rows", map[string]any{"Sessions": list, "CSRF": csrf})
		if err != nil {
			slog.Error("render session rows", "err", err)
			return false
		}
		foot, _ := a.RenderPartial("session-foot", totals)
		payload, _ := json.Marshal(map[string]any{"rows": rows, "foot": foot, "count": totals.Count})
		if _, err := fmt.Fprintf(w, "event: sessions\ndata: %s\n\n", payload); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	if !send() {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			if !send() {
				return
			}
		}
	}
}

func (a *Admin) disconnect(w http.ResponseWriter, r *http.Request) {
	ip := core.AddrFromString(r.FormValue("ip"))
	if err := a.Core.Disconnect(ip, "disconnected by administrator", a.actor(r)); err != nil {
		portal.Flash(w, "warn", "Disconnect: "+err.Error())
	} else {
		portal.Flash(w, "ok", "Session "+ip.String()+" disconnected.")
	}
	back(w, r, "/admin")
}

func back(w http.ResponseWriter, r *http.Request, def string) {
	ref := r.Referer()
	if i := strings.Index(ref, "/admin"); i >= 0 {
		def = ref[i:]
	}
	http.Redirect(w, r, def, http.StatusSeeOther)
}

func (a *Admin) revoke(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.Core.RevokeUser(id, "disconnected by administrator "+a.actor(r), a.actor(r)); err != nil {
		portal.Flash(w, "bad", "Revoke failed: "+err.Error())
	} else {
		portal.Flash(w, "ok", "User disconnected and VPN password revoked. The user gets a new password at the next portal sign-in.")
	}
	back(w, r, "/admin/users")
}

func (a *Admin) revalidate(w http.ResponseWriter, r *http.Request) {
	a.Core.RevalidateNow()
	portal.Flash(w, "ok", "Revalidation of all sessions started.")
	back(w, r, "/admin/users")
}

// --- users ---

type userRow struct {
	*store.User
	VPNGroups []string
	Sessions  int
	Traffic1  [2]int64
	Traffic3  [2]int64
}

func (a *Admin) users(w http.ResponseWriter, r *http.Request) {
	users, err := a.Store.Users()
	if err != nil {
		a.Error(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	day, _ := a.Store.TrafficTotals(time.Now().Add(-24 * time.Hour))
	month, _ := a.Store.TrafficTotals(time.Now().Add(-30 * 24 * time.Hour))
	active := map[int64]int{}
	for _, s := range a.Core.Sessions() {
		active[s.UserID]++
	}
	q := strings.ToLower(r.URL.Query().Get("q"))
	var rows []userRow
	for _, u := range users {
		if q != "" && !strings.Contains(strings.ToLower(u.Username+" "+u.Email+" "+strings.Join(u.Groups, " ")), q) {
			continue
		}
		rows = append(rows, userRow{User: u, VPNGroups: a.Core.VPNGroups(u), Sessions: active[u.ID], Traffic1: day[u.ID], Traffic3: month[u.ID]})
	}
	a.Render(w, r, http.StatusOK, "admin_users", &portal.Page{Title: "Users", Nav: "users", Data: map[string]any{"Users": rows, "Q": r.URL.Query().Get("q")}})
}

func (a *Admin) user(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := a.Store.UserByID(id)
	if err != nil {
		a.Error(w, r, http.StatusNotFound, "User not found.")
		return
	}
	hours, _ := a.Store.Traffic(id, "hour", time.Now().Add(-48*time.Hour))
	days, _ := a.Store.Traffic(id, "day", time.Now().AddDate(0, 0, -30))
	hist, _ := a.Store.RecentSessions(id, 30)
	journal, _ := a.Store.Audit(store.AuditFilter{Username: u.Username, Limit: 15})
	var logins []loginRouting
	for _, o := range a.Core.AvailableLogins(u) {
		lr := loginRouting{LoginOption: o}
		if o.Profile != nil {
			lr.Via, lr.Default = a.profileTunnels(o.Profile)
			if routes, widened := policy.Widen(o.Profile.Routes(), a.Cfg.Int("ANYCONNECT_ROUTE_LIMIT")); widened {
				lr.Widened = len(routes)
			}
		}
		logins = append(logins, lr)
	}
	a.Render(w, r, http.StatusOK, "admin_user", &portal.Page{Title: u.Username, Nav: "users", Data: map[string]any{
		"VPNGroups": a.Core.VPNGroups(u),
		"User":      u, "Logins": logins, "Sessions": a.Core.UserSessions(id, false),
		"HourChart": chart(hours, 48, time.Hour), "DayChart": chart(days, 30, 24*time.Hour), "History": hist, "Journal": journal,
	}})
}

// loginRouting is a VPN login with where its traffic goes.
type loginRouting struct {
	core.LoginOption
	Via     []string // allowed networks behind tunnel peers
	Default string   // where everything else goes
	Widened int      // AnyConnect routes after widening (0 = not needed)
}

// --- audit ---

func (a *Admin) auditFilter(r *http.Request) store.AuditFilter {
	q := r.URL.Query()
	f := store.AuditFilter{Username: q.Get("user"), Event: q.Get("event"), Protocol: q.Get("protocol"), Search: q.Get("q")}
	if d, err := time.Parse("2006-01-02", q.Get("since")); err == nil {
		f.Since = d
	}
	if d, err := time.Parse("2006-01-02", q.Get("until")); err == nil {
		f.Until = d.Add(24 * time.Hour)
	}
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	return f
}

func (a *Admin) audit(w http.ResponseWriter, r *http.Request) {
	f := a.auditFilter(r)
	f.Limit = 50
	entries, err := a.Store.Audit(f)
	if err != nil {
		a.Error(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	next := ""
	if len(entries) == f.Limit {
		q := r.URL.Query()
		q.Set("before", strconv.FormatInt(entries[len(entries)-1].ID, 10))
		next = "/admin/audit?" + q.Encode()
	}
	csvq := r.URL.Query()
	csvq.Del("before")
	a.Render(w, r, http.StatusOK, "admin_audit", &portal.Page{Title: "Journal", Nav: "audit", Data: map[string]any{
		"Entries": entries, "F": r.URL.Query(), "Next": next, "Paged": f.BeforeID != 0, "First": "/admin/audit?" + csvq.Encode(), "CSV": "/admin/audit.csv?" + csvq.Encode(), "Protocols": config.Protocols,
		"Events": []string{"portal.", "password.", "vpn.connect", "vpn.disconnect", "vpn.denied", "vpn.kill", "user.revoked", "oidc.", "auth.blocked", "policy.", "admin."},
	}})
}

func (a *Admin) auditCSV(w http.ResponseWriter, r *http.Request) {
	f := a.auditFilter(r)
	f.Limit = 100000
	entries, err := a.Store.Audit(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"vpngw-journal-%s.csv\"", time.Now().UTC().Format("20060102-150405")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time_utc", "level", "event", "actor", "user", "protocol", "ip", "message"})
	for _, e := range entries {
		_ = cw.Write([]string{e.TS.UTC().Format(time.RFC3339), e.Level, e.Event, e.Actor, e.Username, e.Protocol, e.IP, e.Message})
	}
	cw.Flush()
}

// --- status ---

type poolStatus struct {
	Protocol string
	Prefix   string
	Used     int
	Size     int
}

func (a *Admin) status(w http.ResponseWriter, r *http.Request) {
	var procs []supervisor.Status
	for _, p := range a.Processes {
		procs = append(procs, p.Status())
	}
	var pools []poolStatus
	for _, proto := range config.Protocols {
		if p := a.Core.IPAM.Pool(proto); p != nil {
			pools = append(pools, poolStatus{proto, p.Prefix().String(), p.Used(), p.Size()})
		}
	}
	lastOK, idpErr := a.OIDC.Health()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	dbErr := a.Store.Ping(ctx)
	blocks := a.Core.Limiter().BlockedKeys()
	keys := make([]string, 0, len(blocks))
	for k := range blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	data := map[string]any{
		"Processes": procs, "Pools": pools, "IdPLastOK": lastOK, "IdPError": idpErr, "DBError": dbErr,
		"Cert": a.TLS.Info(), "Uncovered": a.TLS.Uncovered(), "Endpoints": a.Cfg.Endpoints(), "Blocks": blocks, "BlockKeys": keys, "Issuer": a.Cfg.Str("OIDC_ISSUER"),
	}
	if a.Hooks.FirewallCounters != nil {
		data["Counters"] = a.counters()
	}
	if a.Hooks.Gateways != nil {
		data["Gateways"] = a.Hooks.Gateways()
	}
	if a.Hooks.EgressIface != nil {
		data["Egress"] = a.Hooks.EgressIface()
	}
	if r.URL.Query().Get("ruleset") == "1" && a.Hooks.FirewallRuleset != nil {
		data["Ruleset"] = a.Hooks.FirewallRuleset()
	}
	a.Render(w, r, http.StatusOK, "admin_status", &portal.Page{Title: "Status", Nav: "status", Data: data})
}

func (a *Admin) restartProcess(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, p := range a.Processes {
		if p.Name == name {
			p.Restart()
			a.Core.Audit("info", "admin.restart", a.actor(r), "", "", portal.ClientIP(r), "restarted "+name)
			portal.Flash(w, "ok", name+" is restarting.")
		}
	}
	back(w, r, "/admin/status")
}

func (a *Admin) unblock(w http.ResponseWriter, r *http.Request) {
	k := r.FormValue("key")
	a.Core.Limiter().Unblock(k)
	a.Core.Audit("info", "admin.unblock", a.actor(r), "", "", portal.ClientIP(r), "unblocked "+k)
	portal.Flash(w, "ok", k+" unblocked.")
	http.Redirect(w, r, "/admin/status", http.StatusSeeOther)
}

func (a *Admin) uploadCert(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		portal.Flash(w, "bad", err.Error())
		back(w, r, "/admin/status")
		return
	}
	cert, key := []byte(r.FormValue("cert")), []byte(r.FormValue("key"))
	if err := a.TLS.Upload(cert, key); err != nil {
		portal.Flash(w, "bad", "Certificate rejected: "+err.Error())
	} else {
		i := a.TLS.Info()
		a.Core.Audit("info", "admin.certificate", a.actor(r), "", "", portal.ClientIP(r),
			fmt.Sprintf("certificate uploaded: %s, valid until %s", strings.Join(i.DNSNames, ","), i.NotAfter.UTC().Format(time.RFC3339)))
		portal.Flash(w, "ok", "Certificate installed and reloaded in all services.")
	}
	http.Redirect(w, r, "/admin/status", http.StatusSeeOther)
}
