package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/oidc"
	"vpngw/internal/secret"
	"vpngw/internal/store"
	"vpngw/internal/supervisor"
	"vpngw/internal/tlsmgr"
)

type netipPrefix = netip.Prefix

func slogLogger() *log.Logger { return log.New(slogWriter{}, "", 0) }

type healthHandler struct {
	st    *store.Store
	procs []*supervisor.Process
	oc    *oidc.Client
	core  *core.Core
	tls   *tlsmgr.Manager
}

// ServeHTTP reports liveness: database reachable and all enabled
// backends running (a backend restarting for less than a minute is tolerated).
func (h *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	res := map[string]any{"status": "ok"}
	code := http.StatusOK
	if err := h.st.Ping(ctx); err != nil {
		res["database"] = err.Error()
		code = http.StatusServiceUnavailable
	}
	procs := map[string]string{}
	for _, p := range h.procs {
		s := p.Status()
		if s.Running {
			procs[s.Name] = "running"
		} else {
			procs[s.Name] = "down"
		}
	}
	res["backends"] = procs
	if t, err := h.oc.Health(); err != nil {
		res["idp"] = "error"
	} else if !t.IsZero() {
		res["idp_last_ok"] = t.UTC().Format(time.RFC3339)
	}
	if code != http.StatusOK {
		res["status"] = "error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(res)
}

// metricsAuth lets localhost through; others need an address in
// METRICS_ALLOWED_NETWORKS (if set) and the METRICS_TOKEN (if set). With
// neither set, only localhost may read the metrics.
func metricsAuth(cfg *config.Config, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		addr, err := netip.ParseAddr(host)
		addr = addr.Unmap()
		if err == nil && addr.IsLoopback() {
			next(w, r)
			return
		}
		nets, tok := cfg.MetricsNetworks(), cfg.Str("METRICS_TOKEN")
		inNets := false
		for _, p := range nets {
			if err == nil && p.Contains(addr) {
				inNets = true
			}
		}
		tokOK := tok != "" && secret.Equal(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), tok)
		allowed := (len(nets) > 0 && inNets && (tok == "" || tokOK)) || (len(nets) == 0 && tokOK)
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// metrics renders Prometheus text exposition.
func (h *healthHandler) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	type agg struct {
		n       int
		in, out uint64
	}
	per := map[string]*agg{}
	for _, p := range config.Protocols {
		per[p] = &agg{}
	}
	for _, s := range h.core.Sessions() {
		if a, ok := per[s.Protocol]; ok {
			a.n++
			a.in += s.BytesIn
			a.out += s.BytesOut
		}
	}
	b.WriteString("# HELP vpngw_sessions Active VPN sessions.\n# TYPE vpngw_sessions gauge\n")
	for _, p := range config.Protocols {
		fmt.Fprintf(&b, "vpngw_sessions{protocol=%q} %d\n", p, per[p].n)
	}
	b.WriteString("# HELP vpngw_session_bytes Bytes of active sessions.\n# TYPE vpngw_session_bytes gauge\n")
	for _, p := range config.Protocols {
		fmt.Fprintf(&b, "vpngw_session_bytes{protocol=%q,direction=\"in\"} %d\n", p, per[p].in)
		fmt.Fprintf(&b, "vpngw_session_bytes{protocol=%q,direction=\"out\"} %d\n", p, per[p].out)
	}
	b.WriteString("# HELP vpngw_pool_used Allocated addresses per pool.\n# TYPE vpngw_pool_used gauge\n")
	for _, p := range config.Protocols {
		if pool := h.core.IPAM.Pool(p); pool != nil {
			fmt.Fprintf(&b, "vpngw_pool_used{protocol=%q} %d\n", p, pool.Used())
		}
	}
	b.WriteString("# HELP vpngw_pool_size Addresses per pool.\n# TYPE vpngw_pool_size gauge\n")
	for _, p := range config.Protocols {
		if pool := h.core.IPAM.Pool(p); pool != nil {
			fmt.Fprintf(&b, "vpngw_pool_size{protocol=%q} %d\n", p, pool.Size())
		}
	}
	b.WriteString("# HELP vpngw_backend_up Backend process running.\n# TYPE vpngw_backend_up gauge\n")
	for _, p := range h.procs {
		up := 0
		if p.Running() {
			up = 1
		}
		fmt.Fprintf(&b, "vpngw_backend_up{backend=%q} %d\n", p.Name, up)
	}
	if t, _ := h.oc.Health(); !t.IsZero() {
		fmt.Fprintf(&b, "# HELP vpngw_idp_last_success_timestamp_seconds Last successful IdP call.\n# TYPE vpngw_idp_last_success_timestamp_seconds gauge\nvpngw_idp_last_success_timestamp_seconds %d\n", t.Unix())
	}
	if users, err := h.st.UsersWithPassword(); err == nil {
		fmt.Fprintf(&b, "# HELP vpngw_users_with_password Users holding a VPN password.\n# TYPE vpngw_users_with_password gauge\nvpngw_users_with_password %d\n", len(users))
	}
	if i := h.tls.Info(); !i.NotAfter.IsZero() {
		fmt.Fprintf(&b, "# HELP vpngw_certificate_expiry_timestamp_seconds Server certificate expiry.\n# TYPE vpngw_certificate_expiry_timestamp_seconds gauge\nvpngw_certificate_expiry_timestamp_seconds %d\n", i.NotAfter.Unix())
	}
	fmt.Fprintf(&b, "# HELP vpngw_blocked_keys Logins/IPs blocked after failures.\n# TYPE vpngw_blocked_keys gauge\nvpngw_blocked_keys %d\n", len(h.core.Limiter().BlockedKeys()))
	writeUserMetrics(&b, h.core.UserStats(), h.core.Sessions())
	_, _ = w.Write([]byte(b.String()))
}

// writeUserMetrics adds who connected, over which protocol, and how much
// traffic: counters per user and protocol since the gateway started, and
// one series per live session.
func writeUserMetrics(b *strings.Builder, stats []core.UserStat, sessions []core.Session) {
	b.WriteString("# HELP vpngw_user_connections_total VPN sessions established per user and protocol.\n# TYPE vpngw_user_connections_total counter\n")
	for _, st := range stats {
		fmt.Fprintf(b, "vpngw_user_connections_total{user=%s,protocol=%s} %d\n", label(st.Username), label(st.Protocol), st.Connections)
	}
	b.WriteString("# HELP vpngw_user_traffic_bytes_total Traffic per user and protocol (received: from the client, sent: to the client).\n# TYPE vpngw_user_traffic_bytes_total counter\n")
	for _, st := range stats {
		fmt.Fprintf(b, "vpngw_user_traffic_bytes_total{user=%s,protocol=%s,direction=\"received\"} %d\n", label(st.Username), label(st.Protocol), st.BytesIn)
		fmt.Fprintf(b, "vpngw_user_traffic_bytes_total{user=%s,protocol=%s,direction=\"sent\"} %d\n", label(st.Username), label(st.Protocol), st.BytesOut)
	}
	b.WriteString("# HELP vpngw_user_sessions Live sessions per user and protocol.\n# TYPE vpngw_user_sessions gauge\n")
	for _, st := range stats {
		fmt.Fprintf(b, "vpngw_user_sessions{user=%s,protocol=%s} %d\n", label(st.Username), label(st.Protocol), st.Active)
	}
	b.WriteString("# HELP vpngw_user_last_connect_timestamp_seconds Last session established per user and protocol.\n# TYPE vpngw_user_last_connect_timestamp_seconds gauge\n")
	for _, st := range stats {
		if !st.LastConnect.IsZero() {
			fmt.Fprintf(b, "vpngw_user_last_connect_timestamp_seconds{user=%s,protocol=%s} %d\n", label(st.Username), label(st.Protocol), st.LastConnect.Unix())
		}
	}
	// One metric family at a time: the text format wants each contiguous.
	var live []core.Session
	for _, s := range sessions {
		if s.State == core.StateActive {
			live = append(live, s)
		}
	}
	lbl := func(s core.Session) string {
		return fmt.Sprintf("user=%s,login=%s,protocol=%s,vpn_ip=%s,client_ip=%s", label(s.Username), label(s.Login), label(s.Protocol), label(s.VPNIP.String()), label(s.ClientIP))
	}
	b.WriteString("# HELP vpngw_session_traffic_bytes Traffic of a live session.\n# TYPE vpngw_session_traffic_bytes gauge\n")
	for _, s := range live {
		fmt.Fprintf(b, "vpngw_session_traffic_bytes{%s,direction=\"received\"} %d\n", lbl(s), s.BytesIn)
		fmt.Fprintf(b, "vpngw_session_traffic_bytes{%s,direction=\"sent\"} %d\n", lbl(s), s.BytesOut)
	}
	b.WriteString("# HELP vpngw_session_start_timestamp_seconds Start of a live session.\n# TYPE vpngw_session_start_timestamp_seconds gauge\n")
	for _, s := range live {
		fmt.Fprintf(b, "vpngw_session_start_timestamp_seconds{%s} %d\n", lbl(s), s.StartedAt.Unix())
	}
}

// label quotes a Prometheus label value.
func label(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
}
