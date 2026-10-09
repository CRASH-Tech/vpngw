package admin

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"vpngw/internal/config"
	"vpngw/internal/portal"
	"vpngw/internal/store"
)

type settingView struct {
	Def      config.Def
	Value    string
	Source   config.Source
	EnvValue string
	HasEnv   bool
	IsSecret bool
	IsBool   bool
}

type settingGroup struct {
	Name     string
	Settings []settingView
}

func (a *Admin) settings(w http.ResponseWriter, r *http.Request) {
	var groups []settingGroup
	idx := map[string]int{}
	for _, d := range config.Defs {
		v, src := a.Cfg.Resolve(d.Key)
		env, hasEnv := a.Cfg.EnvValue(d.Key)
		sv := settingView{Def: d, Value: v, Source: src, EnvValue: env, HasEnv: hasEnv, IsSecret: d.Kind == config.Secret, IsBool: d.Kind == config.Bool}
		if sv.IsSecret {
			sv.Value = ""
			if sv.HasEnv {
				sv.EnvValue = "(set)"
			}
		}
		i, ok := idx[d.Group]
		if !ok {
			i = len(groups)
			idx[d.Group] = i
			groups = append(groups, settingGroup{Name: d.Group})
		}
		groups[i].Settings = append(groups[i].Settings, sv)
	}
	// Tabs in a fixed order; OIDC-dependent groups are hidden without user VPN.
	order := []string{"General", "OIDC", "Tunnels", "Network", "Protocols", "Certificates", "Admin", "Security"}
	vpnOnly := map[string]bool{"Network": true, "Protocols": true}
	var tabs []settingGroup
	for _, name := range order {
		if i, ok := idx[name]; ok && (a.Cfg.VPNEnabled() || !vpnOnly[name]) {
			tabs = append(tabs, groups[i])
		}
	}
	a.Render(w, r, http.StatusOK, "admin_settings", &portal.Page{Title: "Settings", Nav: "settings", Data: map[string]any{"Groups": tabs}})
}

func (a *Admin) settingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.Error(w, r, http.StatusBadRequest, err.Error())
		return
	}
	changes := map[string]*string{}
	for _, d := range config.Defs {
		if _, env := a.Cfg.EnvValue(d.Key); env {
			continue // fixed by the environment
		}
		if r.PostForm.Get("reset_"+d.Key) == "1" {
			if _, src := a.Cfg.Resolve(d.Key); src == config.SourceAdmin {
				changes[d.Key] = nil
			}
			continue
		}
		vals, present := r.PostForm["v_"+d.Key]
		if !present {
			continue
		}
		v := strings.TrimSpace(vals[len(vals)-1])
		if d.Kind == config.Secret && v == "" {
			continue // unchanged
		}
		if cur, _ := a.Cfg.Resolve(d.Key); cur == v {
			continue
		}
		vv := v
		changes[d.Key] = &vv
	}
	if len(changes) == 0 {
		portal.Flash(w, "ok", "No changes.")
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}
	for k, v := range changes {
		d, _ := config.Lookup(k)
		if v != nil {
			if err := config.Validate(d, *v); err != nil {
				portal.Flash(w, "bad", fmt.Sprintf("%s: %v", k, err))
				http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
				return
			}
		}
	}
	var restart []string
	var keys []string
	for k, v := range changes {
		if err := a.Store.SetSetting(k, v, a.actor(r)); err != nil {
			a.Error(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		d, _ := config.Lookup(k)
		if d.Restart {
			restart = append(restart, k)
		}
		keys = append(keys, k)
	}
	if err := a.Cfg.Apply(changes); err != nil {
		portal.Flash(w, "bad", err.Error())
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}
	a.Core.Audit("info", "admin.settings", a.actor(r), "", "", portal.ClientIP(r), "settings changed: "+strings.Join(keys, ", "))
	msg := "Saved: " + strings.Join(keys, ", ") + "."
	if len(restart) > 0 {
		msg += " Backends were restarted where needed; changes to " + strings.Join(restart, ", ") +
			" that affect the whole gateway (hostnames, pools, OIDC client, data dir) apply after a container restart."
	}
	portal.Flash(w, "ok", msg)
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}

// --- configs ---

type configView struct {
	Name       string
	Backend    string
	Path       string
	Overridden bool
	UpdatedAt  time.Time
	UpdatedBy  string
	Secret     bool
}

func (a *Admin) configs(w http.ResponseWriter, r *http.Request) {
	ov, _ := a.Store.ConfigOverrides()
	var list []configView
	for _, f := range a.Configs.Files() {
		o, ok := ov[f.Name]
		list = append(list, configView{Name: f.Name, Backend: f.Backend, Path: f.Path, Overridden: ok, UpdatedAt: o.UpdatedAt, UpdatedBy: o.UpdatedBy, Secret: f.Secret})
	}
	a.Render(w, r, http.StatusOK, "admin_configs", &portal.Page{Title: "Configs", Nav: "configs", Data: map[string]any{"Files": list}})
}

func (a *Admin) configEdit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	f, ok := a.Configs.Get(name)
	if !ok {
		a.Error(w, r, http.StatusNotFound, "Unknown config file.")
		return
	}
	eff, over, err := a.Configs.Effective(name)
	if err != nil {
		a.Error(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	gen, _ := f.Generate()
	ov, _ := a.Store.ConfigOverrides()
	a.Render(w, r, http.StatusOK, "admin_config_edit", &portal.Page{Title: name, Nav: "configs", Data: map[string]any{
		"File": f, "Effective": eff, "Generated": gen, "Overridden": over, "Override": ov[name], "Diff": template.HTML(diffHTML(gen, eff)),
	}})
}

func (a *Admin) configSave(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	f, ok := a.Configs.Get(name)
	if !ok {
		a.Error(w, r, http.StatusNotFound, "Unknown config file.")
		return
	}
	var err error
	switch r.FormValue("action") {
	case "reset":
		err = a.Store.SetConfigOverride(name, nil, a.actor(r))
		a.Core.Audit("info", "admin.config", a.actor(r), "", f.Backend, portal.ClientIP(r), "config "+name+" reset to generated")
	default:
		content := strings.ReplaceAll(r.FormValue("content"), "\r\n", "\n")
		gen, _ := f.Generate()
		if content == gen {
			err = a.Store.SetConfigOverride(name, nil, a.actor(r))
		} else {
			err = a.Store.SetConfigOverride(name, &content, a.actor(r))
		}
		a.Core.Audit("info", "admin.config", a.actor(r), "", f.Backend, portal.ClientIP(r), "config "+name+" edited manually")
	}
	if err != nil {
		portal.Flash(w, "bad", err.Error())
	} else {
		if a.Hooks.RestartBackend != nil {
			a.Hooks.RestartBackend(f.Backend)
		}
		portal.Flash(w, "ok", "Saved. "+config.ProtocolTitle(f.Backend)+" is restarting with the new configuration.")
	}
	http.Redirect(w, r, "/admin/configs/"+name, http.StatusSeeOther)
}

// diffHTML renders a minimal line diff (generated → effective).
func diffHTML(a, b string) string {
	if a == b {
		return ""
	}
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	// LCS table (configs are small).
	n, m := len(al), len(bl)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var sb strings.Builder
	i, j := 0, 0
	esc := template.HTMLEscapeString
	for i < n || j < m {
		switch {
		case i < n && j < m && al[i] == bl[j]:
			i++
			j++
		case j < m && (i == n || dp[i][j+1] >= dp[i+1][j]):
			sb.WriteString(`<div class="diff-add">+ ` + esc(bl[j]) + "</div>")
			j++
		default:
			sb.WriteString(`<div class="diff-del">- ` + esc(al[i]) + "</div>")
			i++
		}
	}
	return sb.String()
}

// --- chart ---

type bar struct {
	X, W     float64
	HRX, HTX float64
	YRX, YTX float64
	Label    string
}

type chartData struct {
	Bars  []bar
	MaxRX int64
	MaxTX int64
	Total [2]int64
	Max   int64
}

// chart lays out an SVG bar chart (viewBox 0 0 600 150).
func chart(points []store.TrafficPoint, n int, step time.Duration) chartData {
	byTS := map[int64]store.TrafficPoint{}
	for _, p := range points {
		byTS[p.TS.Unix()] = p
	}
	now := time.Now()
	var start time.Time
	if step == time.Hour {
		start = now.Truncate(time.Hour).Add(-time.Duration(n-1) * time.Hour)
	} else {
		y, mo, d := now.UTC().Date()
		start = time.Date(y, mo, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -(n - 1))
	}
	var cd chartData
	vals := make([]store.TrafficPoint, n)
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(i) * step)
		if step != time.Hour {
			ts = start.AddDate(0, 0, i)
		}
		vals[i] = byTS[ts.Unix()]
		vals[i].TS = ts
		cd.Max = max(cd.Max, vals[i].RX, vals[i].TX)
		cd.Total[0] += vals[i].RX
		cd.Total[1] += vals[i].TX
	}
	w := 600.0 / float64(n)
	for i, v := range vals {
		b := bar{X: float64(i) * w, W: w * 0.42}
		if cd.Max > 0 {
			b.HRX = 140 * float64(v.RX) / float64(cd.Max)
			b.HTX = 140 * float64(v.TX) / float64(cd.Max)
		}
		b.YRX, b.YTX = 145-b.HRX, 145-b.HTX
		if step == time.Hour {
			b.Label = v.TS.UTC().Format("Jan 2 15:00")
		} else {
			b.Label = v.TS.UTC().Format("Jan 2")
		}
		cd.Bars = append(cd.Bars, b)
	}
	return cd
}
