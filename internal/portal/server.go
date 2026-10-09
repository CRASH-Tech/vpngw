// Package portal serves the user portal and hosts the admin panel routes.
package portal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"vpngw/internal/backend"
	"vpngw/internal/clients"
	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/oidc"
	"vpngw/internal/secret"
	"vpngw/internal/store"
	"vpngw/internal/supervisor"
	"vpngw/internal/tlsmgr"
	"vpngw/templates"
)

// Deps are the collaborators of the web layer.
type Deps struct {
	Core      *core.Core
	Cfg       *config.Config
	Store     *store.Store
	OIDC      *oidc.Client
	TLS       *tlsmgr.Manager
	Configs   *backend.Configs
	Processes []*supervisor.Process
	// OVPNProfile renders an .ovpn profile for (username, tls metadata,
	// remotes, connection name, saved login, saved password).
	OVPNProfile func(username, meta string, remotes []string, name, login, password string) (string, error)
	Version     string
}

// Server is the HTTP handler of portal and admin panel.
type Server struct {
	Deps
	Mux     *http.ServeMux
	pages   map[string]*template.Template
	Clients *clients.Catalog
}

const (
	sessionCookie = "vpngw_session"
	authCookie    = "vpngw_auth"
	// signedOutCookie makes the next SSO sign-in ask for credentials.
	signedOutCookie = "vpngw_signed_out"
	sessionTTL      = 12 * time.Hour
)

// New builds the server and registers portal routes.
func New(d Deps) (*Server, error) {
	s := &Server{Deps: d, Mux: http.NewServeMux(), pages: map[string]*template.Template{}}
	s.Clients = &clients.Catalog{Dir: func() string { return d.Cfg.Str("CLIENTS_DIR") }}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	static, _ := fs.Sub(templates.Web, "web/static")
	fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	s.Mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") != "" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	}))
	s.Mux.HandleFunc("GET /{$}", s.handleHome)
	s.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.Error(w, r, http.StatusNotFound, "Page not found.")
	})
	s.Mux.HandleFunc("GET /login", s.handleLogin)
	s.Mux.HandleFunc("GET /oidc/callback", s.handleCallback)
	s.Mux.HandleFunc("POST /oidc/backchannel-logout", s.handleBackchannel)
	s.Mux.HandleFunc("GET /login/local", s.handleLocalLoginForm)
	s.Mux.HandleFunc("POST /login/local", s.handleLocalLogin)
	s.Mux.HandleFunc("POST /logout", s.requireLogin(s.handleLogout))
	s.Mux.HandleFunc("POST /password/reissue", s.requireLogin(s.handleReissue))
	s.Mux.HandleFunc("POST /sessions/disconnect", s.requireLogin(s.handleUserDisconnect))
	s.Mux.HandleFunc("GET /download/{kind}", s.requireLogin(s.handleDownload))
	s.Mux.HandleFunc("GET /clients/{file...}", s.requireLogin(s.handleClient))
	// Links of older pages (one-time tokens).
	s.Mux.HandleFunc("GET /dl/{token}", s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		Flash(w, "warn", "That download link was from an older page. Download again below.")
		http.Redirect(w, r, "/#connect", http.StatusSeeOther)
	}))
	return s, nil
}

var funcs = template.FuncMap{
	"bytes":        humanBytes,
	"rate":         func(v float64) string { return humanBytes(uint64(v)) + "/s" },
	"ago":          ago,
	"dur":          humanDuration,
	"ts":           func(t time.Time) string { return fmtTS(t) },
	"proto":        config.ProtocolTitle,
	"join":         strings.Join,
	"lower":        strings.ToLower,
	"add":          func(a, b int) int { return a + b },
	"add2":         func(a, b float64) float64 { return a + b },
	"pct":          func(a, b int) int { return pct(a, b) },
	"claim":        core.ClaimJSON,
	"contains":     strings.Contains,
	"until":        func(t time.Time) string { return humanDuration(time.Until(t)) },
	"isZero":       func(t time.Time) bool { return t.IsZero() },
	"uint":         func(v int64) uint64 { return uint64(max(v, 0)) },
	"list":         func(items ...any) []any { return items },
	"choice":       func(s string) bool { return strings.HasPrefix(s, "!") },
	"choiceText":   func(s string) string { return strings.TrimPrefix(s, "!") },
	"profileName":  ProfileName,
	"ipsecCommand": IPsecCommand,
	"profileNames": func(host string, logins []string) []string {
		out := make([]string, len(logins))
		for i, l := range logins {
			out[i] = ProfileName(host, l)
		}
		return out
	},
	// field is a row of a settings table: the client's field label and the
	// value(s) to enter; a value starting with "!" is an instruction, not
	// something to type.
	"field": func(label string, value any, note string) map[string]any {
		var vals []string
		switch v := value.(type) {
		case string:
			vals = []string{v}
		case []string:
			vals = v
		}
		return map[string]any{"Label": label, "Values": vals, "Note": note}
	},
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[fmt.Sprint(kv[i])] = kv[i+1]
		}
		return m
	},
}

func pct(a, b int) int {
	if b <= 0 {
		return 0
	}
	return a * 100 / b
}

// assetVersion changes whenever a static file changes: links carry it, so
// browsers fetch new CSS/JS right after an update despite caching.
var assetVersion = func() string {
	h := sha256.New()
	_ = fs.WalkDir(templates.Web, "web/static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(templates.Web, p)
			h.Write([]byte(p))
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

func (s *Server) loadTemplates() error {
	shared := []string{"web/base.html", "web/partials.html", "web/instructions.html"}
	pagesDir, err := fs.Glob(templates.Web, "web/page_*.html")
	if err != nil {
		return err
	}
	for _, p := range pagesDir {
		files := append(append([]string{}, shared...), p)
		t, err := template.New(path.Base(p)).Funcs(funcs).ParseFS(templates.Web, files...)
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(path.Base(p), "page_"), ".html")
		s.pages[name] = t
	}
	partials, err := template.New("partials").Funcs(funcs).ParseFS(templates.Web, "web/partials.html")
	if err != nil {
		return err
	}
	s.pages["_partials"] = partials
	return nil
}

// Page is the data passed to every page template.
type Page struct {
	Title     string
	Nav       string
	Session   *Session
	CSRF      string
	Flash     string
	FlashKind string
	Data      any
	Version   string
	PortalURL string
	VPN       bool   // user VPN enabled (OIDC configured)
	Asset     string // content hash of the static files (cache busting)
	Node      string // name of this gateway
}

// Render renders a page.
func (s *Server) Render(w http.ResponseWriter, r *http.Request, status int, name string, p *Page) {
	t, ok := s.pages[name]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	if p.Session == nil {
		p.Session = s.CurrentSession(r)
	}
	if p.Session != nil {
		p.CSRF = p.Session.Web.CSRF
	}
	if p.Flash == "" {
		if c, err := r.Cookie("vpngw_flash"); err == nil {
			if v, err := url.QueryUnescape(c.Value); err == nil {
				kind, msg, _ := strings.Cut(v, "|")
				p.Flash, p.FlashKind = msg, kind
			}
			http.SetCookie(w, &http.Cookie{Name: "vpngw_flash", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
		}
	}
	p.Version = s.Version
	p.PortalURL = s.Cfg.PortalURL()
	p.VPN = s.Cfg.VPNEnabled()
	p.Asset = assetVersion
	p.Node = s.Cfg.NodeName()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", p); err != nil {
		slog.Error("render", "page", name, "err", err)
	}
}

// RenderPartial renders a named template from partials.html into a string.
func (s *Server) RenderPartial(name string, data any) (string, error) {
	var b strings.Builder
	err := s.pages["_partials"].ExecuteTemplate(&b, name, data)
	return b.String(), err
}

// Flash sets a one-time message shown on the next page.
func Flash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{Name: "vpngw_flash", Value: url.QueryEscape(kind + "|" + msg), Path: "/", MaxAge: 60,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// Error renders an error page.
func (s *Server) Error(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.Render(w, r, status, "error", &Page{Title: http.StatusText(status), Data: map[string]any{"Status": status, "Message": msg}})
}

// --- sessions ---

// Session is the authenticated portal context.
type Session struct {
	Web       *store.WebSession
	User      *store.User // nil for the emergency admin
	Username  string
	Emergency bool
	IsAdmin   bool
}

// FreshAdmin reports whether admin actions are allowed without re-login.
func (s *Session) FreshAdmin(maxAge time.Duration) bool {
	return s.IsAdmin && time.Since(s.Web.AuthTime) <= maxAge
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// CurrentSession returns the session of the request, if any.
func (s *Server) CurrentSession(r *http.Request) *Session {
	if v := r.Context().Value(ctxSession{}); v != nil {
		return v.(*Session)
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	ws, err := s.Store.WebSession(hashToken(c.Value))
	if err != nil {
		return nil
	}
	sess := &Session{Web: ws, Emergency: ws.Emergency}
	if ws.Emergency {
		sess.Username = s.Cfg.Str("EMERGENCY_USER")
		sess.IsAdmin = true
		return sess
	}
	u, err := s.Store.UserByID(ws.UserID)
	if err != nil || u.Status == store.StatusRevoked {
		return nil
	}
	sess.User, sess.Username, sess.IsAdmin = u, u.Username, u.IsAdmin
	return sess
}

type ctxSession struct{}

func (s *Server) startSession(w http.ResponseWriter, userID int64, emergency bool, authTime time.Time, idToken string) error {
	token := secret.RandomToken(32)
	ws := &store.WebSession{ID: hashToken(token), UserID: userID, Emergency: emergency, CSRF: secret.RandomToken(24),
		AuthTime: authTime, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(sessionTTL)}
	if idToken != "" {
		ws.IDToken = s.Core.Box.Seal([]byte(idToken), "idtoken:"+ws.ID)
	}
	if err := s.Store.CreateWebSession(ws); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", Expires: ws.ExpiresAt,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return nil
}

// requireLogin enforces a session and CSRF on unsafe methods.
func (s *Server) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.CurrentSession(r)
		if sess == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			s.Error(w, r, http.StatusUnauthorized, "Your session has expired. Please sign in again.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.FormValue("csrf")
			}
			if !secret.Equal(tok, sess.Web.CSRF) {
				s.Error(w, r, http.StatusForbidden, "Invalid or missing CSRF token. Reload the page and try again.")
				return
			}
		}
		next(w, r.WithContext(withSession(r.Context(), sess)))
	}
}

// RequireAdmin enforces an admin session; mutations need a fresh login.
func (s *Server) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		sess := s.CurrentSession(r)
		if !sess.IsAdmin {
			s.Error(w, r, http.StatusForbidden, "The admin panel is available to members of the "+s.Cfg.Str("ADMIN_GROUP")+" group.")
			return
		}
		if r.Method != http.MethodGet && !sess.FreshAdmin(s.Cfg.Dur("ADMIN_MAX_AUTH_AGE")) {
			Flash(w, "warn", "Admin actions require a recent sign-in. Please sign in again.")
			http.Redirect(w, r, "/login?prompt=login&return="+url.QueryEscape(r.Referer()), http.StatusSeeOther)
			return
		}
		next(w, r)
	})
}

// ClientIP returns the remote address of a request.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SecurityHeaders wraps h with security headers.
func (s *Server) SecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		formAction := "'self'"
		if iss, err := url.Parse(s.Cfg.Str("OIDC_ISSUER")); err == nil && iss.Host != "" {
			formAction += " " + iss.Scheme + "://" + iss.Host
		}
		hdr.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'; form-action "+formAction)
		hdr.Set("Strict-Transport-Security", "max-age=31536000")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "same-origin")
		hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.ServeHTTP(w, r)
	})
}

// --- formatting helpers ---

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return humanDuration(time.Since(t)) + " ago"
}

func fmtTS(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05") + " UTC"
}

var errNoSession = errors.New("no session")
