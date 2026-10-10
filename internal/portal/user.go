package portal

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vpngw/internal/clients"
	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/policy"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

// LoginView is a VPN login with its download links.
type LoginView struct {
	core.LoginOption
	Downloads map[string]string
}

type portalData struct {
	Emergency      bool
	Username       string
	Email          string
	Password       string
	PasswordIssued time.Time
	SessionExpires time.Time // end of the IdP session; zero = unknown
	Logins         []LoginView
	LoginNames     []string
	Sessions       []core.Session
	LastCheckOK    time.Time
	LastCheckErr   string
	NextCheck      time.Time
	RoutesWidened  bool
	Host           string // the selected endpoint
	Endpoints      []config.Endpoint
	EP             int // index of the selected endpoint
	IKEID          string
	OpenVPNPort    int
	OVPNDownload   string
	Enabled        map[string]bool
	SelfSigned     bool
	SessionLimit   int
	IsAdmin        bool
	Groups         []string
	NoRoutes       bool
	Clients        []clients.Group
}

// ClientsFor lists the client applications of a protocol for an OS tab.
func (d *portalData) ClientsFor(protocol, os string) []clients.Item {
	return clients.For(d.Clients, protocol, os)
}

// downloadURL links a profile download. Links are not tokens: they work
// for the signed-in user whenever the page is open (only the user's own
// logins and the configured endpoints are accepted).
func downloadURL(kind, login, host string, saved bool) string {
	q := url.Values{}
	if login != "" {
		q.Set("login", login)
	}
	q.Set("ep", host)
	if saved {
		q.Set("saved", "1")
	}
	return "/download/" + kind + "?" + q.Encode()
}

// profileLinkTTL is how long a signed profile link works.
const profileLinkTTL = 24 * time.Hour

// signedDownloadURL is downloadURL that also works without the portal
// session, for profiles without secrets. Apple devices install profiles
// only from Safari: other browsers on iOS hand the link over to Safari,
// which is not signed in to the portal. The link names the user and works
// while the password does: a reissued password invalidates it.
func (s *Server) signedDownloadURL(u *store.User, kind, login, host string) string {
	link := downloadURL(kind, login, host, false)
	q := url.Values{}
	q.Set("u", strconv.FormatInt(u.ID, 10))
	q.Set("exp", strconv.FormatInt(time.Now().Add(profileLinkTTL).Unix(), 10))
	q.Set("sig", s.profileLinkMAC(u, kind, login, host, q.Get("exp")))
	return link + "&" + q.Encode()
}

func (s *Server) profileLinkMAC(u *store.User, kind, login, host, exp string) string {
	// The password hash (salted) changes with every reissue.
	data := fmt.Sprintf("%d|%s|%s|%s|%s|%s", u.ID, u.PwHash, kind, login, host, exp)
	return hex.EncodeToString(s.Core.Box.MAC("profile-link", []byte(data)))
}

// handleDownloadRoute serves downloads to the signed-in user, or a
// signed profile link without a session (see signedDownloadURL).
func (s *Server) handleDownloadRoute(w http.ResponseWriter, r *http.Request) {
	if s.CurrentSession(r) == nil {
		if sess := s.linkSession(r); sess != nil {
			s.handleDownload(w, r.WithContext(withSession(r.Context(), sess)))
			return
		}
	}
	s.requireLogin(s.handleDownload)(w, r)
}

// linkSession returns the user of a valid signed profile link.
func (s *Server) linkSession(r *http.Request) *Session {
	q := r.URL.Query()
	if r.PathValue("kind") != "mobileconfig" || q.Get("sig") == "" {
		return nil
	}
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil
	}
	uid, err := strconv.ParseInt(q.Get("u"), 10, 64)
	if err != nil {
		return nil
	}
	u, err := s.Store.UserByID(uid)
	if err != nil || !u.HasPassword() {
		return nil
	}
	if !secret.Equal(q.Get("sig"), s.profileLinkMAC(u, "mobileconfig", q.Get("login"), q.Get("ep"), q.Get("exp"))) {
		return nil
	}
	// No portal session behind it: no CSRF token, so it can only download.
	return &Session{Web: &store.WebSession{}, User: u, Username: u.Username}
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	sess := s.CurrentSession(r)
	eps := s.Cfg.Endpoints()
	ep, _ := strconv.Atoi(r.URL.Query().Get("ep"))
	if ep < 0 || ep >= len(eps) {
		ep = 0
	}
	d := &portalData{
		Emergency:    sess.Emergency,
		Username:     sess.Username,
		Host:         eps[ep].Host,
		Endpoints:    eps,
		EP:           ep,
		IKEID:        s.TLS.IKEIdentity(),
		OpenVPNPort:  s.Cfg.Int("OPENVPN_PORT"),
		SelfSigned:   s.TLS.IsSelfSigned(),
		SessionLimit: s.Cfg.Int("SESSION_LIMIT"),
		IsAdmin:      sess.IsAdmin,
		Enabled: map[string]bool{
			config.AnyConnect: s.Cfg.Bool("ENABLE_ANYCONNECT"),
			config.OpenVPN:    s.Cfg.Bool("ENABLE_OPENVPN"),
			config.IKEv2:      s.Cfg.Bool("ENABLE_IKEV2"),
		},
	}
	if sess.Emergency {
		d.Sessions = s.Core.UserSessions(0, true)
		var opts []core.LoginOption
		if p, err := s.Core.ProfileFor(nil, ""); err == nil {
			opts = append(opts, core.LoginOption{Login: sess.Username, Profile: p})
		}
		d.Logins = s.loginViews(nil, opts, d.Host)
	} else {
		u := sess.User
		d.Email, d.Groups = u.Email, s.Core.VPNGroups(u)
		if pw, err := s.Core.RevealPassword(u); err == nil {
			d.Password = pw
		}
		d.PasswordIssued = u.PwIssuedAt
		d.SessionExpires = u.SessionExpiresAt
		d.LastCheckOK, d.LastCheckErr = u.LastCheckOKAt, u.LastCheckError
		if !u.LastCheckAt.IsZero() {
			d.NextCheck = u.LastCheckAt.Add(s.Cfg.Dur("OIDC_REVALIDATE_INTERVAL"))
		}
		d.Sessions = s.Core.UserSessions(u.ID, false)
		d.Logins = s.loginViews(u, s.Core.AvailableLogins(u), d.Host)
		d.NoRoutes = len(d.Logins) == 0
	}
	for _, l := range d.Logins {
		d.LoginNames = append(d.LoginNames, l.Login)
	}
	if len(d.LoginNames) == 0 {
		d.LoginNames = []string{d.Username}
	}
	for _, x := range d.Sessions {
		if x.RoutesWidened {
			d.RoutesWidened = true
		}
	}
	d.Clients = s.clientGroups(d.Enabled)
	if d.Enabled[config.OpenVPN] {
		d.OVPNDownload = downloadURL("ovpn", "", d.Host, false)
	}
	s.Render(w, r, http.StatusOK, "portal", &Page{Title: "My VPN", Nav: "portal", Data: d})
}

// loginViews lists the logins with their downloads; u is nil for the
// emergency administrator.
func (s *Server) loginViews(u *store.User, opts []core.LoginOption, host string) []LoginView {
	out := make([]LoginView, 0, len(opts))
	for _, o := range opts {
		v := LoginView{LoginOption: o, Downloads: map[string]string{}}
		if u != nil && o.Profile != nil && s.Cfg.Bool("ENABLE_OPENVPN") {
			// Profile with the login and password saved in it.
			v.Downloads["ovpn"] = downloadURL("ovpn", o.Login, host, true)
		}
		if o.Profile != nil && s.Cfg.Bool("ENABLE_IKEV2") {
			for _, kind := range []string{"ps1", "mobileconfig", "sswan", "swanctl"} {
				v.Downloads[kind] = downloadURL(kind, o.Login, host, false)
			}
			if u != nil {
				v.Downloads["mobileconfig"] = s.signedDownloadURL(u, "mobileconfig", o.Login, host)
			}
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) handleReissue(w http.ResponseWriter, r *http.Request) {
	sess := s.CurrentSession(r)
	if sess.Emergency {
		Flash(w, "warn", "The emergency administrator password is set with EMERGENCY_PASS.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, err := s.Core.ReissuePassword(sess.User.ID, sess.Username, ClientIP(r)); err != nil {
		slog.Error("reissue password", "err", err)
		Flash(w, "bad", "Could not reissue the password.")
	} else {
		Flash(w, "ok", "A new VPN password was issued. All your VPN sessions were disconnected; download fresh OpenVPN profiles.")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleUserDisconnect(w http.ResponseWriter, r *http.Request) {
	sess := s.CurrentSession(r)
	ip := core.AddrFromString(r.FormValue("ip"))
	live, ok := s.Core.SessionByIP(ip)
	own := ok && ((sess.Emergency && live.Emergency) || (!sess.Emergency && !live.Emergency && live.UserID == sess.User.ID))
	if !own {
		s.Error(w, r, http.StatusNotFound, "Session not found.")
		return
	}
	if err := s.Core.Disconnect(ip, "disconnected by user from portal", sess.Username); err != nil {
		slog.Warn("portal disconnect", "err", err)
	}
	Flash(w, "ok", "Session "+ip.String()+" disconnected.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	sess := s.CurrentSession(r)
	q := r.URL.Query()
	what, login, epHost, saved := r.PathValue("kind"), q.Get("login"), q.Get("ep"), q.Get("saved") == "1"
	if user, _ := policy.SplitLogin(login); login != "" && !strings.EqualFold(user, sess.Username) {
		s.Error(w, r, http.StatusForbidden, "This profile belongs to another user.")
		return
	}
	// The endpoint chosen on the portal; only configured endpoints are accepted.
	eps := s.Cfg.Endpoints()
	host := eps[0].Host
	var remotes []string
	for _, e := range eps {
		if e.Host == epHost {
			host = e.Host
		}
	}
	remotes = append(remotes, host)
	for _, e := range eps {
		if e.Host != host {
			remotes = append(remotes, e.Host)
		}
	}
	var u *store.User
	if !sess.Emergency {
		u = sess.User
		if !u.HasPassword() {
			s.Error(w, r, http.StatusForbidden, "You have no active VPN password.")
			return
		}
	}
	var prof *policy.Profile
	var err error
	if login != "" {
		_, group := policy.SplitLogin(login)
		prof, err = s.Core.ProfileFor(u, group)
		if err != nil {
			s.Error(w, r, http.StatusBadRequest, err.Error())
			return
		}
	}
	base := FileBase(host, login)
	var body []byte
	var ctype, fname string
	switch what {
	case "ovpn":
		meta := core.TLSMeta(0, s.Core.EmergencyTLSSerial(false))
		if u != nil {
			meta = core.TLSMeta(u.ID, u.TLSKeySerial)
		}
		var saveLogin, savePassword string
		fname = host + ".ovpn"
		if login != "" && saved && u != nil {
			pw, err := s.Core.RevealPassword(u)
			if err != nil {
				s.Error(w, r, http.StatusForbidden, "You have no active VPN password.")
				return
			}
			saveLogin, savePassword, fname = login, pw, base+".ovpn"
		}
		txt, err := s.OVPNProfile(sess.Username, meta, remotes, ProfileName(host, login), saveLogin, savePassword)
		if err != nil {
			slog.Error("ovpn profile", "err", err)
			s.Error(w, r, http.StatusInternalServerError, "Cannot generate the profile.")
			return
		}
		body, ctype = []byte(txt), "application/x-openvpn-profile"
	case "ps1":
		body, ctype, fname = WindowsSetup(host, login, prof), "application/octet-stream", base+".cmd"
	case "mobileconfig":
		body, ctype, fname = MobileConfig(host, s.TLS.IKEIdentity(), login, prof), "application/x-apple-aspen-config", base+".mobileconfig"
	case "sswan":
		body, ctype, fname = SSwan(host, s.TLS.IKEIdentity(), login, prof), "application/vnd.strongswan.profile", base+".sswan"
	case "swanctl":
		body, ctype, fname = LinuxSwanctl(host, s.TLS.IKEIdentity(), login), "text/plain; charset=utf-8", base+".conf"
	default:
		s.Error(w, r, http.StatusNotFound, "Unknown download.")
		return
	}
	s.Core.Audit("info", "portal.download", sess.Username, sess.Username, "", ClientIP(r), fmt.Sprintf("downloaded %s profile %s", what, fname))
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fname))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
