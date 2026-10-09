package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vpngw/internal/oidc"
	"vpngw/internal/secret"
)

func withSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxSession{}, s)
}

// safeReturn accepts only local paths.
func safeReturn(r string) string {
	if r == "" || !strings.HasPrefix(r, "/") || strings.HasPrefix(r, "//") || strings.HasPrefix(r, "/\\") {
		return "/"
	}
	if u, err := url.Parse(r); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return r
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	sess := s.CurrentSession(r)
	if !s.Cfg.VPNEnabled() {
		// Tunnels only: the site is the admin panel.
		if sess == nil {
			s.Render(w, r, http.StatusOK, "local_login", &Page{Title: "Sign in"})
		} else {
			http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		}
		return
	}
	if sess == nil {
		_, idpErr := s.OIDC.Health()
		s.Render(w, r, http.StatusOK, "login", &Page{Title: "Sign in", Data: map[string]any{"IdPError": idpErr != nil}})
		return
	}
	s.handlePortal(w, r.WithContext(withSession(r.Context(), sess)))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.VPNEnabled() {
		s.Error(w, r, http.StatusNotFound, "Single sign-on is not configured (OIDC_ISSUER is empty).")
		return
	}
	req := oidc.AuthRequest{
		State:    secret.RandomToken(24),
		Nonce:    secret.RandomToken(24),
		Verifier: oidc.PKCEVerifier(),
		Return:   safeReturn(r.URL.Query().Get("return")),
	}
	if r.URL.Query().Get("prompt") == "login" {
		req.Prompt = "login"
	}
	// After signing out here, the IdP asks for credentials again instead of
	// silently reusing its session.
	if c, err := r.Cookie(signedOutCookie); err == nil && c.Value == "1" {
		req.Prompt = "login"
		http.SetCookie(w, &http.Cookie{Name: signedOutCookie, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
	}
	u, err := s.OIDC.AuthURL(r.Context(), req)
	if err != nil {
		slog.Error("oidc auth url", "err", err)
		s.Error(w, r, http.StatusServiceUnavailable, "The identity provider is unavailable. Please try again later.")
		return
	}
	raw, _ := json.Marshal(req)
	sealed := s.Core.Box.Seal(raw, "authreq")
	http.SetCookie(w, &http.Cookie{Name: authCookie, Value: base64.RawURLEncoding.EncodeToString(sealed), Path: "/oidc/",
		MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := r.Cookie(authCookie)
	http.SetCookie(w, &http.Cookie{Name: authCookie, Path: "/oidc/", MaxAge: -1, Secure: true, HttpOnly: true})
	if err != nil {
		s.Error(w, r, http.StatusBadRequest, "The sign-in request expired. Please start again.")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	var req oidc.AuthRequest
	if err == nil {
		raw, err = s.Core.Box.Open(raw, "authreq")
	}
	if err == nil {
		err = json.Unmarshal(raw, &req)
	}
	if err != nil || !secret.Equal(req.State, q.Get("state")) {
		s.Error(w, r, http.StatusBadRequest, "Invalid sign-in state. Please start again.")
		return
	}
	if e := q.Get("error"); e != "" {
		s.Core.Audit("warn", "portal.login_failed", "", "", "", ClientIP(r), "IdP returned error: "+e)
		s.Error(w, r, http.StatusForbidden, "The identity provider refused the sign-in: "+e)
		return
	}
	tok, err := s.OIDC.Exchange(r.Context(), q.Get("code"), req)
	if err != nil {
		s.Core.Audit("warn", "portal.login_failed", "", "", "", ClientIP(r), "OIDC login failed: "+err.Error())
		msg := "Sign-in failed. Please try again."
		if strings.Contains(err.Error(), "encrypts ID tokens") {
			msg = "The identity provider encrypts ID tokens, which this gateway is not configured to decrypt. " +
				"Ask the administrator to remove the Encryption Key from the OIDC provider."
		}
		if errors.Is(err, oidc.ErrNoRefreshToken) {
			msg = "The identity provider did not return a refresh token, so your session cannot be verified. " +
				"Ask the administrator to enable the offline_access scope for this application."
		}
		s.Error(w, r, http.StatusForbidden, msg)
		return
	}
	res, err := s.Core.PortalLogin(tok, ClientIP(r))
	if err != nil {
		slog.Error("portal login", "err", err)
		s.Error(w, r, http.StatusForbidden, err.Error())
		return
	}
	authTime := tok.Identity.AuthTime
	if authTime.IsZero() || req.Prompt == "login" {
		authTime = time.Now()
	}
	if err := s.startSession(w, res.User.ID, false, authTime, tok.IDToken); err != nil {
		s.Error(w, r, http.StatusInternalServerError, "Cannot create session.")
		return
	}
	if res.NewPassword != "" {
		Flash(w, "ok", "Your VPN password has been issued.")
	}
	http.Redirect(w, r, safeReturn(req.Return), http.StatusSeeOther)
}

func (s *Server) handleLocalLoginForm(w http.ResponseWriter, r *http.Request) {
	s.Render(w, r, http.StatusOK, "local_login", &Page{Title: "Emergency sign-in"})
}

func (s *Server) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r)
	key := "portal:" + ip
	lim := s.Core.Limiter()
	if blocked, _ := lim.Blocked(key); blocked {
		s.Render(w, r, http.StatusTooManyRequests, "local_login", &Page{Title: "Emergency sign-in", Flash: "Too many attempts. Try again later.", FlashKind: "bad"})
		return
	}
	user, pw := r.FormValue("username"), r.FormValue("password")
	if !s.Core.IsEmergency(user) || !s.Core.CheckEmergencyPassword(pw) {
		if lim.Fail(key) {
			s.Core.Audit("warn", "auth.blocked", "", user, "", ip, "emergency sign-in blocked after repeated failures")
		}
		s.Core.Audit("warn", "portal.login_failed", "", user, "", ip, "emergency sign-in failed")
		s.Render(w, r, http.StatusUnauthorized, "local_login", &Page{Title: "Emergency sign-in", Flash: "Invalid credentials.", FlashKind: "bad"})
		return
	}
	lim.Success(key)
	if err := s.startSession(w, 0, true, time.Now(), ""); err != nil {
		s.Error(w, r, http.StatusInternalServerError, "Cannot create session.")
		return
	}
	s.Core.Audit("info", "portal.login", user, user, "", ip, "emergency administrator signed in")
	if !s.Cfg.VPNEnabled() {
		http.Redirect(w, r, "/admin/tunnels", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := s.CurrentSession(r)
	_ = s.Store.DeleteWebSession(sess.Web.ID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
	s.Core.Audit("info", "portal.logout", sess.Username, sess.Username, "", ClientIP(r), "signed out of the portal")
	if !sess.Emergency && s.Cfg.Str("OIDC_LOGOUT") == "idp" && len(sess.Web.IDToken) > 0 {
		// RP-initiated logout; the IdP returns to the sign-in page if it
		// supports post_logout_redirect_uri.
		if raw, err := s.Core.Box.Open(sess.Web.IDToken, "idtoken:"+sess.Web.ID); err == nil {
			if u := s.OIDC.EndSessionURL(r.Context(), s.Cfg.PortalURL()+"/", string(raw)); u != "" {
				http.Redirect(w, r, u, http.StatusSeeOther)
				return
			}
		}
	}
	if !sess.Emergency {
		http.SetCookie(w, &http.Cookie{Name: signedOutCookie, Value: "1", Path: "/", MaxAge: 7 * 24 * 3600,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	Flash(w, "ok", "You have signed out.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleBackchannel implements OIDC Back-Channel Logout 1.0.
func (s *Server) handleBackchannel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := r.FormValue("logout_token")
	if token == "" {
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}
	lc, err := s.OIDC.VerifyLogoutToken(r.Context(), token)
	if err != nil {
		slog.Warn("invalid back-channel logout token", "err", err)
		http.Error(w, "invalid logout_token", http.StatusBadRequest)
		return
	}
	n := s.Core.BackchannelLogout(lc)
	slog.Info("back-channel logout processed", "users", n)
	w.WriteHeader(http.StatusOK)
}
