// Package testutil provides a mock identity provider and a core wired for
// tests (SQLite in a temp dir, firewall in dry-run mode).
package testutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/firewall"
	"vpngw/internal/oidc"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

// ClientID and ClientSecret of the mock IdP.
const (
	ClientID     = "vpngw-test"
	ClientSecret = "test-client-secret-0123456789abcdef"
)

// IdP is a minimal OIDC provider signing HS256 tokens with the client secret.
type IdP struct {
	*httptest.Server
	mu       sync.Mutex
	Mode     string // "ok", "invalid_grant", "down"
	Claims   map[string]any
	Refresh  int
	Rotation int
}

// NewIdP starts the mock provider.
func NewIdP(t *testing.T) *IdP {
	idp := &IdP{Mode: "ok", Claims: map[string]any{
		"sub": "sub-1", "preferred_username": "alice", "email": "alice@example.com", "sid": "sid-1",
		"groups": []string{"vpn-dc1", "vpn-internet"},
		"vpn": map[string]any{
			"vpn-dc1":      map[string]any{"vpnRoutes": []string{"10.4.0.0/16", "!10.4.5.0/24"}, "vpnGateway": "dc1"},
			"vpn-internet": map[string]any{"vpnRoutes": []string{"0.0.0.0/0"}},
		},
	}}
	mux := http.NewServeMux()
	idp.Server = httptest.NewTLSServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": idp.URL, "authorization_endpoint": idp.URL + "/authorize", "token_endpoint": idp.URL + "/token",
			"userinfo_endpoint": idp.URL + "/userinfo", "jwks_uri": idp.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"HS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) })
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		_ = json.NewEncoder(w).Encode(idp.Claims)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		idp.Refresh++
		switch idp.Mode {
		case "invalid_grant":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Token is not valid"}`))
			return
		case "down":
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		idp.Rotation++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 300, "refresh_expires_in": 86400,
			"refresh_token": "rt-" + time.Now().Format(time.RFC3339Nano), "id_token": idp.sign(nil),
		})
	})
	t.Cleanup(idp.Close)
	return idp
}

// Set changes provider behaviour.
func (i *IdP) Set(mode string, mutate func(c map[string]any)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.Mode = mode
	if mutate != nil {
		mutate(i.Claims)
	}
}

func (i *IdP) sign(extra map[string]any) string {
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(ClientSecret)}, nil)
	cl := map[string]any{"iss": i.URL, "aud": ClientID, "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix()}
	for k, v := range i.Claims {
		cl[k] = v
	}
	for k, v := range extra {
		cl[k] = v
	}
	s, _ := jwt.Signed(sig).Claims(cl).Serialize()
	return s
}

// LogoutToken returns a signed back-channel logout token.
func (i *IdP) LogoutToken(sid string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(ClientSecret)}, nil)
	s, _ := jwt.Signed(sig).Claims(map[string]any{"iss": i.URL, "aud": ClientID, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
		"sid": sid, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}).Serialize()
	return s
}

// Identity returns tokens as Exchange would for the current claims.
func (i *IdP) Identity() *oidc.Tokens {
	i.mu.Lock()
	defer i.mu.Unlock()
	vpn, _ := json.Marshal(i.Claims["vpn"])
	groups, _ := i.Claims["groups"].([]string)
	return &oidc.Tokens{RefreshToken: "rt-initial", Identity: oidc.Identity{
		Sub: i.Claims["sub"].(string), Username: i.Claims["preferred_username"].(string), Email: "alice@example.com",
		Groups: groups, RoutesClaim: vpn, SID: i.Claims["sid"].(string), AuthTime: time.Now(),
	}}
}

// Backend records disconnect requests.
type Backend struct {
	Proto string
	mu    sync.Mutex
	Kills []netip.Addr
}

func (b *Backend) Protocol() string { return b.Proto }
func (b *Backend) Disconnect(s *core.Session) error {
	b.mu.Lock()
	b.Kills = append(b.Kills, s.VPNIP)
	b.mu.Unlock()
	return nil
}
func (b *Backend) Poll(context.Context) ([]core.LiveSession, error) { return nil, nil }

// Killed returns the number of disconnects.
func (b *Backend) Killed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.Kills)
}

// Env bundles a core for tests.
type Env struct {
	Core     *core.Core
	Store    *store.Store
	IdP      *IdP
	Cfg      *config.Config
	Backends map[string]*Backend
}

// NewEnv creates a core backed by a temp database and a mock IdP.
func NewEnv(t *testing.T, env map[string]string) *Env {
	t.Helper()
	idp := NewIdP(t)
	base := map[string]string{
		"VPN_HOSTNAME": "vpn.test", "PORTAL_HOSTNAME": "vpn.test", "OIDC_ISSUER": idp.URL, "OIDC_CLIENT_ID": ClientID,
		"OIDC_CLIENT_SECRET": ClientSecret, "ADMIN_GROUP": "vpn-admins", "EMERGENCY_USER": "root", "EMERGENCY_PASS": "emergency-pass",
		"DATA_DIR": t.TempDir(),
	}
	for k, v := range env {
		base[k] = v
	}
	cfg := config.NewFromMap(base)
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	master := secret.RandomBytes(secret.KeySize)
	box, _ := secret.NewBox(master)
	fw := firewall.New(firewall.Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/16")}, DryRun: true})
	_ = fw.Init()
	oc := oidc.New(oidc.Config{Issuer: idp.URL, ClientID: ClientID, ClientSecret: ClientSecret, RedirectURL: "https://vpn.test/oidc/callback",
		HTTPClient: idp.Client()})
	c := core.New(cfg, st, master, box, oc, fw)
	e := &Env{Core: c, Store: st, IdP: idp, Cfg: cfg, Backends: map[string]*Backend{}}
	for _, p := range config.Protocols {
		b := &Backend{Proto: p}
		e.Backends[p] = b
		c.RegisterBackend(b)
	}
	return e
}

// Login performs a portal login and returns the user and its password.
func (e *Env) Login(t *testing.T) (*store.User, string) {
	t.Helper()
	res, err := e.Core.PortalLogin(e.IdP.Identity(), "198.51.100.1")
	if err != nil {
		t.Fatal(err)
	}
	pw, err := e.Core.RevealPassword(res.User)
	if err != nil || pw != res.NewPassword {
		t.Fatalf("reveal password: %v", err)
	}
	return res.User, pw
}
