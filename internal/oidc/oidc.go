// Package oidc wraps the OpenID Connect relying-party logic: login,
// token refresh, introspection and back-channel logout verification.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// Errors returned by Refresh.
var (
	// ErrRevoked means the IdP rejected the refresh token (session ended,
	// user blocked or deleted).
	ErrRevoked = errors.New("identity provider revoked the session")
	// ErrNoRefreshToken means the IdP did not issue a refresh token.
	ErrNoRefreshToken = errors.New("identity provider did not return a refresh token (enable the offline_access scope)")
)

// TransientError wraps network and server errors that do not revoke access.
type TransientError struct{ Err error }

func (e *TransientError) Error() string { return "identity provider unavailable: " + e.Err.Error() }
func (e *TransientError) Unwrap() error { return e.Err }

// IsTransient reports whether err is a temporary IdP failure.
func IsTransient(err error) bool {
	var t *TransientError
	return errors.As(err, &t)
}

// Config configures the client.
type Config struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	ExtraScopes   []string
	UsernameClaim string
	GroupsClaim   string
	RoutesClaim   string
	// DecryptionKey (PEM) decrypts ID tokens the IdP encrypts as JWE.
	DecryptionKey string
	HTTPClient    *http.Client
}

// Identity is what the gateway needs to know about a user.
type Identity struct {
	Sub         string
	Username    string
	Email       string
	Name        string
	Groups      []string
	RoutesClaim json.RawMessage
	SID         string
	AuthTime    time.Time
}

// Tokens is the result of a code exchange or refresh.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	// RefreshExpiry is when the refresh token (the IdP session for this
	// client) ends, if the IdP says so in the token response
	// (refresh_expires_in); see also RefreshTokenExpiry.
	RefreshExpiry time.Time
	Identity      Identity
	IDToken       string // signed ID token of the login (id_token_hint)
}

func refreshExpiry(tok *oauth2.Token) time.Time {
	switch v := tok.Extra("refresh_expires_in").(type) {
	case float64:
		if v > 0 {
			return time.Now().Add(time.Duration(v) * time.Second)
		}
	case string:
		if n, err := time.ParseDuration(v + "s"); err == nil && n > 0 {
			return time.Now().Add(n)
		}
	}
	return time.Time{}
}

// RefreshTokenExpiry asks the IdP (RFC 7662 introspection) when a refresh
// token expires. Zero time: unknown (no introspection, inactive or no exp).
func (c *Client) RefreshTokenExpiry(ctx context.Context, refreshToken string) (time.Time, error) {
	if err := c.init(ctx); err != nil {
		return time.Time{}, err
	}
	if c.introspect == "" {
		return time.Time{}, nil
	}
	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.introspect, strings.NewReader(form.Encode()))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	var r struct {
		Active *bool `json:"active"`
		Exp    int64 `json:"exp"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&r) != nil {
		return time.Time{}, fmt.Errorf("introspection: HTTP %d", resp.StatusCode)
	}
	if (r.Active != nil && !*r.Active) || r.Exp == 0 {
		return time.Time{}, nil
	}
	return time.Unix(r.Exp, 0), nil
}

// Client is an OIDC relying party. It lazily (re)discovers the provider.
type Client struct {
	cfg Config

	mu           sync.Mutex
	provider     *gooidc.Provider
	verifier     *gooidc.IDTokenVerifier
	oauth        *oauth2.Config
	introspect   string
	endSession   string
	lastOK       time.Time
	lastErr      error
	discoveredAt time.Time
}

// New creates a client; discovery happens on first use.
func New(cfg Config) *Client {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.RoutesClaim == "" {
		cfg.RoutesClaim = "vpn"
	}
	return &Client{cfg: cfg}
}

// Scopes returns the requested scopes.
func (c *Client) Scopes() []string {
	s := []string{gooidc.ScopeOpenID, "profile", "email", gooidc.ScopeOfflineAccess, "vpn"}
	seen := map[string]bool{}
	for _, x := range s {
		seen[x] = true
	}
	for _, x := range c.cfg.ExtraScopes {
		if !seen[x] {
			s = append(s, x)
			seen[x] = true
		}
	}
	return s
}

func (c *Client) ctx(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, c.cfg.HTTPClient)
}

// hmacKeySet verifies HS256/384/512 tokens with the client secret and
// delegates asymmetric algorithms to the provider JWKS.
type hmacKeySet struct {
	secret []byte
	remote gooidc.KeySet
}

func (k *hmacKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	sig, err := jose.ParseSigned(jwt, []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512,
		jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("malformed jwt: %w", err)
	}
	if len(sig.Signatures) != 1 {
		return nil, errors.New("jwt must have exactly one signature")
	}
	switch jose.SignatureAlgorithm(sig.Signatures[0].Header.Algorithm) {
	case jose.HS256, jose.HS384, jose.HS512:
		return sig.Verify(k.secret)
	}
	return k.remote.VerifySignature(ctx, jwt)
}

func (c *Client) init(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && time.Since(c.discoveredAt) < 6*time.Hour {
		return nil
	}
	p, err := gooidc.NewProvider(c.ctx(ctx), strings.TrimSuffix(c.cfg.Issuer, "/.well-known/openid-configuration"))
	if err != nil {
		c.lastErr = err
		if c.provider != nil {
			return nil // keep the old discovery document
		}
		return &TransientError{err}
	}
	var meta struct {
		JWKS          string `json:"jwks_uri"`
		Introspection string `json:"introspection_endpoint"`
		EndSession    string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&meta)
	ks := &hmacKeySet{secret: []byte(c.cfg.ClientSecret), remote: gooidc.NewRemoteKeySet(c.ctx(context.Background()), meta.JWKS)}
	c.verifier = gooidc.NewVerifier(issuerOf(p), ks, &gooidc.Config{
		ClientID: c.cfg.ClientID,
		SupportedSigningAlgs: []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA",
			"HS256", "HS384", "HS512"},
	})
	c.provider = p
	c.introspect = meta.Introspection
	c.endSession = meta.EndSession
	c.oauth = &oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  c.cfg.RedirectURL,
		Scopes:       c.Scopes(),
	}
	c.discoveredAt = time.Now()
	c.lastOK = time.Now()
	return nil
}

func issuerOf(p *gooidc.Provider) string {
	var m struct {
		Issuer string `json:"issuer"`
	}
	_ = p.Claims(&m)
	return m.Issuer
}

// Ready reports whether discovery succeeded at least once.
func (c *Client) Ready(ctx context.Context) error { return c.init(ctx) }

// Health returns the time of the last successful IdP interaction and the last error.
func (c *Client) Health() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastOK, c.lastErr
}

func (c *Client) markOK() {
	c.mu.Lock()
	c.lastOK = time.Now()
	c.lastErr = nil
	c.mu.Unlock()
}

func (c *Client) markErr(err error) {
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
}

// AuthRequest holds per-login values that must survive the redirect.
type AuthRequest struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r,omitempty"`
	Prompt   string `json:"p,omitempty"`
}

// AuthURL returns the authorization endpoint URL for req.
func (c *Client) AuthURL(ctx context.Context, req AuthRequest) (string, error) {
	if err := c.init(ctx); err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{gooidc.Nonce(req.Nonce), oauth2.S256ChallengeOption(req.Verifier)}
	if req.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", req.Prompt), oauth2.SetAuthURLParam("max_age", "0"))
	}
	return c.oauth.AuthCodeURL(req.State, opts...), nil
}

// Exchange trades an authorization code for tokens and validates the ID token.
func (c *Client) Exchange(ctx context.Context, code string, req AuthRequest) (*Tokens, error) {
	if err := c.init(ctx); err != nil {
		return nil, err
	}
	tok, err := c.oauth.Exchange(c.ctx(ctx), code, oauth2.VerifierOption(req.Verifier))
	if err != nil {
		c.markErr(err)
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	c.markOK()
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("token response has no id_token")
	}
	if raw, err = c.decrypt(raw); err != nil {
		return nil, err
	}
	idt, err := c.verifier.Verify(c.ctx(ctx), raw)
	if err != nil {
		return nil, fmt.Errorf("id_token: %w", err)
	}
	if !hmac.Equal([]byte(idt.Nonce), []byte(req.Nonce)) {
		return nil, errors.New("id_token: nonce mismatch")
	}
	if tok.RefreshToken == "" {
		return nil, ErrNoRefreshToken
	}
	ident, err := c.identity(ctx, idt, tok)
	if err != nil {
		return nil, err
	}
	return &Tokens{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry, RefreshExpiry: refreshExpiry(tok),
		Identity: *ident, IDToken: raw}, nil
}

// identity merges ID token claims with userinfo.
func (c *Client) identity(ctx context.Context, idt *gooidc.IDToken, tok *oauth2.Token) (*Identity, error) {
	claims := map[string]json.RawMessage{}
	if idt != nil {
		if err := idt.Claims(&claims); err != nil {
			return nil, err
		}
	}
	if ui, err := c.provider.UserInfo(c.ctx(ctx), oauth2.StaticTokenSource(tok)); err == nil {
		var extra map[string]json.RawMessage
		if ui.Claims(&extra) == nil {
			for k, v := range extra {
				if k == "sub" && idt != nil {
					continue
				}
				claims[k] = v
			}
		}
	} else if idt == nil {
		return nil, classify(err)
	}
	id := &Identity{}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(claims[k], &s)
		return s
	}
	id.Sub = str("sub")
	if idt != nil {
		if id.Sub == "" {
			id.Sub = idt.Subject
		}
		var at struct {
			AuthTime int64 `json:"auth_time"`
		}
		_ = idt.Claims(&at)
		if at.AuthTime > 0 {
			id.AuthTime = time.Unix(at.AuthTime, 0)
		}
	}
	id.Username = str(c.cfg.UsernameClaim)
	id.Email = str("email")
	id.Name = str("name")
	id.SID = str("sid")
	if g, ok := claims[c.cfg.GroupsClaim]; ok {
		var groups []string
		if json.Unmarshal(g, &groups) != nil {
			var one string
			if json.Unmarshal(g, &one) == nil && one != "" {
				groups = []string{one}
			}
		}
		id.Groups = groups
	}
	if r, ok := claims[c.cfg.RoutesClaim]; ok {
		id.RoutesClaim = r
	}
	if id.Sub == "" {
		return nil, errors.New("identity has no sub claim")
	}
	if id.Username == "" {
		return nil, fmt.Errorf("identity has no %q claim", c.cfg.UsernameClaim)
	}
	return id, nil
}

// Refresh uses a refresh token and returns fresh tokens and identity.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	if err := c.init(ctx); err != nil {
		return nil, err
	}
	src := c.oauth.TokenSource(c.ctx(ctx), &oauth2.Token{RefreshToken: refreshToken, Expiry: time.Unix(1, 0)})
	tok, err := src.Token()
	if err != nil {
		err = classify(err)
		if IsTransient(err) {
			c.markErr(err)
		} else {
			c.markOK()
		}
		return nil, err
	}
	c.markOK()
	var idt *gooidc.IDToken
	if raw, ok := tok.Extra("id_token").(string); ok && raw != "" {
		if raw, err = c.decrypt(raw); err != nil {
			return nil, err
		}
		// Nonce is not repeated on refresh; signature, iss, aud and exp are.
		idt, err = c.verifier.Verify(c.ctx(ctx), raw)
		if err != nil {
			return nil, fmt.Errorf("refreshed id_token: %w", err)
		}
	}
	ident, err := c.identity(ctx, idt, tok)
	if err != nil {
		return nil, err
	}
	rt := tok.RefreshToken
	if rt == "" {
		rt = refreshToken
	}
	return &Tokens{AccessToken: tok.AccessToken, RefreshToken: rt, Expiry: tok.Expiry, RefreshExpiry: refreshExpiry(tok), Identity: *ident}, nil
}

func classify(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.Response != nil && re.Response.StatusCode >= 500 {
			return &TransientError{err}
		}
		switch re.ErrorCode {
		case "invalid_grant":
			return fmt.Errorf("%w (%s)", ErrRevoked, re.ErrorCode)
		case "temporarily_unavailable", "server_error":
			return &TransientError{err}
		}
		// invalid_client, unauthorized_client etc. are configuration errors:
		// do not revoke users instantly; the grace period applies.
		return &TransientError{err}
	}
	return &TransientError{err}
}

// Introspect checks whether an access token is active (RFC 7662).
func (c *Client) Introspect(ctx context.Context, accessToken string) (bool, error) {
	if err := c.init(ctx); err != nil {
		return false, err
	}
	if c.introspect == "" {
		return true, nil
	}
	form := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.introspect, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return false, &TransientError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return false, &TransientError{fmt.Errorf("introspection: HTTP %d", resp.StatusCode)}
	}
	var r struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return false, &TransientError{err}
	}
	return r.Active, nil
}

// EndSessionURL returns the RP-initiated logout URL, if supported. The IdP
// redirects to postLogout only with a valid id_token_hint and when the URL
// is registered with it (Authentik: "Post logout redirect URIs", 2026.5+).
func (c *Client) EndSessionURL(ctx context.Context, postLogout, idTokenHint string) string {
	if c.init(ctx) != nil || c.endSession == "" {
		return ""
	}
	u, err := url.Parse(c.endSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", c.cfg.ClientID)
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
		if postLogout != "" {
			q.Set("post_logout_redirect_uri", postLogout)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// LogoutClaims are the relevant parts of a back-channel logout token.
type LogoutClaims struct {
	Sub string
	SID string
}

const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// VerifyLogoutToken validates an OIDC Back-Channel Logout token.
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutClaims, error) {
	if err := c.init(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	v := c.verifier
	c.mu.Unlock()
	// The ID token verifier checks signature, iss, aud and exp.
	tok, err := v.Verify(c.ctx(ctx), raw)
	if err != nil {
		return nil, err
	}
	var cl struct {
		Sub    string                     `json:"sub"`
		SID    string                     `json:"sid"`
		Nonce  *string                    `json:"nonce"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := tok.Claims(&cl); err != nil {
		return nil, err
	}
	if cl.Nonce != nil {
		return nil, errors.New("logout token must not contain nonce")
	}
	if _, ok := cl.Events[backchannelEvent]; !ok {
		return nil, errors.New("logout token lacks the back-channel logout event")
	}
	if cl.Sub == "" && cl.SID == "" {
		return nil, errors.New("logout token has neither sub nor sid")
	}
	return &LogoutClaims{Sub: cl.Sub, SID: cl.SID}, nil
}

// decrypt unwraps an encrypted (JWE, five-part) ID token into the signed
// JWT it contains. Plain JWTs are returned unchanged.
func (c *Client) decrypt(raw string) (string, error) {
	if strings.Count(raw, ".") != 4 {
		return raw, nil
	}
	if c.cfg.DecryptionKey == "" {
		return "", errors.New("the identity provider encrypts ID tokens (JWE); remove the encryption key from the " +
			"OIDC provider or set OIDC_ID_TOKEN_DECRYPTION_KEY")
	}
	key, err := parsePrivateKey(c.cfg.DecryptionKey)
	if err != nil {
		return "", fmt.Errorf("OIDC_ID_TOKEN_DECRYPTION_KEY: %w", err)
	}
	jwe, err := jose.ParseEncrypted(raw,
		[]jose.KeyAlgorithm{jose.RSA_OAEP, jose.RSA_OAEP_256, jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW},
		[]jose.ContentEncryption{jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512, jose.A128GCM, jose.A192GCM, jose.A256GCM})
	if err != nil {
		return "", fmt.Errorf("encrypted id_token: %w", err)
	}
	inner, err := jwe.Decrypt(key)
	if err != nil {
		return "", fmt.Errorf("decrypt id_token: %w", err)
	}
	return strings.TrimSpace(string(inner)), nil
}

func parsePrivateKey(s string) (any, error) {
	data := []byte(s)
	if !strings.Contains(s, "-----BEGIN") {
		b, err := os.ReadFile(s)
		if err != nil {
			return nil, err
		}
		data = b
	}
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return nil, errors.New("no private key in PEM data")
		}
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
	}
}

// PKCEVerifier returns a new PKCE code verifier.
func PKCEVerifier() string { return oauth2.GenerateVerifier() }

// HashSID returns a stable identifier for an IdP session id.
func HashSID(sid string) string {
	h := sha256.Sum256([]byte(sid))
	return fmt.Sprintf("%x", h[:8])
}
