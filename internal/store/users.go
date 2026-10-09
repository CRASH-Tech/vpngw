package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// User statuses.
const (
	StatusNone    = "none"    // logged in once, no VPN password
	StatusActive  = "active"  // password valid
	StatusRevoked = "revoked" // password revoked by IdP or admin
)

// User is a portal user known from the IdP.
type User struct {
	ID               int64
	Sub              string
	Username         string
	Email            string
	Name             string
	Groups           []string
	VPNClaim         string // raw JSON of the routes claim
	IsAdmin          bool
	RefreshToken     []byte // encrypted
	OIDCSID          string
	SessionCreatedAt time.Time
	PwHash           string
	NTHash           []byte // encrypted
	PwIssuedAt       time.Time
	PwSeed           []byte    // encrypted derivation inputs
	SessionExpiresAt time.Time // end of the IdP session (refresh token); zero = unknown
	TLSKeySerial     int64
	Status           string
	LastCheckAt      time.Time
	LastCheckOKAt    time.Time
	LastCheckError   string
	IdPFailSince     time.Time
	LastLoginAt      time.Time
	AuthTime         time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// HasPassword reports whether the user holds a valid VPN password.
func (u *User) HasPassword() bool { return u.Status == StatusActive && u.PwHash != "" }

const userCols = `id, sub, username, email, name, groups_json, vpn_claim, is_admin, refresh_token, oidc_sid,
	session_created_at, pw_hash, nt_hash, pw_issued_at, tls_key_serial, status, last_check_at, last_check_ok_at,
	last_check_error, idp_fail_since, last_login_at, auth_time, created_at, updated_at, pw_seed, session_expires_at`

type scanner interface{ Scan(...any) error }

func scanUser(r scanner) (*User, error) {
	var u User
	var groups string
	var isAdmin int
	var sca, pia, lca, lco, ifs, lla, at, ca, ua, sea int64
	err := r.Scan(&u.ID, &u.Sub, &u.Username, &u.Email, &u.Name, &groups, &u.VPNClaim, &isAdmin, &u.RefreshToken, &u.OIDCSID,
		&sca, &u.PwHash, &u.NTHash, &pia, &u.TLSKeySerial, &u.Status, &lca, &lco, &u.LastCheckError, &ifs, &lla, &at, &ca, &ua, &u.PwSeed, &sea)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(groups), &u.Groups)
	u.IsAdmin = isAdmin != 0
	u.SessionCreatedAt, u.PwIssuedAt, u.LastCheckAt, u.LastCheckOKAt = tm(sca), tm(pia), tm(lca), tm(lco)
	u.IdPFailSince, u.LastLoginAt, u.AuthTime, u.CreatedAt, u.UpdatedAt = tm(ifs), tm(lla), tm(at), tm(ca), tm(ua)
	u.SessionExpiresAt = tm(sea)
	return &u, nil
}

// UserByID loads a user.
func (s *Store) UserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserBySub loads a user by IdP subject.
func (s *Store) UserBySub(sub string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE sub = ?`, sub))
}

// UserByUsername loads a user by VPN login (case-insensitive).
func (s *Store) UserByUsername(name string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

// UsersBySID returns users bound to an IdP session id.
func (s *Store) UsersBySID(sid string) ([]*User, error) {
	return s.queryUsers(`SELECT `+userCols+` FROM users WHERE oidc_sid = ? AND oidc_sid != ''`, sid)
}

// Users returns all users.
func (s *Store) Users() ([]*User, error) {
	return s.queryUsers(`SELECT ` + userCols + ` FROM users ORDER BY username`)
}

// UsersWithPassword returns users whose VPN password is active.
func (s *Store) UsersWithPassword() ([]*User, error) {
	return s.queryUsers(`SELECT `+userCols+` FROM users WHERE status = ? ORDER BY id`, StatusActive)
}

func (s *Store) queryUsers(q string, args ...any) ([]*User, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SaveUser inserts or updates a user (matched by ID, or by sub when ID is 0).
func (s *Store) SaveUser(u *User) error {
	groups, _ := json.Marshal(u.Groups)
	if u.Groups == nil {
		groups = []byte("[]")
	}
	if u.Status == "" {
		u.Status = StatusNone
	}
	ts := now()
	if u.ID == 0 {
		u.CreatedAt = tm(ts)
		res, err := s.db.Exec(`INSERT INTO users (sub, username, email, name, groups_json, vpn_claim, is_admin, refresh_token, oidc_sid,
			session_created_at, pw_hash, nt_hash, pw_issued_at, tls_key_serial, status, last_check_at, last_check_ok_at, last_check_error,
			idp_fail_since, last_login_at, auth_time, created_at, updated_at, pw_seed, session_expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(sub) DO NOTHING`,
			u.Sub, u.Username, u.Email, u.Name, string(groups), u.VPNClaim, b2i(u.IsAdmin), u.RefreshToken, u.OIDCSID,
			unix(u.SessionCreatedAt), u.PwHash, u.NTHash, unix(u.PwIssuedAt), u.TLSKeySerial, u.Status, unix(u.LastCheckAt),
			unix(u.LastCheckOKAt), u.LastCheckError, unix(u.IdPFailSince), unix(u.LastLoginAt), unix(u.AuthTime), ts, ts, u.PwSeed, unix(u.SessionExpiresAt))
		if err != nil {
			return err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			existing, err := s.UserBySub(u.Sub)
			if err != nil {
				return err
			}
			u.ID = existing.ID
			return s.SaveUser(u)
		}
		u.ID = id
		return nil
	}
	_, err := s.db.Exec(`UPDATE users SET sub=?, username=?, email=?, name=?, groups_json=?, vpn_claim=?, is_admin=?, refresh_token=?,
		oidc_sid=?, session_created_at=?, pw_hash=?, nt_hash=?, pw_issued_at=?, tls_key_serial=?, status=?, last_check_at=?,
		last_check_ok_at=?, last_check_error=?, idp_fail_since=?, last_login_at=?, auth_time=?, updated_at=?, pw_seed=?, session_expires_at=? WHERE id=?`,
		u.Sub, u.Username, u.Email, u.Name, string(groups), u.VPNClaim, b2i(u.IsAdmin), u.RefreshToken, u.OIDCSID,
		unix(u.SessionCreatedAt), u.PwHash, u.NTHash, unix(u.PwIssuedAt), u.TLSKeySerial, u.Status, unix(u.LastCheckAt),
		unix(u.LastCheckOKAt), u.LastCheckError, unix(u.IdPFailSince), unix(u.LastLoginAt), unix(u.AuthTime), ts, u.PwSeed, unix(u.SessionExpiresAt), u.ID)
	u.UpdatedAt = tm(ts)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// RevokeTLSKey records a revoked tls-crypt-v2 client key.
func (s *Store) RevokeTLSKey(userID, serial int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO revoked_tls_keys(user_id, serial, revoked_at) VALUES (?,?,?)`, userID, serial, now())
	return err
}

// TLSKeyRevoked reports whether a tls-crypt-v2 key is revoked.
func (s *Store) TLSKeyRevoked(userID, serial int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM revoked_tls_keys WHERE user_id=? AND serial=?`, userID, serial).Scan(&n)
	return n > 0, err
}

// --- web sessions ---

// WebSession is a portal login.
type WebSession struct {
	ID        string // SHA-256 of the cookie token
	UserID    int64
	Emergency bool
	CSRF      string
	AuthTime  time.Time
	CreatedAt time.Time
	ExpiresAt time.Time
	IDToken   []byte // sealed ID token (id_token_hint at logout); nil for the emergency admin
}

// CreateWebSession stores a portal session.
func (s *Store) CreateWebSession(w *WebSession) error {
	_, err := s.db.Exec(`INSERT INTO web_sessions(id, user_id, emergency, csrf, auth_time, created_at, expires_at, id_token) VALUES (?,?,?,?,?,?,?,?)`,
		w.ID, w.UserID, b2i(w.Emergency), w.CSRF, unix(w.AuthTime), unix(w.CreatedAt), unix(w.ExpiresAt), w.IDToken)
	return err
}

// WebSession loads a non-expired portal session.
func (s *Store) WebSession(id string) (*WebSession, error) {
	var w WebSession
	var em int
	var at, ca, ea int64
	err := s.db.QueryRow(`SELECT id, user_id, emergency, csrf, auth_time, created_at, expires_at, id_token FROM web_sessions WHERE id=? AND expires_at > ?`,
		id, now()).Scan(&w.ID, &w.UserID, &em, &w.CSRF, &at, &ca, &ea, &w.IDToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	w.Emergency = em != 0
	w.AuthTime, w.CreatedAt, w.ExpiresAt = tm(at), tm(ca), tm(ea)
	return &w, nil
}

// DeleteWebSession removes one portal session.
func (s *Store) DeleteWebSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM web_sessions WHERE id=?`, id)
	return err
}

// DeleteUserWebSessions logs a user out of the portal everywhere.
func (s *Store) DeleteUserWebSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM web_sessions WHERE user_id=? AND emergency=0`, userID)
	return err
}

// --- downloads ---

// CreateDownload registers a short-lived download token.
func (s *Store) CreateDownload(id string, userID int64, kind string, ttl time.Duration) error {
	_, err := s.db.Exec(`INSERT INTO downloads(id, user_id, kind, expires_at) VALUES (?,?,?,?)`, id, userID, kind, time.Now().Add(ttl).Unix())
	return err
}

// TakeDownload consumes a download token.
func (s *Store) TakeDownload(id string) (userID int64, kind string, err error) {
	err = s.db.QueryRow(`DELETE FROM downloads WHERE id=? AND expires_at > ? RETURNING user_id, kind`, id, now()).Scan(&userID, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrNotFound
	}
	return
}

// Cleanup removes expired rows.
func (s *Store) Cleanup(auditRetention time.Duration) error {
	ts := now()
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM web_sessions WHERE expires_at <= ?`, []any{ts}},
		{`DELETE FROM downloads WHERE expires_at <= ?`, []any{ts}},
		{`DELETE FROM audit WHERE ts < ?`, []any{ts - int64(auditRetention.Seconds())}},
		{`DELETE FROM vpn_sessions WHERE ended_at != 0 AND ended_at < ?`, []any{ts - int64(auditRetention.Seconds())}},
		{`DELETE FROM traffic WHERE bucket='hour' AND ts < ?`, []any{ts - 40*86400}},
		{`DELETE FROM traffic WHERE bucket='day' AND ts < ?`, []any{ts - 400*86400}},
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st.q, st.args...); err != nil {
			return err
		}
	}
	return nil
}
