// Package store persists gateway state in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the database handle.
type Store struct {
	db *sql.DB
}

// migrations are applied in order; never edit an applied migration.
var migrations = []string{
	`CREATE TABLE settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		updated_by TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE kv (
		key TEXT PRIMARY KEY,
		value BLOB NOT NULL
	);
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sub TEXT NOT NULL UNIQUE,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		email TEXT NOT NULL DEFAULT '',
		name TEXT NOT NULL DEFAULT '',
		groups_json TEXT NOT NULL DEFAULT '[]',
		vpn_claim TEXT NOT NULL DEFAULT '',
		is_admin INTEGER NOT NULL DEFAULT 0,
		refresh_token BLOB,
		oidc_sid TEXT NOT NULL DEFAULT '',
		session_created_at INTEGER NOT NULL DEFAULT 0,
		pw_hash TEXT NOT NULL DEFAULT '',
		nt_hash BLOB,
		pw_issued_at INTEGER NOT NULL DEFAULT 0,
		tls_key_serial INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'none',
		last_check_at INTEGER NOT NULL DEFAULT 0,
		last_check_ok_at INTEGER NOT NULL DEFAULT 0,
		last_check_error TEXT NOT NULL DEFAULT '',
		idp_fail_since INTEGER NOT NULL DEFAULT 0,
		last_login_at INTEGER NOT NULL DEFAULT 0,
		auth_time INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE web_sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL DEFAULT 0,
		emergency INTEGER NOT NULL DEFAULT 0,
		csrf TEXT NOT NULL,
		auth_time INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE INDEX web_sessions_user ON web_sessions(user_id);
	CREATE TABLE vpn_sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL DEFAULT 0,
		username TEXT NOT NULL,
		login TEXT NOT NULL,
		protocol TEXT NOT NULL,
		backend_ref TEXT NOT NULL DEFAULT '',
		profile_id TEXT NOT NULL DEFAULT '',
		vpn_ip TEXT NOT NULL,
		client_ip TEXT NOT NULL DEFAULT '',
		started_at INTEGER NOT NULL,
		ended_at INTEGER NOT NULL DEFAULT 0,
		bytes_in INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		end_reason TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX vpn_sessions_user ON vpn_sessions(user_id, started_at);
	CREATE INDEX vpn_sessions_open ON vpn_sessions(ended_at);
	CREATE TABLE audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts INTEGER NOT NULL,
		level TEXT NOT NULL,
		event TEXT NOT NULL,
		actor TEXT NOT NULL DEFAULT '',
		username TEXT NOT NULL DEFAULT '',
		protocol TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT '',
		message TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX audit_ts ON audit(ts);
	CREATE INDEX audit_user ON audit(username, ts);
	CREATE TABLE route_maps (
		group_name TEXT PRIMARY KEY COLLATE NOCASE,
		routes TEXT NOT NULL DEFAULT '[]',
		dns TEXT NOT NULL DEFAULT '[]',
		gateway TEXT NOT NULL DEFAULT '',
		domain TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE traffic (
		user_id INTEGER NOT NULL,
		bucket TEXT NOT NULL,
		ts INTEGER NOT NULL,
		rx INTEGER NOT NULL DEFAULT 0,
		tx INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, bucket, ts)
	);
	CREATE TABLE revoked_tls_keys (
		user_id INTEGER NOT NULL,
		serial INTEGER NOT NULL,
		revoked_at INTEGER NOT NULL,
		PRIMARY KEY (user_id, serial)
	);
	CREATE TABLE downloads (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		kind TEXT NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE TABLE config_overrides (
		name TEXT PRIMARY KEY,
		content TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		updated_by TEXT NOT NULL DEFAULT ''
	);`,
	// Encrypted password derivation inputs (sid, session time, nonce) so
	// the portal can show the password without storing it.
	`ALTER TABLE users ADD COLUMN pw_seed BLOB;`,
	`CREATE TABLE tunnel_peers (
		name TEXT PRIMARY KEY COLLATE NOCASE,
		public_key TEXT NOT NULL,
		endpoint TEXT NOT NULL DEFAULT '',
		transport TEXT NOT NULL DEFAULT '',
		psk BLOB,
		subnets TEXT NOT NULL DEFAULT '[]',
		exit INTEGER NOT NULL DEFAULT 0,
		nat INTEGER NOT NULL DEFAULT 1,
		disabled INTEGER NOT NULL DEFAULT 0,
		keepalive INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL
	);`,
	// Routing comes from tunnel peers; admin group → routes mappings are gone.
	`DROP TABLE IF EXISTS route_maps;`,
	// When the IdP session (refresh token) ends, if the IdP tells.
	`ALTER TABLE users ADD COLUMN session_expires_at INTEGER NOT NULL DEFAULT 0;`,
	// Tunnel peers: address handed to the site, networks it may reach here.
	`ALTER TABLE tunnel_peers ADD COLUMN address TEXT NOT NULL DEFAULT '';
	ALTER TABLE tunnel_peers ADD COLUMN allow TEXT NOT NULL DEFAULT '[]';`,
	// ID token of a portal session (sealed), for RP-initiated logout.
	`ALTER TABLE web_sessions ADD COLUMN id_token BLOB;`,
}

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for ad-hoc queries.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (0)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`UPDATE schema_version SET version = ?`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func now() int64 { return time.Now().Unix() }

func tm(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// --- settings ---

// Settings returns all admin overrides.
func (s *Store) Settings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

// SetSetting stores (value != nil) or deletes an override.
func (s *Store) SetSetting(key string, value *string, by string) error {
	if value == nil {
		_, err := s.db.Exec(`DELETE FROM settings WHERE key = ?`, key)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO settings(key, value, updated_at, updated_by) VALUES (?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		key, *value, now(), by)
	return err
}

// --- kv ---

// GetKV returns a raw value.
func (s *Store) GetKV(key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// PutKV stores a raw value.
func (s *Store) PutKV(key string, v []byte) error {
	_, err := s.db.Exec(`INSERT INTO kv(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, v)
	return err
}

// --- config overrides ---

// ConfigOverride is a manually edited backend config.
type ConfigOverride struct {
	Name      string
	Content   string
	UpdatedAt time.Time
	UpdatedBy string
}

// ConfigOverrides returns all overrides keyed by name.
func (s *Store) ConfigOverrides() (map[string]ConfigOverride, error) {
	rows, err := s.db.Query(`SELECT name, content, updated_at, updated_by FROM config_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]ConfigOverride{}
	for rows.Next() {
		var o ConfigOverride
		var ts int64
		if err := rows.Scan(&o.Name, &o.Content, &ts, &o.UpdatedBy); err != nil {
			return nil, err
		}
		o.UpdatedAt = tm(ts)
		m[o.Name] = o
	}
	return m, rows.Err()
}

// SetConfigOverride stores or (content == nil) removes an override.
func (s *Store) SetConfigOverride(name string, content *string, by string) error {
	if content == nil {
		_, err := s.db.Exec(`DELETE FROM config_overrides WHERE name = ?`, name)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO config_overrides(name, content, updated_at, updated_by) VALUES (?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at, updated_by=excluded.updated_by`,
		name, *content, now(), by)
	return err
}
