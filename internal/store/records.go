package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// --- audit ---

// AuditEntry is one journal record.
type AuditEntry struct {
	ID       int64
	TS       time.Time
	Level    string
	Event    string
	Actor    string
	Username string
	Protocol string
	IP       string
	Message  string
}

// AddAudit appends a journal record.
func (s *Store) AddAudit(e *AuditEntry) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Level == "" {
		e.Level = "info"
	}
	res, err := s.db.Exec(`INSERT INTO audit(ts, level, event, actor, username, protocol, ip, message) VALUES (?,?,?,?,?,?,?,?)`,
		e.TS.Unix(), e.Level, e.Event, e.Actor, e.Username, e.Protocol, e.IP, e.Message)
	if err == nil {
		e.ID, _ = res.LastInsertId()
	}
	return err
}

// AuditFilter narrows journal queries.
type AuditFilter struct {
	Username string
	Event    string
	Protocol string
	Search   string
	Since    time.Time
	Until    time.Time
	Limit    int
	BeforeID int64
}

// Audit returns journal entries, newest first.
func (s *Store) Audit(f AuditFilter) ([]AuditEntry, error) {
	var where []string
	var args []any
	if f.Username != "" {
		where = append(where, "username = ? COLLATE NOCASE")
		args = append(args, f.Username)
	}
	if f.Event != "" {
		where = append(where, "event LIKE ?")
		args = append(args, f.Event+"%")
	}
	if f.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, f.Protocol)
	}
	if f.Search != "" {
		where = append(where, "(message LIKE ? OR username LIKE ? OR ip LIKE ? OR actor LIKE ?)")
		p := "%" + f.Search + "%"
		args = append(args, p, p, p, p)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		where = append(where, "ts < ?")
		args = append(args, f.Until.Unix())
	}
	if f.BeforeID > 0 {
		where = append(where, "id < ?")
		args = append(args, f.BeforeID)
	}
	q := `SELECT id, ts, level, event, actor, username, protocol, ip, message FROM audit`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Event, &e.Actor, &e.Username, &e.Protocol, &e.IP, &e.Message); err != nil {
			return nil, err
		}
		e.TS = tm(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- VPN session history ---

// SessionRecord is a persisted VPN session.
type SessionRecord struct {
	ID         int64
	UserID     int64
	Username   string
	Login      string
	Protocol   string
	BackendRef string
	ProfileID  string
	VPNIP      string
	ClientIP   string
	StartedAt  time.Time
	EndedAt    time.Time
	BytesIn    int64
	BytesOut   int64
	EndReason  string
}

// InsertSession stores a new session row.
func (s *Store) InsertSession(r *SessionRecord) error {
	res, err := s.db.Exec(`INSERT INTO vpn_sessions(user_id, username, login, protocol, backend_ref, profile_id, vpn_ip, client_ip, started_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, r.UserID, r.Username, r.Login, r.Protocol, r.BackendRef, r.ProfileID, r.VPNIP, r.ClientIP, unix(r.StartedAt))
	if err != nil {
		return err
	}
	r.ID, err = res.LastInsertId()
	return err
}

// UpdateSessionCounters stores current byte counters.
func (s *Store) UpdateSessionCounters(id, in, out int64, backendRef, clientIP string) error {
	_, err := s.db.Exec(`UPDATE vpn_sessions SET bytes_in=?, bytes_out=?, backend_ref=CASE WHEN ?='' THEN backend_ref ELSE ? END,
		client_ip=CASE WHEN ?='' THEN client_ip ELSE ? END WHERE id=?`, in, out, backendRef, backendRef, clientIP, clientIP, id)
	return err
}

// EndSession closes a session row.
func (s *Store) EndSession(id int64, in, out int64, reason string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE vpn_sessions SET bytes_in=?, bytes_out=?, end_reason=?, ended_at=? WHERE id=? AND ended_at=0`,
		in, out, reason, unix(at), id)
	return err
}

// CloseOrphanSessions ends rows left open by a previous run.
func (s *Store) CloseOrphanSessions(reason string) error {
	_, err := s.db.Exec(`UPDATE vpn_sessions SET ended_at=?, end_reason=? WHERE ended_at=0`, now(), reason)
	return err
}

// RecentSessions returns sessions of a user, newest first.
func (s *Store) RecentSessions(userID int64, limit int) ([]SessionRecord, error) {
	rows, err := s.db.Query(`SELECT id, user_id, username, login, protocol, backend_ref, profile_id, vpn_ip, client_ip, started_at, ended_at,
		bytes_in, bytes_out, end_reason FROM vpn_sessions WHERE user_id=? ORDER BY id DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRecord
	for rows.Next() {
		var r SessionRecord
		var sa, ea int64
		if err := rows.Scan(&r.ID, &r.UserID, &r.Username, &r.Login, &r.Protocol, &r.BackendRef, &r.ProfileID, &r.VPNIP, &r.ClientIP,
			&sa, &ea, &r.BytesIn, &r.BytesOut, &r.EndReason); err != nil {
			return nil, err
		}
		r.StartedAt, r.EndedAt = tm(sa), tm(ea)
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- traffic ---

// AddTraffic adds byte deltas to the hourly and daily buckets of a user.
func (s *Store) AddTraffic(userID int64, at time.Time, rx, tx int64) error {
	if rx == 0 && tx == 0 {
		return nil
	}
	hour := at.Truncate(time.Hour).Unix()
	y, m, d := at.UTC().Date()
	day := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix()
	for _, b := range []struct {
		name string
		ts   int64
	}{{"hour", hour}, {"day", day}} {
		if _, err := s.db.Exec(`INSERT INTO traffic(user_id, bucket, ts, rx, tx) VALUES (?,?,?,?,?)
			ON CONFLICT(user_id, bucket, ts) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx`, userID, b.name, b.ts, rx, tx); err != nil {
			return err
		}
	}
	return nil
}

// TrafficPoint is one bucket.
type TrafficPoint struct {
	TS time.Time
	RX int64
	TX int64
}

// Traffic returns buckets ("hour" or "day") since a time.
func (s *Store) Traffic(userID int64, bucket string, since time.Time) ([]TrafficPoint, error) {
	rows, err := s.db.Query(`SELECT ts, rx, tx FROM traffic WHERE user_id=? AND bucket=? AND ts >= ? ORDER BY ts`, userID, bucket, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrafficPoint
	for rows.Next() {
		var p TrafficPoint
		var ts int64
		if err := rows.Scan(&ts, &p.RX, &p.TX); err != nil {
			return nil, err
		}
		p.TS = tm(ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// TrafficTotals returns rx/tx sums per user since a time (hour buckets).
func (s *Store) TrafficTotals(since time.Time) (map[int64][2]int64, error) {
	rows, err := s.db.Query(`SELECT user_id, SUM(rx), SUM(tx) FROM traffic WHERE bucket='hour' AND ts >= ? GROUP BY user_id`, since.Truncate(time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][2]int64{}
	for rows.Next() {
		var id, rx, tx int64
		if err := rows.Scan(&id, &rx, &tx); err != nil {
			return nil, err
		}
		out[id] = [2]int64{rx, tx}
	}
	return out, rows.Err()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// IsNotFound reports whether err is ErrNotFound or sql.ErrNoRows.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}
