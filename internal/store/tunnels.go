package store

import (
	"encoding/json"
	"time"
)

// TunnelPeer is a remote site (goproxy node) configured in the admin panel.
type TunnelPeer struct {
	Name      string
	PublicKey string
	Endpoint  string
	Transport string
	PSK       []byte // encrypted; nil = node default
	Subnets   []string
	Exit      bool
	NAT       bool
	Disabled  bool
	Keepalive int
	Address   string   // tunnel address handed to the site ("" = automatic)
	Allow     []string // networks the site may reach through this node
	UpdatedAt time.Time
}

// TunnelPeers returns all peers.
func (s *Store) TunnelPeers() ([]TunnelPeer, error) {
	rows, err := s.db.Query(`SELECT name, public_key, endpoint, transport, psk, subnets, exit, nat, disabled, keepalive, updated_at,
		address, allow FROM tunnel_peers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TunnelPeer
	for rows.Next() {
		var p TunnelPeer
		var subnets, allow string
		var exit, nat, dis int
		var ua int64
		if err := rows.Scan(&p.Name, &p.PublicKey, &p.Endpoint, &p.Transport, &p.PSK, &subnets, &exit, &nat, &dis, &p.Keepalive, &ua,
			&p.Address, &allow); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(subnets), &p.Subnets)
		_ = json.Unmarshal([]byte(allow), &p.Allow)
		p.Exit, p.NAT, p.Disabled, p.UpdatedAt = exit != 0, nat != 0, dis != 0, tm(ua)
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveTunnelPeer inserts or replaces a peer.
func (s *Store) SaveTunnelPeer(p *TunnelPeer) error {
	subnets, _ := json.Marshal(nonNil(p.Subnets))
	allow, _ := json.Marshal(nonNil(p.Allow))
	_, err := s.db.Exec(`INSERT INTO tunnel_peers(name, public_key, endpoint, transport, psk, subnets, exit, nat, disabled, keepalive, updated_at,
		address, allow) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET public_key=excluded.public_key, endpoint=excluded.endpoint, transport=excluded.transport,
		psk=excluded.psk, subnets=excluded.subnets, exit=excluded.exit, nat=excluded.nat, disabled=excluded.disabled,
		keepalive=excluded.keepalive, updated_at=excluded.updated_at, address=excluded.address, allow=excluded.allow`,
		p.Name, p.PublicKey, p.Endpoint, p.Transport, p.PSK, string(subnets), b2i(p.Exit), b2i(p.NAT), b2i(p.Disabled), p.Keepalive, now(),
		p.Address, string(allow))
	return err
}

// DeleteTunnelPeer removes a peer.
func (s *Store) DeleteTunnelPeer(name string) error {
	res, err := s.db.Exec(`DELETE FROM tunnel_peers WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
