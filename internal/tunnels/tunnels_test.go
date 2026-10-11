package tunnels

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"vpngw/internal/config"
	"vpngw/internal/goproxy/keys"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

func newManager(t *testing.T) *Manager {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, _ := secret.NewBox(secret.RandomBytes(32))
	cfg := config.NewFromMap(map[string]string{"VPN_HOSTNAME": "vpn.example.com", "TUNNEL_ADDRESS": "10.255.250.1/32"})
	return &Manager{Cfg: cfg, Store: st, Box: box, Dir: t.TempDir()}
}

func pub(t *testing.T) string {
	k, _ := keys.GeneratePrivateKey()
	return k.Public().String()
}

func TestIfaceName(t *testing.T) {
	for in, want := range map[string]string{"lat": "gp-lat", "DC_Riga": "gp-dc-riga", "very-long-site-name": "gp-very-long-si"} {
		if got := IfaceName(in); got != want || len(got) > 15 {
			t.Errorf("IfaceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPeersAndRoutes(t *testing.T) {
	m := newManager(t)
	t.Setenv("TUNNEL_PEER_ENVDC_PUBLIC_KEY", pub(t))
	t.Setenv("TUNNEL_PEER_ENVDC_SUBNETS", "10.7.0.0/16, 10.8.0.0/24")
	t.Setenv("TUNNEL_PEER_ENVDC_EXIT", "true")
	pools := []netip.Prefix{netip.MustParsePrefix("10.250.0.0/16")}
	p := Peer{Name: "lat", PublicKey: pub(t), Endpoint: "203.0.113.10:444", PSK: "secret", NAT: true,
		Subnets: []netip.Prefix{netip.MustParsePrefix("10.6.0.0/16")}, Source: "admin"}
	if err := m.Validate(p, pools); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	peers := m.Peers()
	if len(peers) != 2 || peers[0].Source != "env" || !peers[0].NAT || !peers[0].Exit || peers[1].PSK != "secret" {
		t.Fatalf("peers %+v", peers)
	}
	// ENVDC connects to us: it gets an automatic address, routed back to it.
	if a := peers[0].Address.String(); a != "10.255.250.2" || !peers[0].AutoAddress || peers[1].Address.IsValid() {
		t.Fatalf("addresses %v %v", peers[0].Address, peers[1].Address)
	}
	routes := m.Routes()
	if len(routes) != 4 || routes[0].Prefix.String() != "10.255.250.2/32" || routes[1].Prefix.String() != "10.6.0.0/16" || routes[1].Dev != "gp-lat" {
		t.Fatalf("routes %+v", routes)
	}
	if f, ok := m.Find("LAT"); !ok || f.Interface() != "gp-lat" {
		t.Fatal("find by name is case-insensitive")
	}
	if f, ok := m.Find("GP-LAT"); !ok || f.Name != "lat" {
		t.Fatal("vpnGateway may name the interface too")
	}
	// Conversion for goproxy: own interface, any source (nftables filters).
	gp := goproxyPeers(peers, true)
	if gp[0].Interface != "gp-envdc" || gp[0].IP != "10.255.250.2" || gp[1].IP != "" ||
		strings.Join(gp[0].Routes, " ") != "0.0.0.0/0" || strings.Join(gp[1].Routes, " ") != "0.0.0.0/0" {
		t.Fatalf("goproxy peers %+v", gp)
	}

	bad := []Peer{
		{Name: "x y", PublicKey: pub(t), Subnets: p.Subnets},
		{Name: "dup", PublicKey: pub(t), Subnets: []netip.Prefix{netip.MustParsePrefix("10.6.0.0/16")}},
		{Name: "pool", PublicKey: pub(t), Subnets: []netip.Prefix{netip.MustParsePrefix("10.250.1.0/24")}},
		{Name: "envdc", PublicKey: pub(t), Exit: true},
		{Name: "own", PublicKey: pub(t), Address: netip.MustParseAddr("10.255.250.1")},
		{Name: "out", PublicKey: pub(t), Endpoint: "203.0.113.11:444", Address: netip.MustParseAddr("10.255.250.9")},
		{Name: "all", PublicKey: pub(t), Subnets: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{Name: "key", PublicKey: "bad", Exit: true},
	}
	for _, b := range bad {
		if err := m.Validate(b, pools); err == nil {
			t.Errorf("peer %q must be rejected", b.Name)
		}
	}
	// A plain incoming site needs nothing but a key.
	if err := m.Validate(Peer{Name: "plain", PublicKey: pub(t)}, pools); err != nil {
		t.Fatal(err)
	}
}

func TestAddressesAndAllowances(t *testing.T) {
	m := newManager(t)
	for _, p := range []Peer{
		{Name: "a", PublicKey: pub(t), Allow: []netip.Prefix{netip.MustParsePrefix("10.6.0.0/16")}},
		{Name: "b", PublicKey: pub(t), Address: netip.MustParseAddr("10.255.250.2")},
		{Name: "c", PublicKey: pub(t), Endpoint: "203.0.113.12:444", Allow: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
	} {
		if err := m.Save(p); err != nil {
			t.Fatal(err)
		}
	}
	addr := func() map[string]string {
		out := map[string]string{}
		for _, p := range m.Peers() {
			out[p.Name] = p.Address.String()
		}
		return out
	}
	got := addr()
	if got["a"] != "10.255.250.3" || got["b"] != "10.255.250.2" || got["c"] != "invalid IP" {
		t.Fatalf("addresses %v", got)
	}
	if again := addr(); again["a"] != got["a"] {
		t.Fatal("automatic addresses must be stable")
	}
	al := m.Allowances()
	if len(al) != 2 || al[0].Dev != "gp-a" || al[1].Prefix.Bits() != 0 {
		t.Fatalf("allowances %+v", al)
	}
}

func TestNodeAddress(t *testing.T) {
	m := newManager(t)
	if a, auto := m.NodeAddress(); a.String() != "10.255.250.1/32" || auto {
		t.Fatalf("explicit address %v %v", a, auto)
	}
	m.Cfg = config.NewFromMap(map[string]string{})
	if a, auto := m.NodeAddress(); a.String() != "10.255.250.1/32" || !auto {
		t.Fatalf("connect-only default %v", a)
	}
	m.Cfg = config.NewFromMap(map[string]string{"TUNNEL_LISTEN": "0.0.0.0:444"})
	a, auto := m.NodeAddress()
	if !auto || a.Bits() != 32 || a.Addr().As4()[0] != 10 || a.Addr().As4()[1] != 255 || a.Addr().As4()[3] != 1 {
		t.Fatalf("automatic address %v", a)
	}
	if b, _ := m.NodeAddress(); b != a {
		t.Fatal("automatic address must be stable")
	}
}

func TestNodeKeyPersisted(t *testing.T) {
	m := newManager(t)
	k1 := m.PublicKey()
	if k1 == "" || m.PublicKey() != k1 {
		t.Fatal("generated key must persist")
	}
	cfg, err := m.nodeConfig()
	if err != nil || cfg.PushRoutes != "false" || cfg.InterfaceName != "gp0" || cfg.Transport != "udp" {
		t.Fatalf("node config %+v %v", cfg, err)
	}
	rc := m.RemoteConfig(Peer{Name: "lat", NAT: true, Subnets: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Allow: []netip.Prefix{netip.MustParsePrefix("10.6.0.0/16"), netip.MustParsePrefix("0.0.0.0/0")}}, "vpn.example.com:444")
	for _, want := range []string{"TUNNEL_PEER_VPN_ENDPOINT: vpn.example.com:444\n", "TUNNEL_PEER_VPN_SUBNETS: 10.6.0.0/16\n",
		"TUNNEL_PEER_VPN_EXIT: true", "TUNNEL_PEER_VPN_ALLOW: 10.20.0.0/16\n", "TUNNEL_PSK: \"<the shared PSK>\"\n"} {
		if !strings.Contains(rc, want) {
			t.Errorf("remote config lacks %q:\n%s", want, rc)
		}
	}
}

func TestRegenerateKey(t *testing.T) {
	m := newManager(t)
	old := m.PublicKey()
	pub, err := m.RegenerateKey()
	if err != nil || pub == old || m.PublicKey() != pub {
		t.Fatalf("regenerate: %v %q %q", err, old, pub)
	}
	k, _ := keys.GeneratePrivateKey()
	m.Cfg = config.NewFromMap(map[string]string{"TUNNEL_PRIVATE_KEY": k.String()})
	if !m.KeyConfigured() {
		t.Fatal("key from TUNNEL_PRIVATE_KEY")
	}
	if _, err := m.RegenerateKey(); err == nil {
		t.Fatal("a configured key must not be regenerated")
	}
}

func TestCheckEnv(t *testing.T) {
	m := newManager(t)
	pools := []netip.Prefix{netip.MustParsePrefix("10.250.0.0/16")}
	key := pub(t)
	t.Setenv("TUNNEL_PEER_GOOD_PUBLIC_KEY", key)
	t.Setenv("TUNNEL_PEER_GOOD_SUBNETS", "10.4.0.0/16")
	t.Setenv("TUNNEL_PEER_GOOD_EXIT", "true")
	if p := append(CheckEnv(m.Cfg, pools), m.CheckTransitGateway()...); len(p) != 0 {
		t.Fatalf("valid environment: %v", p)
	}
	t.Setenv("TUNNEL_PEER_ALL_PUBLIC_KEY", pub(t))
	t.Setenv("TUNNEL_PEER_ALL_SUBNETS", "10.6.0.0/16 0.0.0.0/0")
	t.Setenv("TUNNEL_PEER_DUP_PUBLIC_KEY", key)
	t.Setenv("TUNNEL_PEER_BAD_PUBLIC_KEY", "nope")
	t.Setenv("TUNNEL_PEER_BAD_EXIT", "yes")
	t.Setenv("TUNNEL_PEER_BAD_KEEPALIVE", "-1")
	t.Setenv("TUNNEL_PEER_POOL_PUBLIC_KEY", pub(t))
	t.Setenv("TUNNEL_PEER_POOL_SUBNETS", "10.250.1.0/24")
	t.Setenv("TUNNEL_PEER_GOOD_SUBNET", "10.5.0.0/16")
	t.Setenv("TUNNEL_PEER_NOKEY_ENDPOINT", "dc.example.com:444")
	m.Cfg = config.NewFromMap(map[string]string{"TUNNEL_ADDRESS": "10.255.250.1/32", "TUNNEL_TRANSIT_GATEWAY": "NOPE", "SOCKS_GATEWAY": "NOPE2"})
	all := strings.Join(append(CheckEnv(m.Cfg, pools), m.CheckTransitGateway()...), "\n")
	for _, w := range []string{
		"TUNNEL_PEER_ALL: networks behind the site: 0.0.0.0/0",
		"TUNNEL_PEER_GOOD: public key already used by peer DUP",
		"TUNNEL_PEER_BAD_EXIT: true or false", "TUNNEL_PEER_BAD_KEEPALIVE: seconds",
		"TUNNEL_PEER_POOL: subnet 10.250.1.0/24 overlaps the VPN pool",
		"unknown setting TUNNEL_PEER_GOOD_SUBNET (did you mean TUNNEL_PEER_GOOD_SUBNETS?)",
		"TUNNEL_PEER_NOKEY_PUBLIC_KEY: required",
		"TUNNEL_TRANSIT_GATEWAY: no site NOPE",
		"SOCKS_GATEWAY: no site NOPE2",
	} {
		if !strings.Contains(all, w) {
			t.Errorf("missing %q in:\n%s", w, all)
		}
	}
}
