// Package tunnels runs the embedded goproxy node that links this gateway
// with remote sites (data centers). Every peer gets a TUN of its own
// (gp-<name>); the subnets configured for a peer are routed into it for VPN
// clients, and a peer can be the internet exit of clients whose vpnGateway
// names it.
package tunnels

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpngw/internal/config"
	gpconfig "vpngw/internal/goproxy/config"
	"vpngw/internal/goproxy/keys"
	"vpngw/internal/goproxy/node"
	"vpngw/internal/secret"
	"vpngw/internal/store"
)

// Peer is a remote site.
type Peer struct {
	Name      string
	PublicKey string
	Endpoint  string         // host:port to connect to; empty = the site connects to us
	Transport string         // empty = TUNNEL_TRANSPORT
	PSK       string         // empty = TUNNEL_PSK
	Subnets   []netip.Prefix // networks behind the site, routed into its tunnel
	Exit      bool           // the site may carry our users' internet (vpnGateway)
	Allow     []netip.Prefix // networks of ours the site may reach (0.0.0.0/0 = internet)
	// Address is the tunnel address handed to a site that connects to us;
	// automatic unless set. Sites we connect to assign ours.
	Address     netip.Addr
	AutoAddress bool // Address was assigned automatically
	NAT         bool // clients appear at the site with this node's address
	Disabled    bool
	Keepalive   int
	Source      string // "env" or "admin"
}

// Incoming reports whether the site connects to us.
func (p *Peer) Incoming() bool { return p.Endpoint == "" }

// Interface returns the name of the peer's TUN.
func (p *Peer) Interface() string { return IfaceName(p.Name) }

// IfaceName derives the interface name of a peer: gp-<name>, at most 15 characters.
func IfaceName(name string) string {
	n := strings.ToLower(strings.NewReplacer("_", "-").Replace(name))
	if len(n) > 12 {
		n = n[:12]
	}
	return "gp-" + n
}

// Allowance is a network a site may reach through this node.
type Allowance struct {
	Dev    string
	Prefix netip.Prefix
}

// Allowances returns what each enabled site may reach through this node.
func (m *Manager) Allowances() []Allowance {
	var out []Allowance
	for _, p := range m.Peers() {
		if p.Disabled {
			continue
		}
		for _, a := range p.Allow {
			out = append(out, Allowance{Dev: p.Interface(), Prefix: a})
		}
	}
	return out
}

// Route is a subnet routed into a peer's interface.
type Route struct {
	Prefix netip.Prefix
	Peer   string
	Dev    string
}

// Manager owns the node.
type Manager struct {
	Cfg   *config.Config
	Store *store.Store
	Box   *secret.Box
	Dir   string // goproxy data directory

	// OnChange is called after peers or their interfaces changed so routing
	// can be brought in line.
	OnChange func()

	addrMu  sync.Mutex
	mu      sync.Mutex
	node    *node.Node
	stop    chan struct{}
	done    chan struct{}
	lastErr string
	started time.Time
	kick    chan struct{}
}

const envPrefix = "TUNNEL_PEER_"

// envPeers parses TUNNEL_PEER_<NAME>_<FIELD> variables.
// peerFields are the TUNNEL_PEER_<NAME>_* settings.
var peerFields = []string{"PUBLIC_KEY", "ENDPOINT", "TRANSPORT", "PSK", "SUBNETS", "EXIT", "ALLOW", "ADDRESS", "NAT", "DISABLED", "KEEPALIVE"}

// envPeers parses the peers declared in the environment and reports all
// problems (the gateway does not start with any).
func envPeers() ([]Peer, []string) {
	var problems []string
	fields := map[string]map[string]string{}
	environ := os.Environ()
	sort.Strings(environ)
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, envPrefix) {
			continue
		}
		rest := strings.TrimPrefix(k, envPrefix)
		known := false
		for _, f := range peerFields {
			if name, ok := strings.CutSuffix(rest, "_"+f); ok && name != "" {
				if fields[name] == nil {
					fields[name] = map[string]string{}
				}
				fields[name][f] = strings.TrimSpace(v)
				known = true
				break
			}
		}
		if !known {
			msg := "unknown setting " + k + " (fields: " + strings.Join(peerFields, ", ") + ")"
			// The name and the field both may contain '_': try every split.
			var cands []string
			for j := 1; j < len(rest); j++ {
				if rest[j] == '_' {
					for _, f := range peerFields {
						cands = append(cands, rest[:j]+"_"+f)
					}
				}
			}
			if s := config.Suggest(rest, cands); s != "" {
				msg = "unknown setting " + k + " (did you mean " + envPrefix + s + "?)"
			}
			problems = append(problems, msg)
		}
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Peer
	for _, name := range names {
		f := fields[name]
		pre := envPrefix + name + "_"
		bad := func(field string, err error) {
			problems = append(problems, fmt.Sprintf("%s%s: %v", pre, field, err))
		}
		if f["PUBLIC_KEY"] == "" {
			bad("PUBLIC_KEY", errors.New("required"))
		}
		p := Peer{Name: name, PublicKey: f["PUBLIC_KEY"], Endpoint: f["ENDPOINT"], Transport: f["TRANSPORT"], PSK: f["PSK"], Source: "env"}
		for field, dst := range map[string]*bool{"EXIT": &p.Exit, "NAT": &p.NAT, "DISABLED": &p.Disabled} {
			v, set := f[field]
			if !set || v == "" {
				*dst = field == "NAT" // NAT is on unless turned off
				continue
			}
			b, err := strconv.ParseBool(v)
			if err != nil {
				bad(field, errors.New("true or false"))
			}
			*dst = b
		}
		if v := f["KEEPALIVE"]; v != "" {
			k, err := strconv.Atoi(v)
			if err != nil || k < 0 {
				bad("KEEPALIVE", errors.New("seconds, 0 or more"))
			}
			p.Keepalive = k
		}
		var err error
		if p.Subnets, err = parsePrefixes(f["SUBNETS"]); err != nil {
			bad("SUBNETS", err)
		}
		if p.Allow, err = parsePrefixes(f["ALLOW"]); err != nil {
			bad("ALLOW", err)
		}
		if a := f["ADDRESS"]; a != "" && a != "auto" {
			if p.Address, err = netip.ParseAddr(a); err != nil || !p.Address.Is4() {
				bad("ADDRESS", errors.New("an IPv4 address"))
			}
		}
		out = append(out, p)
	}
	return out, problems
}

// CheckEnv validates the tunnel peers from the environment at startup,
// before the database is open: the same rules as for peers added in the
// panel.
func CheckEnv(cfg *config.Config, pools []netip.Prefix) []string {
	peers, problems := envPeers()
	var own netip.Addr
	if p, err := netip.ParsePrefix(cfg.Str("TUNNEL_ADDRESS")); err == nil {
		own = p.Addr()
	}
	for i, p := range peers {
		if p.PublicKey == "" {
			continue // reported as missing
		}
		pre := envPrefix + p.Name + ": "
		if err := checkPeer(p, pools, own); err != nil {
			problems = append(problems, pre+err.Error())
			continue
		}
		for _, o := range peers[:i] {
			if err := conflict(p, o); err != nil {
				problems = append(problems, pre+err.Error())
			}
		}
	}
	return problems
}

// CheckTransitGateway reports a TUNNEL_TRANSIT_GATEWAY or SOCKS_GATEWAY
// from the environment that names no internet exit site.
func (m *Manager) CheckTransitGateway() []string {
	var out []string
	for _, key := range []string{"TUNNEL_TRANSIT_GATEWAY", "SOCKS_GATEWAY"} {
		gw, src := m.Cfg.Resolve(key)
		if gw == "" || src != config.SourceEnv || m.Cfg.IsSelf(gw) || m.isExit(gw) {
			continue
		}
		out = append(out, key+": no site "+gw+" marked as internet exit (TUNNEL_PEER_"+gw+"_EXIT=true)")
	}
	return out
}

func (m *Manager) isExit(gw string) bool {
	for _, p := range m.Peers() {
		if (strings.EqualFold(p.Name, gw) || strings.EqualFold(p.Interface(), gw)) && p.Exit {
			return true
		}
	}
	return false
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range config.SplitList(s) {
		pfx, err := netip.ParsePrefix(item)
		if err != nil || !pfx.Addr().Is4() {
			return nil, fmt.Errorf("%q: need IPv4 CIDR notation", item)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

func isTrue(s string) bool {
	b, _ := strconv.ParseBool(s)
	return b
}

// Peers returns all peers: the environment's first, then the admin's.
func (m *Manager) Peers() []Peer {
	out, _ := envPeers() // problems stop the gateway at startup (CheckEnv)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	db, err := m.Store.TunnelPeers()
	if err != nil {
		slog.Error("tunnel peers", "err", err)
	}
	for _, d := range db {
		p := Peer{Name: d.Name, PublicKey: d.PublicKey, Endpoint: d.Endpoint, Transport: d.Transport, Exit: d.Exit, NAT: d.NAT,
			Disabled: d.Disabled, Keepalive: d.Keepalive, Source: "admin"}
		if len(d.PSK) > 0 {
			if b, err := m.Box.Open(d.PSK, "tunnel-psk:"+strings.ToLower(d.Name)); err == nil {
				p.PSK = string(b)
			}
		}
		p.Subnets, _ = parsePrefixes(strings.Join(d.Subnets, " "))
		p.Allow, _ = parsePrefixes(strings.Join(d.Allow, " "))
		p.Address, _ = netip.ParseAddr(d.Address)
		out = append(out, p)
	}
	m.assignAddresses(out)
	return out
}

// NodeAddress is this node's tunnel address: TUNNEL_ADDRESS, or by default
// 10.255.250.1 for a node that only connects out (sites assign it an
// address, or plain goproxy nodes expect this one) and 10.255.x.1 with x
// derived from the node key for a node that accepts sites. Sites see the
// latter as the source of its traffic, so it must not be their own default
// (the packets would carry a local source address and be dropped).
func (m *Manager) NodeAddress() (pfx netip.Prefix, auto bool) {
	if v := m.Cfg.Str("TUNNEL_ADDRESS"); v != "" {
		if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Is4() {
			return p, false
		}
	}
	if m.Cfg.Str("TUNNEL_LISTEN") == "" {
		return netip.MustParsePrefix("10.255.250.1/32"), true
	}
	h := sha256.Sum256([]byte(m.PublicKey()))
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 255, h[0], 1}), 32), true
}

// tunnelNetwork is where addresses for incoming sites come from: the /24
// of the node address.
func (m *Manager) tunnelNetwork() (netip.Addr, netip.Prefix) {
	own, _ := m.NodeAddress()
	nw, _ := own.Addr().Prefix(24)
	return own.Addr(), nw
}

// assignAddresses gives every incoming site without an explicit address a
// stable one from the tunnel network (kept in the database).
func (m *Manager) assignAddresses(peers []Peer) {
	m.addrMu.Lock()
	defer m.addrMu.Unlock()
	own, nw := m.tunnelNetwork()
	used := map[netip.Addr]bool{own: true}
	for _, p := range peers {
		if p.Address.IsValid() {
			used[p.Address] = true
		}
	}
	for i := range peers {
		p := &peers[i]
		if p.Address.IsValid() || !p.Incoming() {
			continue
		}
		key := "tunnel/addr/" + strings.ToLower(p.Name)
		if b, err := m.Store.GetKV(key); err == nil {
			if a, err := netip.ParseAddr(string(b)); err == nil && nw.Contains(a) && !used[a] {
				p.Address, p.AutoAddress = a, true
				used[a] = true
				continue
			}
		}
		for a := nw.Addr().Next(); nw.Contains(a); a = a.Next() {
			if !used[a] && a.As4()[3] != 255 {
				p.Address, p.AutoAddress = a, true
				used[a] = true
				_ = m.Store.PutKV(key, []byte(a.String()))
				break
			}
		}
	}
}

// Find returns the enabled peer with a name (case-insensitive).
// Find returns the enabled peer with this name or interface name
// (case-insensitive), as used in vpnGateway.
func (m *Manager) Find(name string) (*Peer, bool) {
	for _, p := range m.Peers() {
		if (strings.EqualFold(p.Name, name) || strings.EqualFold(p.Interface(), name)) && !p.Disabled {
			pp := p
			return &pp, true
		}
	}
	return nil, false
}

// Routes returns the subnets of enabled peers.
func (m *Manager) Routes() []Route {
	var out []Route
	for _, p := range m.Peers() {
		if p.Disabled {
			continue
		}
		for _, s := range p.Subnets {
			out = append(out, Route{Prefix: s, Peer: p.Name, Dev: p.Interface()})
		}
		if p.Address.IsValid() {
			// Replies to a site that reaches our networks.
			out = append(out, Route{Prefix: netip.PrefixFrom(p.Address, 32), Peer: p.Name, Dev: p.Interface()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.String() < out[j].Prefix.String() })
	return out
}

// Validate checks a peer (with the others) before it is saved.
func (m *Manager) Validate(p Peer, pools []netip.Prefix) error {
	own, _ := m.tunnelNetwork()
	if err := checkPeer(p, pools, own); err != nil {
		return err
	}
	for _, o := range m.Peers() {
		if strings.EqualFold(o.Name, p.Name) {
			if o.Source == "env" {
				return errors.New("a peer with this name comes from the environment")
			}
			continue
		}
		if err := conflict(p, o); err != nil {
			return err
		}
	}
	return nil
}

// checkPeer checks a peer's own settings; own is this node's tunnel
// address (zero: unknown, not checked).
func checkPeer(p Peer, pools []netip.Prefix, own netip.Addr) error {
	if !gpconfig.ValidPeerName(p.Name) {
		return errors.New("name: letters, digits, '-' and '_' only, at most 32 characters")
	}
	if _, err := keys.ParsePublicKey(p.PublicKey); err != nil {
		return errors.New("public key: not a valid key (44 base64 characters, from the site's Tunnels page)")
	}
	if p.Endpoint != "" {
		host, port, err := net.SplitHostPort(p.Endpoint)
		if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
			return fmt.Errorf("endpoint %q: use host:port, e.g. dc1.example.com:444", p.Endpoint)
		}
	}
	if p.Transport != "" && p.Transport != "udp" && p.Transport != "aead" && p.Transport != "tls" {
		return errors.New("transport must be udp, aead or tls")
	}
	if p.Address.IsValid() {
		if !p.Incoming() {
			return errors.New("tunnel address: leave it empty — a site we connect to assigns our address itself, nothing is needed on this side")
		}
		if p.Address == own {
			return errors.New("the tunnel address is this node's own address")
		}
	}
	for _, s := range p.Subnets {
		if s.Bits() == 0 {
			return errors.New("networks behind the site: 0.0.0.0/0 would send everything into this tunnel; mark the site as internet exit instead")
		}
		for _, pool := range pools {
			if s.Overlaps(pool) {
				return fmt.Errorf("subnet %s overlaps the VPN pool %s", s, pool)
			}
		}
	}
	return nil
}

// conflict reports a clash between two different peers.
func conflict(p, o Peer) error {
	if o.Interface() == p.Interface() {
		return fmt.Errorf("interface %s is already used by peer %s; choose a more distinct name", p.Interface(), o.Name)
	}
	if o.PublicKey == p.PublicKey {
		return fmt.Errorf("public key already used by peer %s", o.Name)
	}
	if p.Address.IsValid() && o.Address == p.Address && !o.AutoAddress {
		return fmt.Errorf("tunnel address %s is already used by peer %s", p.Address, o.Name)
	}
	if o.Disabled || p.Disabled {
		return nil
	}
	for _, a := range o.Subnets {
		for _, b := range p.Subnets {
			if a == b {
				return fmt.Errorf("subnet %s is already behind peer %s", a, o.Name)
			}
		}
	}
	return nil
}

// Save stores an admin peer and applies it.
func (m *Manager) Save(p Peer) error {
	tp := &store.TunnelPeer{Name: p.Name, PublicKey: p.PublicKey, Endpoint: p.Endpoint, Transport: p.Transport, Exit: p.Exit,
		NAT: p.NAT, Disabled: p.Disabled, Keepalive: p.Keepalive}
	if p.PSK != "" {
		tp.PSK = m.Box.Seal([]byte(p.PSK), "tunnel-psk:"+strings.ToLower(p.Name))
	}
	for _, s := range p.Subnets {
		tp.Subnets = append(tp.Subnets, s.String())
	}
	for _, a := range p.Allow {
		tp.Allow = append(tp.Allow, a.String())
	}
	if p.Address.IsValid() && !p.AutoAddress {
		tp.Address = p.Address.String()
	}
	if err := m.Store.SaveTunnelPeer(tp); err != nil {
		return err
	}
	m.Apply()
	return nil
}

// Delete removes an admin peer and applies the change.
func (m *Manager) Delete(name string) error {
	if err := m.Store.DeleteTunnelPeer(name); err != nil {
		return err
	}
	m.Apply()
	return nil
}

// privateKey returns the node key: TUNNEL_PRIVATE_KEY or a generated one
// kept encrypted in the database.
func (m *Manager) privateKey() (keys.PrivateKey, error) {
	if s := m.Cfg.Str("TUNNEL_PRIVATE_KEY"); s != "" {
		return keys.ParsePrivateKey(s)
	}
	const kv = "tunnel/private_key"
	if enc, err := m.Store.GetKV(kv); err == nil {
		raw, err := m.Box.Open(enc, kv)
		if err != nil {
			return keys.PrivateKey{}, err
		}
		return keys.ParsePrivateKey(string(raw))
	}
	k, err := keys.GeneratePrivateKey()
	if err != nil {
		return keys.PrivateKey{}, err
	}
	if err := m.Store.PutKV(kv, m.Box.Seal([]byte(k.String()), kv)); err != nil {
		return keys.PrivateKey{}, err
	}
	slog.Info("generated the tunnel node key", "public_key", k.Public().String())
	return k, nil
}

// siteName is how other sites call this node: NODE_NAME, or the first
// label of VPN_HOSTNAME (letters, digits, '-' and '_').
func (m *Manager) siteName() string { return m.Cfg.SiteName() }

// SiteName is how other sites should call this node.
func (m *Manager) SiteName() string { return m.siteName() }

// KeyConfigured reports whether the node key comes from TUNNEL_PRIVATE_KEY
// (then it cannot be regenerated here).
func (m *Manager) KeyConfigured() bool { return m.Cfg.Str("TUNNEL_PRIVATE_KEY") != "" }

// RegenerateKey replaces the generated node key and restarts the node.
// Every site has to be given the new public key.
func (m *Manager) RegenerateKey() (string, error) {
	if m.KeyConfigured() {
		return "", errors.New("the key is set with TUNNEL_PRIVATE_KEY; change it there")
	}
	k, err := keys.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	const kv = "tunnel/private_key"
	if err := m.Store.PutKV(kv, m.Box.Seal([]byte(k.String()), kv)); err != nil {
		return "", err
	}
	slog.Info("regenerated the tunnel node key", "public_key", k.Public().String())
	m.Restart()
	return k.Public().String(), nil
}

// PublicKey returns this node's public key.
func (m *Manager) PublicKey() string {
	k, err := m.privateKey()
	if err != nil {
		return ""
	}
	return k.Public().String()
}

func (m *Manager) nodeConfig() (*gpconfig.NodeConfig, error) {
	k, err := m.privateKey()
	if err != nil {
		return nil, fmt.Errorf("tunnel key: %w", err)
	}
	transport := m.Cfg.Str("TUNNEL_TRANSPORT")
	if transport != "udp" && transport != "aead" && transport != "tls" {
		return nil, fmt.Errorf("TUNNEL_TRANSPORT must be udp, aead or tls")
	}
	if v := m.Cfg.Str("TUNNEL_ADDRESS"); v != "" {
		if p, err := netip.ParsePrefix(v); err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("TUNNEL_ADDRESS must be an IPv4 CIDR")
		}
	}
	addr, _ := m.NodeAddress()
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, m.siteName())
	return &gpconfig.NodeConfig{
		PrivateKey:       k.String(),
		Name:             strings.ToUpper(name),
		DataDir:          m.Dir,
		InterfaceName:    m.Cfg.Str("TUNNEL_IFNAME"),
		Address:          addr.String(),
		MTU:              m.Cfg.Int("TUNNEL_MTU"),
		FwMark:           0x676f,
		PushRoutes:       "false", // vpngw routes clients itself
		LogConns:         m.Cfg.Bool("TUNNEL_LOG_CONNECTIONS"),
		Listen:           m.Cfg.Str("TUNNEL_LISTEN"),
		Transport:        transport,
		TLS:              gpconfig.TLSServerConfig{Host: "www.microsoft.com"},
		FallbackMode:     "off",
		FallbackStatus:   403,
		ObfsMaxPad:       255,
		ObfsCover:        true,
		DefaultPSK:       m.Cfg.Str("TUNNEL_PSK"),
		DefaultInsecure:  m.Cfg.Bool("TUNNEL_TLS_INSECURE"),
		DefaultKeepalive: 25,
	}, nil
}

// goproxyPeers converts peers for the node.
func goproxyPeers(peers []Peer, insecure bool) []gpconfig.Peer {
	var out []gpconfig.Peer
	for _, p := range peers {
		gp := gpconfig.Peer{
			Name: p.Name, PublicKey: p.PublicKey, Endpoint: p.Endpoint, NAT: p.NAT, Disabled: p.Disabled,
			Interface: p.Interface(), Transport: p.Transport, PSK: p.PSK, KeepaliveSec: p.Keepalive,
			TLS: gpconfig.TLSClientConfig{Insecure: insecure},
		}
		// Routes of a peer with its own interface are only the sources it may
		// use. Accept any: the other side may send from its subnets, the
		// internet (exit), its tunnel address or its clients' addresses, and
		// nftables decides per interface what a site may reach (site_allow).
		gp.Routes = []string{"0.0.0.0/0"}
		if p.Incoming() && p.Address.IsValid() {
			gp.IP = p.Address.String() // handed out in the handshake
		}
		out = append(out, gp)
	}
	return out
}

// Enabled reports whether a node is needed.
func (m *Manager) Enabled() bool {
	return len(m.Peers()) > 0 || m.Cfg.Str("TUNNEL_LISTEN") != ""
}

// EnsureAddresses gives every peer interface the node's tunnel address.
// goproxy creates them without one, and the kernel's reverse-path filter
// (loose included) drops traffic arriving on an interface without an IPv4
// address unless the route back points into that very interface — which is
// never true for replies from the internet through an exit site.
func (m *Manager) EnsureAddresses() {
	pfx, _ := m.NodeAddress()
	addr := pfx.Addr().String() + "/32"
	for _, p := range m.Peers() {
		if p.Disabled {
			continue
		}
		ifc, err := net.InterfaceByName(p.Interface())
		if err != nil {
			continue
		}
		if hasIPv4(ifc) {
			continue
		}
		if out, err := exec.Command("ip", "-4", "addr", "add", addr, "dev", ifc.Name).CombinedOutput(); err != nil {
			slog.Warn("tunnel interface address", "dev", ifc.Name, "err", strings.TrimSpace(string(out)))
		}
	}
}

func hasIPv4(ifc *net.Interface) bool {
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return true
		}
	}
	return false
}

func warnRPFilter() {
	b, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter")
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		slog.Warn("net.ipv4.conf.all.rp_filter is 1 (strict): replies from internet exits through tunnels are dropped; set it to 2 (loose) on the host")
	}
}

// Run keeps the node running until ctx ends: it starts when peers exist,
// restarts after failures and on Restart.
func (m *Manager) Run(ctx context.Context) {
	m.mu.Lock()
	m.kick = make(chan struct{}, 1)
	m.mu.Unlock()
	log.SetFlags(0)
	log.SetOutput(goproxyLog{})
	warnRPFilter()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.EnsureAddresses()
			}
		}
	}()
	backoff := time.Second
	for ctx.Err() == nil {
		if !m.Enabled() {
			select {
			case <-ctx.Done():
				return
			case <-m.kick:
				continue
			}
		}
		start := time.Now()
		err := m.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			m.setErr(err.Error())
			slog.Error("tunnel node stopped", "err", err, "retry", backoff.String())
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		case <-m.kick:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (m *Manager) setErr(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

func (m *Manager) runOnce(ctx context.Context) error {
	cfg, err := m.nodeConfig()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	// The peer set comes from vpngw; never start with a stale file.
	_ = os.Remove(filepath.Join(m.Dir, "peers.json"))
	n, err := node.New(cfg)
	if err != nil {
		return err
	}
	if err := n.SetFilePeers(goproxyPeers(m.Peers(), cfg.DefaultInsecure)); err != nil {
		return fmt.Errorf("peers: %w", err)
	}
	stop := make(chan struct{})
	n.OnStarted = func() {
		m.mu.Lock()
		m.lastErr = ""
		m.started = time.Now()
		m.mu.Unlock()
		slog.Info("tunnel node started", "public_key", n.Info().PublicKey, "peers", len(m.Peers()))
		if m.OnChange != nil {
			go m.OnChange()
		}
	}
	m.mu.Lock()
	m.node, m.stop = n, stop
	m.mu.Unlock()
	errc := make(chan error, 1)
	go func() { errc <- n.Run(stop) }()
	var runErr error
	select {
	case <-ctx.Done():
		close(stop)
		runErr = <-errc
	case runErr = <-errc:
	}
	m.mu.Lock()
	if m.node == n {
		m.node, m.stop = nil, nil
	}
	m.mu.Unlock()
	if m.OnChange != nil {
		go m.OnChange()
	}
	return runErr
}

// Restart stops the node; Run starts it again with fresh settings.
func (m *Manager) Restart() {
	m.mu.Lock()
	stop := m.stop
	m.stop = nil
	kick := m.kick
	m.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if kick != nil {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
}

// Apply pushes the current peer set to the running node without dropping
// the sessions of unchanged peers.
func (m *Manager) Apply() {
	m.mu.Lock()
	n := m.node
	m.mu.Unlock()
	if n == nil {
		m.Restart() // starts the node if it was idle
		return
	}
	if !m.Enabled() {
		m.Restart()
		return
	}
	if err := n.SetFilePeers(goproxyPeers(m.Peers(), m.Cfg.Bool("TUNNEL_TLS_INSECURE"))); err != nil {
		slog.Error("apply tunnel peers", "err", err)
		m.setErr(err.Error())
	}
	if m.OnChange != nil {
		go m.OnChange()
	}
}

// PeerStatus is a peer with its live state.
type PeerStatus struct {
	Peer
	InterfaceUp bool
	Connected   bool
	Links       []node.LinkInfo
	RxBytes     uint64
	TxBytes     uint64
	// From is the public address a connected incoming site uses.
	From string
}

// Status describes the node.
type Status struct {
	Running   bool
	Error     string
	Since     time.Time
	PublicKey string
	Info      node.Info
	Peers     []PeerStatus
}

// Status returns the node and peer state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	n := m.node
	st := Status{Running: n != nil, Error: m.lastErr, Since: m.started}
	m.mu.Unlock()
	st.PublicKey = m.PublicKey()
	live := map[string]node.PeerInfo{}
	if n != nil {
		st.Info = n.Info()
		for _, pi := range n.Peers() {
			live[pi.Name] = pi
		}
	}
	for _, p := range m.Peers() {
		ps := PeerStatus{Peer: p}
		if pi, ok := live[p.Name]; ok {
			ps.InterfaceUp = pi.InterfaceUp
			ps.Links = pi.Links
			ps.Connected = len(pi.Links) > 0
			for _, l := range pi.Links {
				ps.RxBytes += l.RxBytes
				ps.TxBytes += l.TxBytes
				if l.Direction == "in" {
					ps.From = l.Remote
					if h, _, err := net.SplitHostPort(l.Remote); err == nil {
						ps.From = h
					}
				}
			}
		}
		st.Peers = append(st.Peers, ps)
	}
	return st
}

// RemoteConfig returns the goproxy environment for the remote site's node.
func (m *Manager) RemoteConfig(p Peer, publicEndpoint string) string {
	var b strings.Builder
	st := m.Status()
	host := m.Cfg.Str("VPN_HOSTNAME")
	name := strings.ToUpper(strings.ReplaceAll(m.siteName(), "-", "_"))
	pre := "TUNNEL_PEER_" + name + "_"
	// YAML for the environment: section of the other site's docker-compose.
	line := func(key, value, comment string) {
		fmt.Fprintf(&b, "%s: %s", key, value)
		if comment != "" {
			b.WriteString("   # " + comment)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "# environment of site %s (vpngw) to link it with this gateway (%s)\n", p.Name, host)
	line(pre+"PUBLIC_KEY", st.PublicKey, "")
	if p.Incoming() {
		if publicEndpoint != "" {
			line(pre+"ENDPOINT", publicEndpoint, "")
		} else {
			line(pre+"ENDPOINT", `"<this gateway:port>"`, "set TUNNEL_LISTEN here first")
		}
	} else {
		b.WriteString("# this gateway connects to the site: the site needs TUNNEL_LISTEN\n")
	}
	var reach []string // what the site may reach here = networks behind us for it
	exit := false
	for _, a := range p.Allow {
		if a.Bits() == 0 {
			exit = true
		} else {
			reach = append(reach, a.String())
		}
	}
	if len(reach) > 0 {
		line(pre+"SUBNETS", strings.Join(reach, " "), "")
	}
	if exit {
		line(pre+"EXIT", "true", "may use this gateway's internet")
	}
	var allow []string // what we may reach there = networks behind the site
	for _, s := range p.Subnets {
		allow = append(allow, s.String())
	}
	if p.Exit {
		allow = append(allow, "0.0.0.0/0")
	}
	if len(allow) > 0 {
		line(pre+"ALLOW", strings.Join(allow, " "), "")
	}
	if p.Transport != "" {
		line(pre+"TRANSPORT", p.Transport, "")
	}
	line("TUNNEL_PSK", `"<the shared PSK>"`, "")
	line("TUNNEL_MTU", strconv.Itoa(m.Cfg.Int("TUNNEL_MTU")), "the same on both sides")
	if len(reach) > 0 {
		b.WriteString("# hosts of the site use it as gateway: TUNNEL_TRANSIT_SOURCES: <their networks>\n")
	}
	return b.String()
}

type goproxyLog struct{}

func (goproxyLog) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		slog.Info(msg, "proc", "tunnels")
	}
	return len(p), nil
}
