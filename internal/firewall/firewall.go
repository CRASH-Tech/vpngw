// Package firewall enforces route profiles with nftables and steers
// traffic of profiles with a vpnGateway through policy routing.
//
// Everything lives in the table "inet vpngw"; other host rules are not
// touched (except optional ACCEPT rules in Docker's DOCKER-USER chain, which
// otherwise drops forwarded traffic). Every change is one nft transaction.
package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	table    = "vpngw"
	markBase = 0x76670000 // "vg"
)

// Options configure the firewall.
type Options struct {
	Pools          []netip.Prefix
	EgressIface    string // empty: interface of the default route
	ClientToClient bool
	DockerCompat   bool
	DryRun         bool // print scripts instead of running nft/ip (tests)
	// Resolve maps a vpnGateway value to a next hop (tunnel peer names);
	// nil: the value is an interface name or an IPv4 next hop.
	Resolve func(gw string) Target
	// PeerRoutes returns the subnets behind tunnel peers, routed for every
	// VPN client.
	PeerRoutes func() []PeerRoute
	// TransitSources returns source networks whose forwarded traffic to
	// peer subnets is routed into the tunnels.
	TransitSources func() []netip.Prefix
	// LocalNetworks returns this site's own networks: traffic to them uses
	// the host's routes even when a gateway is set for the rest.
	LocalNetworks func() []netip.Prefix
	// TransitGateway returns the gateway (like vpnGateway: a site name, an
	// interface or a next hop) for TransitSources traffic that is not for a
	// peer subnet; empty: the host's default route.
	TransitGateway func() string
	// Allowances returns what each tunnel interface may reach through this
	// node (masqueraded); other new connections from tunnels are dropped.
	Allowances func() []Allowance
	// DomainPool holds the addresses the domain proxy's DNS gives out;
	// connections to them are translated to the real addresses (MapDomain).
	// DNSServer (in the pool) port 53 goes to the local DNSPort.
	DomainPool netip.Prefix
	DNSServer  netip.Addr
	DNSPort    int
	// TransitDomainsGateway is the exit (like TransitGateway) for
	// TransitSources' connections to domain pool addresses; nil or "": the
	// host's routes.
	TransitDomainsGateway func() string
}

// Allowance lets traffic arriving on a tunnel interface reach a network.
type Allowance struct {
	Dev    string
	Prefix netip.Prefix
}

type profileState struct {
	allow   []netip.Prefix
	gateway string
}

// Manager owns the vpngw table.
type Manager struct {
	mu         sync.Mutex
	opt        Options
	egress     string
	profiles   map[string]*profileState
	sessions   map[netip.Addr]string              // client IP → profile id
	gateways   map[string]int                     // gateway → index
	replies    map[string]int                     // tunnel interface → reply table index
	transitSig string                             // transit sources applied to DOCKER-USER
	domainNAT  map[netip.Addr]netip.Addr          // domain pool address → real address
	grants     map[netip.Addr]map[netip.Addr]bool // client → pool addresses it was given
	run        func(ctx context.Context, name string, stdin string, args ...string) (string, error)
	Log        []string // executed scripts in DryRun mode
}

// New creates a manager; call Init before use.
func New(opt Options) *Manager {
	m := &Manager{opt: opt, profiles: map[string]*profileState{}, sessions: map[netip.Addr]string{}, gateways: map[string]int{}, replies: map[string]int{}}
	m.run = m.exec
	return m
}

func (m *Manager) exec(ctx context.Context, name, stdin string, args ...string) (string, error) {
	if m.opt.DryRun {
		m.Log = append(m.Log, name+" "+strings.Join(args, " ")+"\n"+stdin)
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func (m *Manager) nft(script string) error {
	_, err := m.run(context.Background(), "nft", script, "-f", "-")
	if err != nil {
		slog.Error("nft transaction failed", "err", err, "script", script)
	}
	return err
}

// EgressIface returns the interface used for NAT.
func (m *Manager) EgressIface() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.egress
}

// DefaultRouteIface returns the interface of the IPv4 default route.
func DefaultRouteIface() string {
	out, err := exec.Command("ip", "-j", "-4", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	var routes []struct {
		Dev string `json:"dev"`
	}
	if json.Unmarshal(out, &routes) != nil || len(routes) == 0 {
		return ""
	}
	return routes[0].Dev
}

func setElems(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

func chainName(id string) string { return "p_" + strings.TrimPrefix(id, "rp-") }
func allowSet(id string) string  { return "a_" + strings.TrimPrefix(id, "rp-") }

// Init (re)creates the table atomically and enables forwarding.
func (m *Manager) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.opt.DryRun {
		if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(b)) != "1" {
			if _, err := m.run(context.Background(), "sysctl", "", "-q", "-w", "net.ipv4.ip_forward=1"); err != nil {
				slog.Error("IPv4 forwarding is disabled and cannot be enabled from the container; set net.ipv4.ip_forward=1 on the host", "err", err)
			}
		}
	}
	m.egress = m.opt.EgressIface
	if m.egress == "" && !m.opt.DryRun {
		m.egress = DefaultRouteIface()
	}
	m.profiles = map[string]*profileState{}
	m.sessions = map[netip.Addr]string{}
	m.domainNAT = map[netip.Addr]netip.Addr{}
	m.grants = map[netip.Addr]map[netip.Addr]bool{}
	m.transitSig = "-"
	if err := m.nft(m.baseScript()); err != nil {
		return err
	}
	m.cleanupRules()
	m.syncPeerRoutes()
	if m.opt.DockerCompat {
		m.dockerCompat()
	}
	return nil
}

func (m *Manager) natIfaces() []string {
	set := map[string]bool{}
	if m.egress != "" {
		set[m.egress] = true
	}
	for g := range m.gateways {
		// Tunnel peers translate clients themselves; next hops by IP leave
		// through an interface that is NATed anyway or routes the pools.
		if t := m.resolve(g); !t.Tunnel && t.Dev != "" {
			set[t.Dev] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, fmt.Sprintf("%q", k))
	}
	sort.Strings(out)
	return out
}

func (m *Manager) postroutingRule() string {
	ifs := m.natIfaces()
	if len(ifs) == 0 {
		return "ip saddr @pools ip daddr != @pools counter masquerade"
	}
	return fmt.Sprintf("ip saddr @pools ip daddr != @pools oifname { %s } counter masquerade", strings.Join(ifs, ", "))
}

// forwardRules filter forwarded traffic: VPN clients see only their
// profile, and new connections arriving from a tunnel may only reach what
// that site is allowed.
func (m *Manager) forwardRules() []string {
	c2c := "ip saddr @pools ip daddr @pools counter name c2c_dropped drop"
	if m.opt.ClientToClient {
		c2c = "ip saddr @pools ip daddr @pools accept"
	}
	return []string{
		`iifname "gp-*" ct state new iifname . ip daddr != @site_allow counter name tunnel_in_dropped drop`,
		// Domain pool addresses without a translation (unknown or expired).
		"ip daddr @domain_pool counter name domain_unmapped drop",
		c2c,
		"ip daddr @pools ct state established,related accept",
		"ip daddr @pools counter name inbound_dropped drop",
		// Domain proxy: only pool addresses the client was given (MapDomain,
		// GrantDomain), translated to their real address.
		"ip saddr @pools ct status dnat ip saddr . ct original ip daddr @domain_grant counter accept",
		"ip saddr @pools ip saddr vmap @sess",
		"ip saddr @pools counter name dropped drop",
	}
}

// steerRules mark packets for policy routing (rules 150xx).
func (m *Manager) steerRules() []string {
	mark := fmt.Sprintf("0x%x", markBase)
	return []string{
		"ip saddr @pools meta mark set ip saddr map @sessmark",
		"ip saddr @transit_src ip daddr @tunnel_dst meta mark set " + mark,
		// Their other traffic: the transit gateway (TUNNEL_TRANSIT_GATEWAY);
		// rule 15001 still keeps the host's specific routes (LANs).
		"ip saddr @transit_src ip daddr != @tunnel_dst meta mark set ip saddr map @transit_gw",
		// Their domain proxy connections: TransitDomainsGateway.
		"ip saddr @transit_src ip daddr @domain_pool meta mark set ip saddr map @transit_dom_gw",
		// This site's own networks always use the host's routes, also when
		// the internet goes through another site (vpnGateway).
		fmt.Sprintf("meta mark and 0x%x == 0x%x ip daddr @local_nets meta mark set %s", markMask, markBase, mark),
		// Connections a site opens through us: replies go back into its
		// tunnel (rules 15500+i), whatever its source address.
		`iifname "gp-*" ct state new ct mark set iifname map @tunmark`,
		fmt.Sprintf("ct direction reply ct mark and 0x%x == 0x%x meta mark set ct mark", markMask, replyMark),
	}
}

// dnatRules send the domain proxy's DNS server to the local resolver and
// translate domain pool addresses to the real ones.
func (m *Manager) dnatRules() []string {
	if !m.opt.DomainPool.IsValid() || m.opt.DNSPort == 0 {
		return nil
	}
	var out []string
	for _, src := range []string{"@pools", "@transit_src"} {
		out = append(out,
			fmt.Sprintf("ip saddr %s ip daddr %s meta l4proto { tcp, udp } th dport 53 redirect to :%d", src, m.opt.DNSServer, m.opt.DNSPort),
			fmt.Sprintf("ip saddr %s ip daddr @domain_pool dnat ip to ip daddr map @domain_nat", src))
	}
	return out
}

// inputRules filter what reaches this host itself. VPN clients reach its
// addresses only as their profile allows (plus ping, DNS and the domain
// proxy's resolver): a route a client adds by hand to one of the host's
// addresses must not open the host's services. Sites through the tunnels
// likewise reach only what they are allowed (site_allow), and ping.
func (m *Manager) inputRules() []string {
	var out []string
	if m.opt.DNSPort != 0 {
		out = append(out,
			fmt.Sprintf("meta l4proto { tcp, udp } th dport %d ct status dnat ip saddr @pools accept", m.opt.DNSPort),
			fmt.Sprintf("meta l4proto { tcp, udp } th dport %d ct status dnat ip saddr @transit_src accept", m.opt.DNSPort),
			fmt.Sprintf("meta l4proto { tcp, udp } th dport %d drop", m.opt.DNSPort))
	}
	return append(out,
		"ip saddr @pools ct state established,related accept",
		"ip saddr @pools icmp type echo-request accept",
		"ip saddr @pools meta l4proto { tcp, udp } th dport 53 accept",
		"ip saddr @pools ip saddr vmap @sess",
		"ip saddr @pools counter name local_dropped drop",
		`iifname "gp-*" ct state new meta l4proto != icmp iifname . ip daddr != @site_allow counter name tunnel_in_dropped drop`,
	)
}

func (m *Manager) postroutingRules() []string {
	return []string{
		m.postroutingRule(),
		`iifname "gp-*" oifname != "gp-*" iifname . ip daddr @site_allow counter masquerade`,
	}
}

func chainBody(rules []string) string {
	return "\t\t" + strings.Join(rules, "\n\t\t")
}

func (m *Manager) baseScript() string {
	return fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	counter dropped { }
	counter c2c_dropped { }
	counter inbound_dropped { }
	counter tunnel_in_dropped { }
	counter domain_unmapped { }
	counter local_dropped { }
	set pools { type ipv4_addr; flags interval; elements = { %[2]s } }
	set domain_pool { type ipv4_addr; flags interval;%[6]s }
	map domain_nat { type ipv4_addr : ipv4_addr; }
	set domain_grant { type ipv4_addr . ipv4_addr; }
	map sess { type ipv4_addr : verdict; }
	map sessmark { type ipv4_addr : mark; }
	set transit_src { type ipv4_addr; flags interval; auto-merge; }
	set tunnel_dst { type ipv4_addr; flags interval; auto-merge; }
	set site_allow { type ifname . ipv4_addr; flags interval; }
	map tunmark { type ifname : mark; }
	map transit_gw { type ipv4_addr : mark; flags interval; }
	map transit_dom_gw { type ipv4_addr : mark; flags interval; }
	set local_nets { type ipv4_addr; flags interval; auto-merge; }
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
%[3]s
	}
	chain steer {
		type filter hook prerouting priority mangle; policy accept;
%[4]s
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
%[5]s
	}
	chain domain_dnat {
		type nat hook prerouting priority dstnat; policy accept;
%[7]s
	}
	chain local_in {
		type filter hook input priority filter - 10; policy accept;
%[8]s
	}
}
`, table, setElems(m.opt.Pools), chainBody(m.forwardRules()), chainBody(m.steerRules()), chainBody(m.postroutingRules()),
		domainPoolElems(m.opt.DomainPool), chainBody(m.dnatRules()), chainBody(m.inputRules()))
}

func domainPoolElems(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return " elements = { " + p.String() + " };"
}

// Reconfigure updates NAT and client-to-client settings without touching sessions.
func (m *Manager) Reconfigure(egress string, c2c bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opt.EgressIface, m.opt.ClientToClient = egress, c2c
	m.egress = egress
	if m.egress == "" && !m.opt.DryRun {
		m.egress = DefaultRouteIface()
	}
	return m.nft(m.chainScript("forward", m.forwardRules()) + m.postroutingScript())
}

func (m *Manager) chainScript(chain string, rules []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s %s\n", table, chain)
	for _, r := range rules {
		fmt.Fprintf(&b, "add rule inet %s %s %s\n", table, chain, r)
	}
	return b.String()
}

func (m *Manager) postroutingScript() string {
	return m.chainScript("postrouting", m.postroutingRules())
}

// Session describes one client address in the firewall.
type Session struct {
	IP      netip.Addr
	Profile string
	Allow   []netip.Prefix
	Gateway string
}

// AddSession allows traffic from ip according to its profile.
func (m *Manager) AddSession(s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	m.ensureProfile(&b, s.Profile, s.Allow, s.Gateway)
	if _, ok := m.sessions[s.IP]; ok {
		fmt.Fprintf(&b, "delete element inet %s sess { %s }\n", table, s.IP)
		fmt.Fprintf(&b, "delete element inet %s sessmark { %s }\n", table, s.IP)
	}
	fmt.Fprintf(&b, "add element inet %s sess { %s : jump %s }\n", table, s.IP, chainName(s.Profile))
	if mark, ok := m.gatewayMark(s.Gateway); ok {
		fmt.Fprintf(&b, "add element inet %s sessmark { %s : 0x%x }\n", table, s.IP, mark)
	}
	if err := m.nft(b.String()); err != nil {
		return err
	}
	m.sessions[s.IP] = s.Profile
	return nil
}

// MapDomain makes connections to a domain pool address go to real.
func (m *Manager) MapDomain(fake, real netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.domainNAT[fake]
	if ok && old == real {
		return nil
	}
	var b strings.Builder
	if ok {
		fmt.Fprintf(&b, "delete element inet %s domain_nat { %s }\n", table, fake)
	}
	fmt.Fprintf(&b, "add element inet %s domain_nat { %s : %s }\n", table, fake, real)
	if err := m.nft(b.String()); err != nil {
		return err
	}
	m.domainNAT[fake] = real
	return nil
}

// UnmapDomain removes translations of domain pool addresses and the
// clients' grants for them (an address may later serve another name).
func (m *Manager) UnmapDomain(fakes []netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	gone := map[netip.Addr]bool{}
	for _, f := range fakes {
		gone[f] = true
		if _, ok := m.domainNAT[f]; ok {
			fmt.Fprintf(&b, "delete element inet %s domain_nat { %s }\n", table, f)
		}
	}
	for c, fs := range m.grants {
		for f := range fs {
			if gone[f] {
				fmt.Fprintf(&b, "delete element inet %s domain_grant { %s . %s }\n", table, c, f)
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	if err := m.nft(b.String()); err != nil {
		return err
	}
	for _, f := range fakes {
		delete(m.domainNAT, f)
	}
	for c, fs := range m.grants {
		for f := range fs {
			if gone[f] {
				delete(fs, f)
			}
		}
		if len(fs) == 0 {
			delete(m.grants, c)
		}
	}
	return nil
}

// GrantDomain lets a VPN client use a domain pool address it was given.
func (m *Manager) GrantDomain(client, fake netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.grants[client][fake] {
		return nil
	}
	if err := m.nft(fmt.Sprintf("add element inet %s domain_grant { %s . %s }\n", table, client, fake)); err != nil {
		return err
	}
	if m.grants[client] == nil {
		m.grants[client] = map[netip.Addr]bool{}
	}
	m.grants[client][fake] = true
	return nil
}

// GatewayMark is the routing mark of a vpnGateway for the gateway's own
// connections (SO_MARK); 0: the host's routes.
func (m *Manager) GatewayMark(gw string) uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if gw == "" {
		return 0
	}
	idx, ok := m.gateways[gw]
	if !ok {
		return 0
	}
	return markBase + uint32(idx)
}

// Deleting a missing element fails the whole transaction, so every session
// gets a sessmark element; markBase has no routing rule (main table).
func (m *Manager) gatewayMark(gw string) (uint32, bool) {
	if gw == "" {
		return markBase, true // mark without routing rule: main table
	}
	idx, ok := m.gateways[gw]
	if !ok {
		return markBase, true
	}
	return markBase + uint32(idx), true
}

// RemoveSession revokes access of ip.
func (m *Manager) RemoveSession(ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[ip]; !ok {
		return nil
	}
	script := fmt.Sprintf("delete element inet %[1]s sess { %[2]s }\ndelete element inet %[1]s sessmark { %[2]s }\n", table, ip)
	for f := range m.grants[ip] {
		script += fmt.Sprintf("delete element inet %s domain_grant { %s . %s }\n", table, ip, f)
	}
	if err := m.nft(script); err != nil {
		return err
	}
	delete(m.sessions, ip)
	delete(m.grants, ip)
	m.gcProfiles()
	return nil
}

// HasSession reports whether ip is allowed.
func (m *Manager) HasSession(ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.sessions[ip]
	return ok
}

func (m *Manager) ensureProfile(b *strings.Builder, id string, allow []netip.Prefix, gw string) {
	if gw != "" {
		m.ensureGateway(gw)
	}
	st, ok := m.profiles[id]
	if ok && equalPrefixes(st.allow, allow) && st.gateway == gw {
		return
	}
	set, chain := allowSet(id), chainName(id)
	if !ok {
		fmt.Fprintf(b, "add set inet %s %s { type ipv4_addr; flags interval; }\n", table, set)
		fmt.Fprintf(b, "add chain inet %s %s\n", table, chain)
		fmt.Fprintf(b, "add rule inet %s %s ip daddr @%s counter accept\n", table, chain, set)
	} else {
		fmt.Fprintf(b, "flush set inet %s %s\n", table, set)
	}
	if len(allow) > 0 {
		fmt.Fprintf(b, "add element inet %s %s { %s }\n", table, set, setElems(allow))
	}
	m.profiles[id] = &profileState{allow: append([]netip.Prefix{}, allow...), gateway: gw}
}

// UpdateProfile changes the allowed networks of a profile in place.
func (m *Manager) UpdateProfile(id string, allow []netip.Prefix, gw string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[id]; !ok {
		return nil
	}
	var b strings.Builder
	m.ensureProfile(&b, id, allow, gw)
	if b.Len() == 0 {
		return nil
	}
	return m.nft(b.String())
}

func (m *Manager) gcProfiles() {
	used := map[string]bool{}
	for _, p := range m.sessions {
		used[p] = true
	}
	var b strings.Builder
	for id := range m.profiles {
		if !used[id] {
			fmt.Fprintf(&b, "delete chain inet %s %s\n", table, chainName(id))
			fmt.Fprintf(&b, "delete set inet %s %s\n", table, allowSet(id))
			delete(m.profiles, id)
		}
	}
	if b.Len() > 0 {
		_ = m.nft(b.String())
	}
}

func equalPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dockerCompat inserts ACCEPT rules for VPN pools into DOCKER-USER, which
// Docker evaluates before its FORWARD chain with policy DROP.
func (m *Manager) dockerCompat() {
	ctx := context.Background()
	if _, err := m.run(ctx, "iptables", "", "-w", "-n", "-L", "DOCKER-USER"); err != nil {
		return
	}
	for _, p := range m.opt.Pools {
		for _, dir := range []string{"-s", "-d"} {
			rule := []string{dir, p.String(), "-m", "comment", "--comment", "vpngw", "-j", "ACCEPT"}
			if _, err := m.run(ctx, "iptables", "", append([]string{"-w", "-C", "DOCKER-USER"}, rule...)...); err == nil {
				continue
			}
			if _, err := m.run(ctx, "iptables", "", append([]string{"-w", "-I", "DOCKER-USER", "1"}, rule...)...); err != nil {
				slog.Warn("cannot add DOCKER-USER rule", "err", err)
			} else {
				slog.Info("added DOCKER-USER accept rule for VPN pool", "pool", p.String(), "dir", dir)
			}
		}
	}
}

// Counters returns named counter values (packets, bytes).
func (m *Manager) Counters() map[string][2]uint64 {
	out := map[string][2]uint64{}
	s, err := m.run(context.Background(), "nft", "", "-j", "list", "counters", "table", "inet", table)
	if err != nil {
		return out
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(s), &doc) != nil {
		return out
	}
	for _, item := range doc.Nftables {
		raw, ok := item["counter"]
		if !ok {
			continue
		}
		var c struct {
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		if json.Unmarshal(raw, &c) == nil {
			out[c.Name] = [2]uint64{c.Packets, c.Bytes}
		}
	}
	return out
}

// Ruleset returns the current table as text (admin panel).
func (m *Manager) Ruleset() string {
	s, err := m.run(context.Background(), "nft", "", "list", "table", "inet", table)
	if err != nil {
		return err.Error()
	}
	return s
}

// Shutdown removes the table and routing rules.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.nft(fmt.Sprintf("add table inet %[1]s\ndelete table inet %[1]s\n", table))
	m.cleanupRules()
	if m.opt.DockerCompat && !m.opt.DryRun {
		m.dockerTransit(nil, nil)
	}
}
