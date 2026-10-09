package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Policy routing of VPN client traffic. Every session carries a mark
// (markBase | gateway index) set in the steer chain; the rules below only
// match marked packets, so the host's own traffic is never affected:
//
//	15000  fwmark markBase/mask  lookup 15100                    subnets behind tunnel peers (all clients)
//	15001  fwmark markBase/mask  lookup main suppress_prefixlength 0   the host's specific routes
//	15010+i fwmark markBase+i    lookup 15100+i                  default route of vpnGateway i
//	(no match)                   main                            the host's default gateway
//
// Connections that sites open through this node carry a conntrack mark per
// tunnel interface (replyMark | i, map tunmark); their replies go back into
// the tunnel they came from, whatever the source address was:
//
//	15500+i fwmark replyMark+i   lookup 15500+i                  default dev gp-<site>
const (
	markMask       = 0xffff0000
	rulePeers      = 15000
	ruleMain       = 15001
	ruleGwBase     = 15010
	ruleReplyBase  = 15500
	ruleLast       = 15999
	tablePeers     = 15100
	tableReplyBase = 15500
	replyMark      = 0x76680000
)

// Target is where a vpnGateway sends traffic.
type Target struct {
	Dev    string     // output interface
	Via    netip.Addr // next hop; zero = on-link (point-to-point)
	Tunnel bool       // a tunnel peer: it translates the clients itself
}

// PeerRoute is a subnet behind a tunnel peer.
type PeerRoute struct {
	Prefix netip.Prefix
	Dev    string
}

func (m *Manager) resolve(gw string) Target {
	if m.opt.Resolve != nil {
		if t := m.opt.Resolve(gw); t.Dev != "" || t.Via.IsValid() {
			return t
		}
	}
	if a, err := netip.ParseAddr(gw); err == nil {
		return Target{Via: a}
	}
	return Target{Dev: gw}
}

func (m *Manager) ip(args ...string) (string, error) {
	return m.run(context.Background(), "ip", "", append([]string{"-4"}, args...)...)
}

func ifaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func (m *Manager) ensureRule(prio int, args ...string) error {
	p := fmt.Sprint(prio)
	_, _ = m.ip("rule", "del", "priority", p)
	_, err := m.ip(append([]string{"rule", "add", "priority", p}, args...)...)
	return err
}

// syncPeerRoutes installs the shared table of peer subnets. A subnet whose
// interface is missing becomes unreachable instead of leaking via the
// default gateway. Called with m.mu held.
func (m *Manager) syncPeerRoutes() {
	mark := fmt.Sprintf("0x%x/0x%x", markBase, markMask)
	if err := m.ensureRule(rulePeers, "fwmark", mark, "lookup", fmt.Sprint(tablePeers)); err != nil {
		slog.Error("routing rule", "err", err)
	}
	if err := m.ensureRule(ruleMain, "fwmark", mark, "lookup", "main", "suppress_prefixlength", "0"); err != nil {
		slog.Error("routing rule", "err", err)
	}
	want := map[string]string{}
	if m.opt.PeerRoutes != nil {
		for _, r := range m.opt.PeerRoutes() {
			want[r.Prefix.Masked().String()] = r.Dev
		}
	}
	m.syncTransit(want)
	tbl := fmt.Sprint(tablePeers)
	prefixes := make([]string, 0, len(want))
	for p := range want {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		dev := want[p]
		var err error
		if m.opt.DryRun || ifaceExists(dev) {
			_, err = m.ip("route", "replace", p, "dev", dev, "table", tbl)
		} else {
			_, err = m.ip("route", "replace", "unreachable", p, "table", tbl)
		}
		if err != nil {
			slog.Warn("peer route", "prefix", p, "dev", dev, "err", err)
		}
	}
	if m.opt.DryRun {
		return
	}
	out, err := m.ip("-j", "route", "show", "table", tbl)
	if err != nil {
		return
	}
	var cur []struct {
		Dst  string `json:"dst"`
		Type string `json:"type"`
	}
	_ = json.Unmarshal([]byte(out), &cur)
	for _, r := range cur {
		dst := r.Dst
		if !strings.Contains(dst, "/") {
			dst += "/32"
		}
		if _, ok := want[dst]; ok {
			continue
		}
		args := []string{"route", "del"}
		if r.Type == "unreachable" {
			args = append(args, "unreachable")
		}
		_, _ = m.ip(append(args, r.Dst, "table", tbl)...)
	}
}

// syncTransit marks forwarded traffic from TUNNEL_TRANSIT_SOURCES to peer
// subnets (sets transit_src and tunnel_dst, one nft transaction) and lets
// it through Docker's FORWARD chain. Called with m.mu held.
func (m *Manager) syncTransit(peerSubnets map[string]string) {
	var srcs []netip.Prefix
	var allows []Allowance
	if m.opt.TransitSources != nil {
		srcs = m.opt.TransitSources()
	}
	if m.opt.Allowances != nil {
		allows = m.opt.Allowances()
	}
	dst := make([]string, 0, len(peerSubnets))
	for p := range peerSubnets {
		dst = append(dst, p)
	}
	sort.Strings(dst)
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s transit_src\nflush set inet %s tunnel_dst\nflush set inet %s site_allow\nflush map inet %s tunmark\nflush map inet %s transit_gw\nflush map inet %s transit_dom_gw\nflush set inet %s local_nets\n",
		table, table, table, table, table, table, table)
	if local := m.localNets(); len(local) > 0 {
		fmt.Fprintf(&b, "add element inet %s local_nets { %s }\n", table, setElems(local))
	}
	gw := ""
	if m.opt.TransitGateway != nil {
		gw = m.opt.TransitGateway()
	}
	if gw != "" && len(srcs) > 0 {
		m.ensureGateway(gw)
		mark := markBase + uint32(m.gateways[gw])
		el := make([]string, 0, len(srcs))
		for _, p := range srcs {
			el = append(el, fmt.Sprintf("%s : 0x%x", p.Masked(), mark))
		}
		fmt.Fprintf(&b, "add element inet %s transit_gw { %s }\n", table, strings.Join(el, ", "))
	}
	if len(srcs) > 0 {
		// Domain proxy exit; markBase alone means the host's routes.
		mark := uint32(markBase)
		if m.opt.TransitDomainsGateway != nil {
			if dgw := m.opt.TransitDomainsGateway(); dgw != "" {
				m.ensureGateway(dgw)
				mark = markBase + uint32(m.gateways[dgw])
			}
		}
		el := make([]string, 0, len(srcs))
		for _, p := range srcs {
			el = append(el, fmt.Sprintf("%s : 0x%x", p.Masked(), mark))
		}
		fmt.Fprintf(&b, "add element inet %s transit_dom_gw { %s }\n", table, strings.Join(el, ", "))
	}
	if len(allows) > 0 {
		fmt.Fprintf(&b, "add element inet %s site_allow { %s }\n", table, allowElems(allows))
		fmt.Fprintf(&b, "add element inet %s tunmark { %s }\n", table, m.syncReplies(allows))
	} else {
		m.syncReplies(nil)
	}
	if len(srcs) > 0 {
		fmt.Fprintf(&b, "add element inet %s transit_src { %s }\n", table, setElems(srcs))
	}
	if len(dst) > 0 {
		fmt.Fprintf(&b, "add element inet %s tunnel_dst { %s }\n", table, strings.Join(dst, ", "))
	}
	_ = m.nft(b.String())

	sig := setElems(srcs) + "|" + allowElems(allows)
	if !m.opt.DockerCompat || sig == m.transitSig {
		return
	}
	m.transitSig = sig
	m.dockerTransit(srcs, allows)
}

// syncReplies keeps a routing table per tunnel interface that sites may
// reach through: replies to their connections go back into it. It returns
// the tunmark elements. Called with m.mu held.
func (m *Manager) syncReplies(allows []Allowance) string {
	want := map[string]bool{}
	for _, a := range allows {
		want[a.Dev] = true
	}
	for dev, idx := range m.replies {
		if !want[dev] {
			_, _ = m.ip("rule", "del", "priority", fmt.Sprint(ruleReplyBase+idx))
			_, _ = m.ip("route", "flush", "table", fmt.Sprint(tableReplyBase+idx))
			delete(m.replies, dev)
		}
	}
	devs := make([]string, 0, len(want))
	for dev := range want {
		devs = append(devs, dev)
	}
	sort.Strings(devs)
	var el []string
	for _, dev := range devs {
		idx, ok := m.replies[dev]
		if !ok {
			used := map[int]bool{}
			for _, i := range m.replies {
				used[i] = true
			}
			for idx = 1; used[idx]; idx++ {
			}
			m.replies[dev] = idx
		}
		mark := replyMark + uint32(idx)
		tbl := fmt.Sprint(tableReplyBase + idx)
		if err := m.ensureRule(ruleReplyBase+idx, "fwmark", fmt.Sprintf("0x%x", mark), "lookup", tbl); err != nil {
			slog.Warn("tunnel reply rule", "dev", dev, "err", err)
		}
		if m.opt.DryRun || ifaceExists(dev) {
			_, _ = m.ip("route", "replace", "default", "dev", dev, "table", tbl)
		} else {
			_, _ = m.ip("route", "replace", "unreachable", "default", "table", tbl)
		}
		el = append(el, fmt.Sprintf("%q : 0x%x", dev, mark))
	}
	return strings.Join(el, ", ")
}

// LocalNets returns this site's own networks, always routed by the host.
func (m *Manager) LocalNets() []netip.Prefix { return policyAggregate(m.localNets()) }

// localNets returns this site's own networks (never 0.0.0.0/0).
func (m *Manager) localNets() []netip.Prefix {
	if m.opt.LocalNetworks == nil {
		return nil
	}
	var out []netip.Prefix
	for _, p := range m.opt.LocalNetworks() {
		if p.Bits() > 0 {
			out = append(out, p.Masked())
		}
	}
	return out
}

// allowElems formats site_allow elements: "gp-dc1" . 10.6.0.0/16.
func allowElems(allows []Allowance) string {
	el := make([]string, 0, len(allows))
	for _, a := range allows {
		el = append(el, fmt.Sprintf("%q . %s", a.Dev, a.Prefix.Masked()))
	}
	sort.Strings(el)
	return strings.Join(el, ", ")
}

// dockerTransit replaces the DOCKER-USER rules (comment vpngw-transit)
// that accept transit traffic into the tunnels, traffic from each tunnel
// into what its site may reach, and the replies.
func (m *Manager) dockerTransit(srcs []netip.Prefix, allows []Allowance) {
	ctx := context.Background()
	out, err := m.run(ctx, "iptables", "", "-w", "-S", "DOCKER-USER")
	if err != nil {
		return // no Docker
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "-A DOCKER-USER ") && strings.Contains(line, "vpngw-transit") {
			args := strings.Fields(strings.Replace(line, "-A ", "-D ", 1))
			_, _ = m.run(ctx, "iptables", "", append([]string{"-w"}, args...)...)
		}
	}
	for _, p := range srcs {
		for _, rule := range [][]string{
			{"-s", p.String(), "-o", "gp-+", "-m", "comment", "--comment", "vpngw-transit", "-j", "ACCEPT"},
			{"-d", p.String(), "-i", "gp-+", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "vpngw-transit", "-j", "ACCEPT"},
		} {
			if _, err := m.run(ctx, "iptables", "", append([]string{"-w", "-I", "DOCKER-USER", "1"}, rule...)...); err != nil {
				slog.Warn("cannot add DOCKER-USER transit rule", "err", err)
			}
		}
	}
	for _, a := range allows {
		p := a.Prefix.Masked().String()
		for _, rule := range [][]string{
			{"-i", a.Dev, "-d", p, "-m", "comment", "--comment", "vpngw-transit", "-j", "ACCEPT"},
			{"-o", a.Dev, "-s", p, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "vpngw-transit", "-j", "ACCEPT"},
		} {
			if _, err := m.run(ctx, "iptables", "", append([]string{"-w", "-I", "DOCKER-USER", "1"}, rule...)...); err != nil {
				slog.Warn("cannot add DOCKER-USER exit rule", "err", err)
			}
		}
	}
}

// PeerRoutesStatus returns the installed peer subnets: prefix → interface
// (or "unreachable").
func (m *Manager) PeerRoutesStatus() map[string]string {
	out := map[string]string{}
	s, err := m.ip("-j", "route", "show", "table", fmt.Sprint(tablePeers))
	if err != nil {
		return out
	}
	var cur []struct {
		Dst  string `json:"dst"`
		Dev  string `json:"dev"`
		Type string `json:"type"`
	}
	_ = json.Unmarshal([]byte(s), &cur)
	for _, r := range cur {
		if r.Type == "unreachable" {
			out[r.Dst] = "unreachable"
		} else {
			out[r.Dst] = r.Dev
		}
	}
	return out
}

func (m *Manager) ensureGateway(gw string) {
	if _, ok := m.gateways[gw]; ok {
		return
	}
	idx := len(m.gateways) + 1
	m.gateways[gw] = idx
	if err := m.applyGateway(gw, idx); err != nil {
		slog.Warn("gateway routing not ready, will retry", "gateway", gw, "err", err)
	}
	// NAT for traffic leaving through a non-tunnel gateway interface.
	_ = m.nft(m.postroutingScript())
}

func (m *Manager) applyGateway(gw string, idx int) error {
	mark := fmt.Sprintf("0x%x", markBase+uint32(idx))
	tbl := fmt.Sprint(tablePeers + idx)
	if err := m.ensureRule(ruleGwBase+idx, "fwmark", mark, "lookup", tbl); err != nil {
		return err
	}
	t := m.resolve(gw)
	var err error
	switch {
	case t.Via.IsValid() && t.Dev != "":
		_, err = m.ip("route", "replace", "default", "via", t.Via.String(), "dev", t.Dev, "table", tbl)
	case t.Via.IsValid():
		_, err = m.ip("route", "replace", "default", "via", t.Via.String(), "table", tbl)
	case !m.opt.DryRun && !ifaceExists(t.Dev):
		err = fmt.Errorf("interface %s does not exist", t.Dev)
	default:
		_, err = m.ip("route", "replace", "default", "dev", t.Dev, "table", tbl)
	}
	if err != nil {
		// An empty table would fall through to the main default route; make
		// it unreachable so traffic does not leak while the tunnel is down.
		_, _ = m.ip("route", "replace", "unreachable", "default", "table", tbl)
		return err
	}
	return nil
}

// Reconcile re-applies peer subnets, gateway routes and NAT (after a tunnel
// or interface changed). Call periodically.
func (m *Manager) Reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncPeerRoutes()
	for gw, idx := range m.gateways {
		if err := m.applyGateway(gw, idx); err != nil {
			slog.Debug("gateway routing not ready", "gateway", gw, "err", err)
		}
	}
	_ = m.nft(m.postroutingScript())
}

// GatewayStatus returns gateways and whether their route is installed.
func (m *Manager) GatewayStatus() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for gw, idx := range m.gateways {
		o, err := m.ip("route", "show", "table", fmt.Sprint(tablePeers+idx))
		out[gw] = err == nil && strings.Contains(o, "default") && !strings.Contains(o, "unreachable")
	}
	return out
}

func (m *Manager) cleanupRules() {
	m.gateways = map[string]int{}
	m.replies = map[string]int{}
	if m.opt.DryRun {
		return
	}
	out, err := m.ip("-j", "rule", "show")
	if err != nil {
		return
	}
	var rules []struct {
		Priority int `json:"priority"`
	}
	if json.Unmarshal([]byte(out), &rules) != nil {
		return
	}
	for _, r := range rules {
		if r.Priority >= rulePeers && r.Priority <= ruleLast {
			_, _ = m.ip("rule", "del", "priority", fmt.Sprint(r.Priority))
		}
	}
	for i := 0; i < 64; i++ {
		_, _ = m.ip("route", "flush", "table", fmt.Sprint(tablePeers+i))
	}
}

// policyAggregate sorts and de-duplicates prefixes for display.
func policyAggregate(in []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, p := range in {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
