package firewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestScripts(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, EgressIface: "eth0", DryRun: true,
		Resolve: func(gw string) Target {
			if gw == "dc1" {
				return Target{Dev: "gp-dc1", Tunnel: true}
			}
			return Target{}
		},
		PeerRoutes: func() []PeerRoute {
			return []PeerRoute{{Prefix: netip.MustParsePrefix("10.6.0.0/16"), Dev: "gp-dc1"}}
		},
	})
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	base := m.Log[0]
	for _, want := range []string{"delete table inet vpngw", "ip saddr @pools ip saddr vmap @sess", "ip saddr @pools counter name dropped drop",
		"c2c_dropped drop", `oifname { "eth0" } counter masquerade`} {
		if !strings.Contains(base, want) {
			t.Errorf("base script lacks %q:\n%s", want, base)
		}
	}
	s := Session{IP: netip.MustParseAddr("10.250.0.2"), Profile: "rp-abc", Allow: []netip.Prefix{netip.MustParsePrefix("10.4.0.0/16")}, Gateway: "wan2"}
	if err := m.AddSession(s); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(m.Log, "\n")
	for _, want := range []string{"add set inet vpngw a_abc", "add element inet vpngw a_abc { 10.4.0.0/16 }", "10.250.0.2 : jump p_abc",
		"sessmark { 10.250.0.2 : 0x76670001 }", "priority 15011 fwmark 0x76670001 lookup 15101", "default dev wan2 table 15101", `"wan2"`,
		"priority 15000 fwmark 0x76670000/0xffff0000 lookup 15100", "lookup main suppress_prefixlength 0",
		"route replace 10.6.0.0/16 dev gp-dc1 table 15100"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	// A second session with the same profile reuses set and chain.
	n := len(m.Log)
	_ = m.AddSession(Session{IP: netip.MustParseAddr("10.250.0.3"), Profile: "rp-abc", Allow: s.Allow, Gateway: "wan2"})
	if strings.Contains(strings.Join(m.Log[n:], "\n"), "add set") {
		t.Error("profile set must be created once")
	}
	if err := m.RemoveSession(s.IP); err != nil {
		t.Fatal(err)
	}
	_ = m.RemoveSession(netip.MustParseAddr("10.250.0.3"))
	if last := m.Log[len(m.Log)-1]; !strings.Contains(last, "delete chain inet vpngw p_abc") {
		t.Errorf("unused profile must be removed, got:\n%s", last)
	}
}

func TestTunnelGateway(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, EgressIface: "eth0", DryRun: true,
		Resolve: func(gw string) Target {
			if gw == "dc1" {
				return Target{Dev: "gp-dc1", Tunnel: true}
			}
			return Target{}
		}})
	_ = m.Init()
	_ = m.AddSession(Session{IP: netip.MustParseAddr("10.250.0.9"), Profile: "rp-x", Allow: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Gateway: "dc1"})
	all := strings.Join(m.Log, "\n")
	if !strings.Contains(all, "default dev gp-dc1 table 15101") {
		t.Fatalf("tunnel gateway route missing:\n%s", all)
	}
	if strings.Contains(all, `"gp-dc1"`) {
		t.Fatal("tunnel interfaces must not be masqueraded by nftables (goproxy NATs them)")
	}
}

func TestTransit(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, DryRun: true,
		PeerRoutes:     func() []PeerRoute { return []PeerRoute{{Prefix: netip.MustParsePrefix("10.6.0.0/16"), Dev: "gp-lat"}} },
		TransitSources: func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")} },
	})
	_ = m.Init()
	all := strings.Join(m.Log, "\n")
	for _, want := range []string{"ip saddr @transit_src ip daddr @tunnel_dst meta mark set 0x76670000",
		"add element inet vpngw transit_src { 192.168.10.0/24 }", "add element inet vpngw tunnel_dst { 10.6.0.0/16 }",
		"route replace 10.6.0.0/16 dev gp-lat table 15100"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
}

func TestSiteAllow(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, DryRun: true,
		Allowances: func() []Allowance {
			return []Allowance{{Dev: "gp-dc2", Prefix: netip.MustParsePrefix("10.6.0.0/16")}, {Dev: "gp-dc3", Prefix: netip.MustParsePrefix("0.0.0.0/0")}}
		},
	})
	_ = m.Init()
	all := strings.Join(m.Log, "\n")
	for _, want := range []string{
		`iifname "gp-*" ct state new iifname . ip daddr != @site_allow counter name tunnel_in_dropped drop`,
		`iifname "gp-*" ct state new ct mark set iifname map @tunmark`,
		"ct direction reply ct mark and 0xffff0000 == 0x76680000 meta mark set ct mark",
		`add element inet vpngw tunmark { "gp-dc2" : 0x76680001, "gp-dc3" : 0x76680002 }`,
		"rule add priority 15501 fwmark 0x76680001 lookup 15501", "route replace default dev gp-dc3 table 15502",
		`iifname "gp-*" oifname != "gp-*" iifname . ip daddr @site_allow counter masquerade`,
		`add element inet vpngw site_allow { "gp-dc2" . 10.6.0.0/16, "gp-dc3" . 0.0.0.0/0 }`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestTransitGateway(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, DryRun: true,
		Resolve:        func(gw string) Target { return Target{Dev: "gp-" + strings.ToLower(gw), Tunnel: true} },
		TransitSources: func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")} },
		TransitGateway: func() string { return "DC2" },
	})
	_ = m.Init()
	all := strings.Join(m.Log, "\n")
	for _, want := range []string{
		"ip saddr @transit_src ip daddr != @tunnel_dst meta mark set ip saddr map @transit_gw",
		"add element inet vpngw transit_gw { 192.168.10.0/24 : 0x76670001 }",
		"rule add priority 15011 fwmark 0x76670001 lookup 15101", "route replace default dev gp-dc2 table 15101",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
}

func TestLocalNetworks(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, DryRun: true,
		LocalNetworks: func() []netip.Prefix {
			return []netip.Prefix{netip.MustParsePrefix("10.4.0.0/16"), netip.MustParsePrefix("0.0.0.0/0")}
		},
	})
	_ = m.Init()
	all := strings.Join(m.Log, "\n")
	for _, want := range []string{
		"meta mark and 0xffff0000 == 0x76670000 ip daddr @local_nets meta mark set 0x76670000",
		"add element inet vpngw local_nets { 10.4.0.0/16 }",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "local_nets { 0.0.0.0/0") || strings.Contains(all, ", 0.0.0.0/0 }") {
		t.Error("0.0.0.0/0 is never a local network")
	}
}

func TestExitMark(t *testing.T) {
	m := New(Options{Pools: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/20")}, DryRun: true,
		Resolve: func(gw string) Target {
			if gw == "dc1" {
				return Target{Dev: "gp-dc1", Tunnel: true}
			}
			return Target{}
		}})
	_ = m.Init()
	if got := m.ExitMark(""); got != markBase {
		t.Fatalf("no exit: mark 0x%x, want the base mark (peer subnets, then the host's routes)", got)
	}
	m.Log = nil
	if got := m.ExitMark("dc1"); got != markBase+1 || m.ExitMark("dc1") != got {
		t.Fatalf("exit dc1: mark 0x%x", got)
	}
	all := strings.Join(m.Log, "\n")
	if !strings.Contains(all, "rule add priority 15011 fwmark 0x76670001 lookup 15101") || !strings.Contains(all, "default dev gp-dc1 table 15101") {
		t.Fatalf("exit routing missing:\n%s", all)
	}
	// A site whose interface is missing: unreachable, never the host's
	// default route.
	run := m.run
	m.run = func(ctx context.Context, name, stdin string, args ...string) (string, error) {
		out, err := run(ctx, name, stdin, args...)
		if name == "ip" && strings.Contains(strings.Join(args, " "), "route replace default dev nope") {
			return out, errors.New("Cannot find device")
		}
		return out, err
	}
	m.Log = nil
	if m.ExitMark("nope") != markBase+2 || !strings.Contains(strings.Join(m.Log, "\n"), "route replace unreachable default table 15102") {
		t.Fatalf("missing site must be unreachable:\n%s", strings.Join(m.Log, "\n"))
	}
}
