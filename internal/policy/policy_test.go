package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func strs(ps []netip.Prefix) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func TestAggregate(t *testing.T) {
	got := strs(Aggregate(pfx("10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25", "10.0.0.0/24", "192.168.1.0/24", "10.0.2.0/23")))
	want := []string{"10.0.0.0/22", "192.168.1.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSubtract(t *testing.T) {
	got := strs(Subtract(pfx("10.4.0.0/16"), pfx("10.4.5.0/24")))
	want := []string{"10.4.0.0/22", "10.4.4.0/24", "10.4.6.0/23", "10.4.8.0/21", "10.4.16.0/20", "10.4.32.0/19", "10.4.64.0/18", "10.4.128.0/17"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if len(Subtract(pfx("10.0.0.0/8"), pfx("0.0.0.0/0"))) != 0 {
		t.Fatal("full exclusion must leave nothing")
	}
	full := Subtract(pfx("0.0.0.0/0"), pfx("10.0.0.0/8"))
	if Contains(full, netip.MustParseAddr("10.1.1.1")) || !Contains(full, netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("bad full-tunnel exclusion %v", strs(full))
	}
}

// subtractSlow is the obvious Subtract: every exclusion cuts every piece.
func subtractSlow(include, exclude []netip.Prefix) []netip.Prefix {
	var out []interval
	for _, x := range toIntervals(include) {
		cur := []interval{x}
		for _, e := range toIntervals(exclude) {
			var next []interval
			for _, c := range cur {
				if e.hi < c.lo || e.lo > c.hi {
					next = append(next, c)
					continue
				}
				if e.lo > c.lo {
					next = append(next, interval{c.lo, e.lo - 1})
				}
				if e.hi < c.hi {
					next = append(next, interval{e.hi + 1, c.hi})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return fromIntervals(mergeIntervals(out))
}

func TestSubtractRandom(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	random := func(n int) []netip.Prefix {
		var out []netip.Prefix
		for i := 0; i < n; i++ {
			// a narrow address range, so prefixes overlap and touch
			a := netip.AddrFrom4([4]byte{10, 0, byte(r.Intn(4)), byte(r.Intn(256))})
			if r.Intn(20) == 0 {
				a = netip.AddrFrom4([4]byte{255, 255, 255, byte(r.Intn(256))})
			}
			p, _ := a.Prefix(20 + r.Intn(13))
			out = append(out, p)
		}
		return out
	}
	for i := 0; i < 2000; i++ {
		inc, exc := random(r.Intn(8)), random(r.Intn(12))
		if r.Intn(50) == 0 {
			inc = append(inc, pfx("0.0.0.0/0")...)
		}
		got, want := strs(Subtract(inc, exc)), strs(subtractSlow(inc, exc))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%v minus %v: got %v want %v", strs(inc), strs(exc), got, want)
		}
	}
}

func TestWiden(t *testing.T) {
	var in []netip.Prefix
	for i := 0; i < 50; i++ {
		in = append(in, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i * 2), 0, 0}), 24))
	}
	out, widened := Widen(in, 10)
	if !widened || len(out) > 10 {
		t.Fatalf("widen: %d routes, widened=%v", len(out), widened)
	}
	if !Covers(out, in) {
		t.Fatal("widened routes must cover the input")
	}
	if _, w := Widen(pfx("10.0.0.0/8"), 200); w {
		t.Fatal("nothing to widen")
	}
	// The cheapest cover: the /24s next to each other, not the far one.
	out, _ = Widen(pfx("10.0.0.0/24", "10.0.2.0/24", "10.0.4.0/24", "10.200.0.0/24"), 2)
	if got, want := strs(out), []string{"10.0.0.0/21", "10.200.0.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestWidenRandom(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 300; i++ {
		var in []netip.Prefix
		for j := r.Intn(300); j > 0; j-- {
			a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
			p, _ := a.Prefix(8 + r.Intn(25))
			in = append(in, p)
		}
		limit := 1 + r.Intn(100)
		out, _ := Widen(in, limit)
		if len(out) > limit || !Covers(out, in) {
			t.Fatalf("%d prefixes, limit %d, covers %v", len(out), limit, Covers(out, in))
		}
	}
}

// Many equal exclusions change at the same price; the limit is still used.
func TestWidenExclusions(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var exc []netip.Prefix
	for i := 0; i < 1000; i++ {
		a := netip.AddrFrom4([4]byte{byte(1 + r.Intn(126)), byte(r.Intn(256)), byte(r.Intn(256)), 0})
		p, _ := a.Prefix(24)
		exc = append(exc, p)
	}
	allow := Subtract(pfx("0.0.0.0/1"), exc)
	for _, limit := range []int{200, 1000} {
		out, _ := Widen(allow, limit)
		if len(out) > limit || len(out) < limit*3/4 || !Covers(out, allow) {
			t.Fatalf("limit %d: %d prefixes", limit, len(out))
		}
	}
}

func TestParseClaimFormats(t *testing.T) {
	c, err := ParseClaim(json.RawMessage(`{"vpn-dc1":{"vpnRoutes":["10.4.0.0/16","!10.4.5.0/24"],"vpnGateway":"dc1","vpnDNS":["10.4.0.53"]},"vpn-internet":{"vpnRoutes":"0.0.0.0/0"}}`))
	if err != nil || len(c.Groups) != 2 || c.Groups["vpn-dc1"].Gateway != "dc1" || c.Groups["vpn-internet"].Routes[0] != "0.0.0.0/0" {
		t.Fatalf("object format: %+v %v", c, err)
	}
	c, err = ParseClaim(json.RawMessage(`["10.1.0.0/16", "!10.1.5.0/24"]`))
	if err != nil || c.Default == nil || len(c.Default.Routes) != 2 {
		t.Fatalf("array format: %+v %v", c, err)
	}
	c, err = ParseClaim(json.RawMessage(`"10.1.0.0/16, 10.2.0.0/16"`))
	if err != nil || c.Default == nil || len(c.Default.Routes) != 2 {
		t.Fatalf("string format: %+v %v", c, err)
	}
	c, _ = ParseClaim(nil)
	if c.Default != nil || len(c.Groups) != 0 {
		t.Fatal("empty claim")
	}
}

func TestBuildProfile(t *testing.T) {
	p, err := Build("vpn-dc1", []GroupRoutes{{Routes: []string{"10.4.0.0/16", "!10.4.5.0/24", "bogus", "fd00::/8"}, Gateway: "dc1"}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.FullTunnel || p.Gateway != "dc1" || len(p.Allow) != 8 || len(p.Warnings) != 2 {
		t.Fatalf("profile %+v", p)
	}
	p2, _ := Build("other-name", []GroupRoutes{{Routes: []string{"10.4.128.0/17", "10.4.0.0/16", "!10.4.5.0/24"}, Gateway: "dc1"}}, nil, "")
	if p.ID != p2.ID {
		t.Fatal("profile id must depend only on routes, DNS and gateway")
	}
	full, _ := Build("", []GroupRoutes{{Routes: []string{"0.0.0.0/0"}}}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, "corp")
	if !full.FullTunnel || len(full.Routes()) != 0 || full.DNS[0].String() != "1.1.1.1" || full.Domain != "corp" {
		t.Fatalf("full tunnel %+v", full)
	}
	if _, err := Build("x", []GroupRoutes{{Routes: []string{"!10.0.0.0/8"}}}, nil, ""); err == nil {
		t.Fatal("profile without routes must fail")
	}
	if _, err := Build("x", []GroupRoutes{{Routes: []string{"10.0.0.0/8"}, Gateway: "bad name;rm"}}, nil, ""); err == nil {
		t.Fatal("invalid gateway must fail")
	}
}

func TestResolve(t *testing.T) {
	claim, _ := ParseClaim(json.RawMessage(`{"vpn-dc1":{"vpnRoutes":["10.4.0.0/16"]},"vpn-internet":{"vpnRoutes":["0.0.0.0/0"]}}`))
	p, err := Resolve("VPN-DC1", claim, nil, "")
	if err != nil || p.Group != "vpn-dc1" || !reflect.DeepEqual(strs(p.Allow), []string{"10.4.0.0/16"}) {
		t.Fatalf("group lookup is case-insensitive: %v %v", p, err)
	}
	if _, err = Resolve("vpn-riga", claim, nil, ""); err == nil {
		t.Fatal("a group without routes in the claim must not be available")
	}
	if _, err = Resolve("", claim, nil, ""); err != nil {
		t.Fatalf("without a group: %v", err)
	}
	// Without a group: all networks of all groups, never 0.0.0.0/0, no gateway;
	// exclusions apply within their group only.
	multi, _ := ParseClaim(json.RawMessage(`{
		"vpn-inet": {"vpnRoutes": ["0.0.0.0/0", "!10.4.5.0/24"], "vpnGateway": "dc1", "vpnDNS": ["1.1.1.1"]},
		"vpn-dc1":  {"vpnRoutes": ["10.4.0.0/16"], "vpnDNS": ["10.0.0.53"]},
		"vpn-lat":  {"vpnRoutes": ["10.6.0.0/16", "!10.6.9.0/24"]}}`))
	p, err = Resolve("", multi, nil, "")
	if err != nil || p.FullTunnel || p.Gateway != "" || p.Group != "" ||
		!reflect.DeepEqual(strs(p.Allow), strs(Subtract(pfx("10.4.0.0/16", "10.6.0.0/16"), pfx("10.6.9.0/24")))) {
		t.Fatalf("merged profile: %+v %v", p, err)
	}
	if len(p.DNS) != 0 {
		t.Fatalf("the merged profile is split tunnel: no DNS, got %v", p.DNS)
	}
	if p, err = Resolve("vpn-inet", multi, nil, ""); err != nil || p.Gateway != "dc1" || p.FullTunnel {
		t.Fatalf("explicit group keeps the internet: %+v %v", p, err)
	}
	inet, _ := ParseClaim(json.RawMessage(`{"vpn-inet":{"vpnRoutes":["0.0.0.0/0"]}}`))
	if _, err = Resolve("", inet, nil, ""); !errors.Is(err, ErrInternetOnly) {
		t.Fatalf("internet-only groups need the group in the login: %v", err)
	}
	single, _ := ParseClaim(json.RawMessage(`{"vpn-dc1":{"vpnRoutes":["10.4.0.0/16"]}}`))
	if p, err = Resolve("", single, nil, ""); err != nil || !reflect.DeepEqual(strs(p.Allow), []string{"10.4.0.0/16"}) {
		t.Fatalf("single group without suffix: %v %v", p, err)
	}
	legacy, _ := ParseClaim(json.RawMessage(`["0.0.0.0/0"]`))
	if p, err = Resolve("", legacy, nil, ""); err != nil || !p.FullTunnel {
		t.Fatalf("ungrouped claim keeps its routes: %v %v", p, err)
	}
	if _, err = Resolve("", Claim{}, nil, ""); err == nil {
		t.Fatal("user without routes must be refused")
	}
}

func TestSplitLogin(t *testing.T) {
	for in, want := range map[string][2]string{
		"v.pupkin@vpn-riga":         {"v.pupkin", "vpn-riga"},
		"v.pupkin":                  {"v.pupkin", ""},
		"v.pupkin@corp.com@vpn-dc1": {"v.pupkin@corp.com", "vpn-dc1"},
	} {
		u, g := SplitLogin(in)
		if u != want[0] || g != want[1] {
			t.Errorf("SplitLogin(%q) = %q, %q", in, u, g)
		}
	}
}

func TestFullTunnelDNS(t *testing.T) {
	fb := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	full, _ := Build("inet", []GroupRoutes{{Routes: []string{"0.0.0.0/0"}}}, nil, "")
	id := full.ID
	if full.WithFullTunnelDNS(fb); len(full.DNS) != 1 || full.ID == id {
		t.Fatalf("full tunnel without DNS gets the fallback: %v", full.DNS)
	}
	own, _ := Build("inet", []GroupRoutes{{Routes: []string{"0.0.0.0/0"}, DNS: []string{"10.6.10.251"}}}, nil, "")
	if own.WithFullTunnelDNS(fb); own.DNS[0].String() != "10.6.10.251" {
		t.Fatal("group DNS wins")
	}
	split, _ := Build("lat", []GroupRoutes{{Routes: []string{"10.6.0.0/16"}}}, nil, "")
	if split.WithFullTunnelDNS(fb); len(split.DNS) != 0 {
		t.Fatal("split tunnel keeps the client's DNS")
	}
}

func TestLocalGateway(t *testing.T) {
	self := func(g string) bool { return strings.EqualFold(g, "LV-EXIT") }
	p, _ := Build("vpn-inet-lat", []GroupRoutes{{Routes: []string{"0.0.0.0/0"}, Gateway: "lv-exit"}}, nil, "")
	id := p.ID
	if p.WithLocalGateway(self); p.Gateway != "" || p.ID == id {
		t.Fatalf("this node as gateway means the host's default route: %+v", p)
	}
	o, _ := Build("vpn-inet-lat", []GroupRoutes{{Routes: []string{"0.0.0.0/0"}, Gateway: "KZ-EXIT"}}, nil, "")
	if o.WithLocalGateway(self); o.Gateway != "KZ-EXIT" {
		t.Fatal("other sites stay gateways")
	}
}

func TestDNSOnlyForFullTunnel(t *testing.T) {
	def := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	split, _ := Build("lat", []GroupRoutes{{Routes: []string{"10.4.0.0/16"}, DNS: []string{"10.4.0.53"}, Domain: "corp.lan"}}, def, "corp.lan")
	if len(split.DNS) != 0 || split.Domain != "" {
		t.Fatalf("split tunnel keeps the client's resolvers: %v %q", split.DNS, split.Domain)
	}
	full, _ := Build("inet", []GroupRoutes{{Routes: []string{"0.0.0.0/0"}}}, def, "corp.lan")
	if len(full.DNS) != 1 || full.Domain != "corp.lan" {
		t.Fatalf("full tunnel gets DNS: %v %q", full.DNS, full.Domain)
	}
}

func TestDomains(t *testing.T) {
	claim, err := ParseClaim([]byte(`{
		"vpn-proxy": {"vpnRoutes": ["10.1.0.0/16"], "vpnDomains": ["*.YouTube.com.", "googlevideo.com", "bad!domain.com", "*.org", "youtu.be", "*.youtu.be", "net"], "vpnDNS": ["8.8.8.8"], "vpnGateway": "lat"},
		"vpn-only": {"vpnDomains": "example.org"},
		"vpn-lat": {"vpnRoutes": ["10.4.0.0/16"]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Resolve("vpn-proxy", claim, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Domains, " ") != "googlevideo.com org youtu.be youtube.com" || len(p.Upstream) != 1 || len(p.DNS) != 0 || len(p.Warnings) != 2 {
		t.Fatalf("domains: %+v", p)
	}
	pool := netip.MustParsePrefix("198.18.0.0/16")
	id := p.ID
	p.WithDomainProxy(pool, netip.MustParseAddr("198.18.0.1"))
	if p.ID == id || len(p.DNS) != 1 || p.DNS[0].String() != "198.18.0.1" || len(p.Allow) != 2 || len(p.Networks()) != 1 || p.FullTunnel {
		t.Fatalf("with pool: %+v", p)
	}
	if !MatchDomain(p.Domains, "www.youtube.com.") || !MatchDomain(p.Domains, "YOUTUBE.COM") || MatchDomain(p.Domains, "notyoutube.com") ||
		!MatchDomain(p.Domains, "wikipedia.org") || MatchDomain(p.Domains, "example.net") {
		t.Fatal("match")
	}
	// A group with only domains is a valid login.
	if p, err := Resolve("vpn-only", claim, nil, ""); err != nil || len(p.Allow) != 0 || len(p.Domains) != 1 {
		t.Fatalf("domains only: %+v %v", p, err)
	}
	// The plain login never gets domains.
	if p, err := Resolve("", claim, nil, ""); err != nil || len(p.Domains) != 0 || len(p.Upstream) != 0 {
		t.Fatalf("plain: %+v %v", p, err)
	}
	// No pool: domains are dropped with a warning.
	p, _ = Resolve("vpn-proxy", claim, nil, "")
	p.WithDomainProxy(netip.Prefix{}, netip.Addr{})
	if len(p.Domains) != 0 || len(p.DNS) != 0 {
		t.Fatalf("no pool: %+v", p)
	}
}

func TestDomainExclusions(t *testing.T) {
	claim, _ := ParseClaim([]byte(`{
		"vpn-proxy": {"vpnDomains": ["*.com", "!google.com", "maps.google.com", "youtu.be", "*.youtu.be", "!Mail.Youtu.Be"]},
		"vpn-none": {"vpnDomains": ["!google.com"], "vpnRoutes": ["10.1.0.0/16"]}
	}`))
	p, err := Resolve("vpn-proxy", claim, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.DomainLabels(), " ") + " | " + strings.Join(p.ExceptLabels(), " "); got != "*.com maps.google.com youtu.be | google.com mail.youtu.be" {
		t.Fatal(got)
	}
	for name, want := range map[string]bool{
		"example.com": true, "google.com": false, "www.google.com": false, "maps.google.com": true,
		"a.maps.google.com": true, "youtu.be": true, "mail.youtu.be": false, "x.mail.youtu.be": false, "example.org": false,
	} {
		if MatchDomain(p.Domains, name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
	if MatchDomain([]string{"example.com", "!example.com"}, "example.com") {
		t.Error("on a tie the exclusion wins")
	}
	// Only exclusions: no domain proxy at all.
	if p, err := Resolve("vpn-none", claim, nil, ""); err != nil || p.Domains != nil {
		t.Fatalf("only exclusions: %+v %v", p, err)
	}
}

func TestLargeLists(t *testing.T) {
	var routes []netip.Prefix
	for i := 0; i < 20000; i++ { // non-adjacent /28s: nothing aggregates
		routes = append(routes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 28))
	}
	start := time.Now()
	out, widened := WidenTo(routes, 200, 3000)
	if !widened || len(out) > 200 || routeBytes(out) > 3000 || !Covers(out, routes) {
		t.Fatalf("widened %v: %d prefixes, %d bytes", widened, len(out), routeBytes(out))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("20000 routes took %v", d)
	}
	var exc []netip.Prefix
	for i := 0; i < 20000; i++ { // "everything except" lists
		exc = append(exc, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i%200), byte(i >> 4), byte(i), 0}), 24))
	}
	start = time.Now()
	if allow := Subtract(pfx("0.0.0.0/0"), exc); Contains(allow, netip.MustParseAddr("1.0.0.1")) || len(allow) < 20000 {
		t.Fatalf("subtract: %d prefixes", len(allow))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("20000 exclusions took %v", d)
	}
	var ds []string
	for i := 0; i < 100000; i++ {
		ds = append(ds, fmt.Sprintf("site%d.example", i))
	}
	set := NewDomainSet(append(ds, "!site7.example"))
	if !set.Match("www.site42.example") || set.Match("site7.example") || set.Match("google.com") || set.Len() != 100001 {
		t.Fatal("domain set")
	}
}
