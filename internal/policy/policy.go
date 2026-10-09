// Package policy turns IdP claims and admin mappings into route profiles.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// GroupRoutes is the routing information attached to one group.
type GroupRoutes struct {
	Routes  []string `json:"vpnRoutes"`
	Gateway string   `json:"vpnGateway,omitempty"`
	DNS     []string `json:"vpnDNS,omitempty"`
	Domain  string   `json:"vpnDomain,omitempty"`
	// Domains are names whose traffic goes through Gateway: the gateway
	// answers them with addresses of its domain pool and forwards the
	// connections. DNS then names the servers the gateway resolves them
	// with, not the client's resolvers.
	Domains []string `json:"vpnDomains,omitempty"`
}

// Claim is the parsed routes claim.
type Claim struct {
	// Groups maps group name to routes (object format).
	Groups map[string]GroupRoutes
	// Default holds routes from the plain array format; used when the
	// login has no @group suffix.
	Default *GroupRoutes
}

// ParseClaim accepts:
//
//	{"vpn-dc1": {"vpnRoutes": ["10.4.0.0/16"], "vpnGateway": "dc1"}}
//	["10.1.0.0/16", "!10.1.5.0/24"]
//	{"vpnRoutes": [...], "vpnGateway": "..."}           (single, ungrouped)
//
// Route values may be arrays or comma/space separated strings.
func ParseClaim(raw json.RawMessage) (Claim, error) {
	c := Claim{Groups: map[string]GroupRoutes{}}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return c, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return c, fmt.Errorf("routes claim: %w", err)
	}
	switch t := v.(type) {
	case []any, string:
		c.Default = &GroupRoutes{Routes: stringList(t)}
	case map[string]any:
		if _, ok := t["vpnRoutes"]; ok {
			gr := groupFromMap(t)
			c.Default = &gr
			break
		}
		for name, val := range t {
			switch gv := val.(type) {
			case map[string]any:
				c.Groups[name] = groupFromMap(gv)
			case []any, string:
				c.Groups[name] = GroupRoutes{Routes: stringList(gv)}
			}
		}
	default:
		return c, errors.New("routes claim: unsupported format")
	}
	return c, nil
}

func groupFromMap(m map[string]any) GroupRoutes {
	var g GroupRoutes
	g.Routes = stringList(m["vpnRoutes"])
	if s, ok := m["vpnGateway"].(string); ok {
		g.Gateway = strings.TrimSpace(s)
	}
	g.DNS = stringList(m["vpnDNS"])
	if s, ok := m["vpnDomain"].(string); ok {
		g.Domain = strings.TrimSpace(s)
	}
	g.Domains = stringList(m["vpnDomains"])
	return g
}

func stringList(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' || r == ';' || r == '\n' })...)
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, stringList(s)...)
			}
		}
	}
	return out
}

// Profile is the resolved routing policy for one VPN login.
type Profile struct {
	ID         string         `json:"id"`
	Group      string         `json:"group"`
	Allow      []netip.Prefix `json:"allow"` // enforced by the firewall
	Gateway    string         `json:"gateway,omitempty"`
	DNS        []netip.Addr   `json:"dns,omitempty"`
	Domain     string         `json:"domain,omitempty"`
	FullTunnel bool           `json:"fullTunnel"`
	Warnings   []string       `json:"warnings,omitempty"`
	// Domains go through Gateway via the gateway's DNS (domain proxy);
	// Upstream resolves them (empty: the gateway's resolvers). Pool is the
	// domain pool added to Allow, DNS then is the gateway's DNS server.
	Domains  []string     `json:"domains,omitempty"`
	Upstream []netip.Addr `json:"upstream,omitempty"`
	Pool     netip.Prefix `json:"pool,omitempty"`
}

// DomainLabels returns the included Domains for people: a top-level
// domain as "*.com".
func (p *Profile) DomainLabels() []string { return domainLabels(p.Domains, false) }

// ExceptLabels returns the excluded Domains ("!name") without the "!".
func (p *Profile) ExceptLabels() []string { return domainLabels(p.Domains, true) }

func domainLabels(domains []string, excluded bool) []string {
	var out []string
	for _, d := range domains {
		d, exc := strings.CutPrefix(d, "!")
		if exc != excluded {
			continue
		}
		if !strings.Contains(d, ".") {
			d = "*." + d
		}
		out = append(out, d)
	}
	return out
}

// Networks returns the allowed networks without the domain pool.
func (p *Profile) Networks() []netip.Prefix {
	if !p.Pool.IsValid() {
		return p.Allow
	}
	out := make([]netip.Prefix, 0, len(p.Allow))
	for _, a := range p.Allow {
		if a != p.Pool {
			out = append(out, a)
		}
	}
	return out
}

// Routes returns the routes to push to clients (empty for full tunnel).
func (p *Profile) Routes() []netip.Prefix {
	if p.FullTunnel {
		return nil
	}
	return p.Allow
}

// AllowStrings returns allowed networks as strings.
func (p *Profile) AllowStrings() []string {
	out := make([]string, len(p.Allow))
	for i, a := range p.Allow {
		out[i] = a.String()
	}
	return out
}

// DNSStrings returns DNS servers as strings.
func (p *Profile) DNSStrings() []string {
	out := make([]string, len(p.DNS))
	for i, a := range p.DNS {
		out[i] = a.String()
	}
	return out
}

// Build creates a profile from raw route strings.
func Build(group string, sources []GroupRoutes, defaultDNS []netip.Addr, defaultDomain string) (*Profile, error) {
	var inc, exc []netip.Prefix
	var dns []netip.Addr
	var domains []string
	p := &Profile{Group: group}
	gateways := map[string]bool{}
	for _, src := range sources {
		for _, r := range src.Routes {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			neg := strings.HasPrefix(r, "!")
			r = strings.TrimSpace(strings.TrimPrefix(r, "!"))
			pfx, err := parsePrefix(r)
			if err != nil {
				p.Warnings = append(p.Warnings, fmt.Sprintf("ignored invalid route %q", r))
				continue
			}
			if !pfx.Addr().Is4() {
				p.Warnings = append(p.Warnings, fmt.Sprintf("ignored IPv6 route %s", pfx))
				continue
			}
			if neg {
				exc = append(exc, pfx)
			} else {
				inc = append(inc, pfx)
			}
		}
		for _, d := range src.DNS {
			if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil && a.Is4() {
				dns = append(dns, a)
			}
		}
		if src.Gateway != "" {
			gateways[src.Gateway] = true
		}
		if src.Domain != "" && p.Domain == "" {
			p.Domain = src.Domain
		}
		for _, d := range src.Domains {
			n, err := NormalizeDomain(d)
			if err != nil {
				p.Warnings = append(p.Warnings, err.Error())
				continue
			}
			domains = append(domains, n)
		}
	}
	if len(gateways) > 1 {
		names := make([]string, 0, len(gateways))
		for g := range gateways {
			names = append(names, g)
		}
		sort.Strings(names)
		p.Warnings = append(p.Warnings, fmt.Sprintf("conflicting gateways %v, using %s", names, names[0]))
		p.Gateway = names[0]
	} else {
		for g := range gateways {
			p.Gateway = g
		}
	}
	if err := ValidGateway(p.Gateway); err != nil {
		return nil, err
	}
	p.Allow = Subtract(inc, exc)
	p.Domains = uniqDomains(domains)
	if len(domainLabels(p.Domains, false)) == 0 {
		p.Domains = nil // only exclusions: nothing to send
	}
	if len(p.Allow) == 0 && len(p.Domains) == 0 {
		return nil, errors.New("no routes")
	}
	p.FullTunnel = len(p.Allow) == 1 && p.Allow[0].Bits() == 0
	if len(p.Domains) > 0 {
		// vpnDNS resolves the domains on the gateway; the client gets the
		// gateway's DNS server (WithDomainProxy).
		p.Upstream = uniqAddrs(dns)
		p.Domain = ""
	} else if p.FullTunnel {
		if len(dns) == 0 {
			dns = defaultDNS
		}
		p.DNS = uniqAddrs(dns)
		if p.Domain == "" {
			p.Domain = defaultDomain
		}
	} else {
		// Split tunnel: the client keeps its own resolvers. Pushed ones are
		// often outside the tunnelled networks and then unreachable, which
		// breaks all name resolution.
		p.Domain = ""
	}
	p.ID = p.hash()
	return p, nil
}

// WithDomainProxy routes the domain pool to a profile with domains and
// makes dnsServer (in the pool) its DNS. Without a pool the domains are
// dropped.
func (p *Profile) WithDomainProxy(pool netip.Prefix, dnsServer netip.Addr) *Profile {
	if len(p.Domains) == 0 {
		return p
	}
	if !pool.IsValid() {
		p.Warnings = append(p.Warnings, "vpnDomains ignored: no domain pool (VPN_DOMAIN_POOL)")
		p.Domains, p.Upstream = nil, nil
	} else {
		p.Pool = pool
		p.Allow = Aggregate(append(append([]netip.Prefix{}, p.Allow...), pool))
		p.FullTunnel = len(p.Allow) == 1 && p.Allow[0].Bits() == 0
		p.DNS = []netip.Addr{dnsServer}
	}
	p.ID = p.hash()
	return p
}

// NormalizeDomain checks a vpnDomains entry: a DNS name, optionally with a
// leading "*." or "." (subdomains always match). A single label such as a
// top-level domain needs the wildcard ("*.com"). "!" excludes the name and
// its subdomains; it is kept in the result.
func NormalizeDomain(s string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	n, exc := strings.CutPrefix(n, "!")
	n = strings.TrimSpace(n)
	wildcard := strings.HasPrefix(n, "*.") || strings.HasPrefix(n, ".")
	n = strings.TrimPrefix(n, "*.")
	n = strings.TrimPrefix(n, ".")
	n = strings.TrimSuffix(n, ".")
	bad := fmt.Errorf("ignored invalid domain %q", s)
	if n == "" || len(n) > 253 || !strings.Contains(n, ".") && !wildcard {
		return "", bad
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", bad
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", bad
			}
		}
	}
	if exc {
		n = "!" + n
	}
	return n, nil
}

// MatchDomain reports whether name is one of domains or a subdomain. The
// most specific entry decides, so "!google.com" excludes it from "*.com"
// and "maps.google.com" includes that one again; on a tie "!" wins.
func MatchDomain(domains []string, name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	best, match := -1, false
	for _, d := range domains {
		d, exc := strings.CutPrefix(d, "!")
		if name != d && !strings.HasSuffix(name, "."+d) {
			continue
		}
		if len(d) > best || len(d) == best && exc {
			best, match = len(d), !exc
		}
	}
	return match
}

func uniqDomains(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// WithLocalGateway drops a gateway that names this node itself (self):
// the traffic leaves through the host's default route, so one IdP group
// can name an exit site and still work on that site's own gateway.
func (p *Profile) WithLocalGateway(self func(string) bool) *Profile {
	if p.Gateway != "" && self(p.Gateway) {
		p.Gateway = ""
		p.ID = p.hash()
	}
	return p
}

// WithFullTunnelDNS gives a full-tunnel profile without DNS servers the
// given ones: otherwise clients keep resolvers of their own network, which
// the tunnel does not reach.
func (p *Profile) WithFullTunnelDNS(dns []netip.Addr) *Profile {
	if p.FullTunnel && len(p.DNS) == 0 && len(dns) > 0 {
		p.DNS = uniqAddrs(dns)
		p.ID = p.hash()
	}
	return p
}

// ValidGateway checks a vpnGateway value: a tunnel peer name, an interface
// name or an IPv4 next hop.
func ValidGateway(g string) error {
	if g == "" {
		return nil
	}
	if a, err := netip.ParseAddr(g); err == nil {
		if !a.Is4() {
			return fmt.Errorf("gateway %q: only IPv4 is supported", g)
		}
		return nil
	}
	if len(g) > 32 {
		return fmt.Errorf("gateway %q: name too long", g)
	}
	for _, r := range g {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("gateway %q: invalid interface name", g)
		}
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func uniqAddrs(in []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range in {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func (p *Profile) hash() string {
	h := sha256.New()
	for _, a := range p.Allow {
		fmt.Fprintf(h, "r:%s\n", a)
	}
	dns := append([]netip.Addr{}, p.DNS...)
	sort.Slice(dns, func(i, j int) bool { return dns[i].Less(dns[j]) })
	for _, d := range dns {
		fmt.Fprintf(h, "d:%s\n", d)
	}
	fmt.Fprintf(h, "g:%s\nn:%s\n", p.Gateway, p.Domain)
	for _, d := range p.Domains {
		fmt.Fprintf(h, "x:%s\n", d)
	}
	for _, u := range p.Upstream {
		fmt.Fprintf(h, "u:%s\n", u)
	}
	return "rp-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// SplitLogin splits "user@group" into its parts. Only the last '@' counts,
// so logins that are e-mail addresses still work with a group suffix.
func SplitLogin(login string) (user, group string) {
	login = strings.TrimSpace(login)
	if i := strings.LastIndex(login, "@"); i >= 0 {
		return login[:i], login[i+1:]
	}
	return login, ""
}

// Available lists the groups a user can connect with (from the routes claim).
func Available(claim Claim) map[string][]GroupRoutes {
	out := map[string][]GroupRoutes{}
	for name, gr := range claim.Groups {
		out[name] = append(out[name], gr)
	}
	return out
}

// ErrInternetOnly is returned for a login without a group when the user's
// groups grant nothing but internet access (0.0.0.0/0).
var ErrInternetOnly = errors.New("your groups grant only internet access; log in as user@group")

// Resolve picks the profile for a login group. Without a group the login
// gets the networks of all the user's groups except 0.0.0.0/0: internet
// access needs a group named explicitly (user@group).
func Resolve(group string, claim Claim, defDNS []netip.Addr, defDomain string) (*Profile, error) {
	avail := Available(claim)
	if group == "" {
		if len(avail) == 0 {
			if claim.Default != nil {
				// Ungrouped claim: there is no group to name.
				return Build("", []GroupRoutes{*claim.Default}, defDNS, defDomain)
			}
			return nil, errors.New("no VPN routes for this user")
		}
		return merged(claim, avail, defDNS, defDomain)
	}
	for name, src := range avail {
		if strings.EqualFold(name, group) {
			return Build(name, src, defDNS, defDomain)
		}
	}
	return nil, fmt.Errorf("group %q is not available for this user", group)
}

// merged combines the networks of all groups (each group's exclusions
// apply to that group only) without default routes and gateways.
func merged(claim Claim, avail map[string][]GroupRoutes, defDNS []netip.Addr, defDomain string) (*Profile, error) {
	var srcs []GroupRoutes
	if claim.Default != nil {
		srcs = append(srcs, *claim.Default)
	}
	for _, name := range GroupNames(avail) {
		srcs = append(srcs, avail[name]...)
	}
	var allow []netip.Prefix
	var dns []string
	domain := ""
	for _, src := range srcs {
		var routes []string
		for _, r := range src.Routes {
			if pfx, err := parsePrefix(strings.TrimSpace(r)); err == nil && pfx.Bits() == 0 {
				continue // 0.0.0.0/0 only with an explicit group
			}
			routes = append(routes, r)
		}
		p, err := Build("", []GroupRoutes{{Routes: routes}}, nil, "")
		if err != nil {
			continue
		}
		allow = append(allow, p.Allow...)
		dns = append(dns, src.DNS...)
		if domain == "" {
			domain = src.Domain
		}
	}
	if len(allow) == 0 {
		return nil, ErrInternetOnly
	}
	allow = Aggregate(allow)
	routes := make([]string, len(allow))
	for i, a := range allow {
		routes[i] = a.String()
	}
	return Build("", []GroupRoutes{{Routes: routes, DNS: dns, Domain: domain}}, defDNS, defDomain)
}

// GroupNames returns sorted names of available groups.
func GroupNames(avail map[string][]GroupRoutes) []string {
	out := make([]string, 0, len(avail))
	for k := range avail {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
