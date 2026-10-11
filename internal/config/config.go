// Package config defines every tunable setting of the gateway.
//
// A setting is resolved in this order: value saved from the admin panel,
// environment variable, built-in default.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"vpngw/internal/policy"
)

// Kind describes how a setting value is parsed and rendered.
type Kind int

const (
	String Kind = iota
	Int
	Bool
	Duration
	Secret
)

// Def is the static definition of a setting.
type Def struct {
	Key      string
	Default  string
	Kind     Kind
	Required bool
	Group    string
	Help     string
	// Restart means the change takes effect after the affected backend
	// (or the whole container) restarts.
	Restart bool
}

// Defs lists all settings. The key doubles as the environment variable name.
var Defs = []Def{
	{Key: "VPN_HOSTNAME", Group: "General", Restart: true, Help: "Public name of the VPN server. Empty: PORTAL_HOSTNAME."},
	{Key: "VPN_ENDPOINTS", Group: "General", Help: "Extra server addresses for clients: Name=host, host2."},
	{Key: "PORTAL_HOSTNAME", Required: true, Group: "General", Restart: true, Help: "Name of the portal and admin panel."},
	{Key: "NODE_NAME", Group: "General", Help: "Name of this gateway shown in the panel and to other sites. Empty: VPN_HOSTNAME."},
	{Key: "PORTAL_PORT", Default: "8443", Kind: Int, Group: "General", Restart: true, Help: "Portal port when it does not share 443 with AnyConnect."},
	{Key: "DATA_DIR", Default: "/data", Group: "General", Restart: true, Help: "State directory."},
	{Key: "CLIENTS_DIR", Default: "/usr/share/vpngw/clients", Group: "General", Help: "VPN client installers offered in the portal, listed in info.txt."},
	{Key: "LOG_LEVEL", Default: "info", Group: "General", Help: "debug, info, warn or error."},
	{Key: "DEV_MODE", Default: "false", Kind: Bool, Group: "General", Restart: true, Help: "Allow self-signed certificates."},

	{Key: "OIDC_ISSUER", Group: "OIDC", Restart: true, Help: "IdP issuer URL. Empty: tunnels only, no user VPN."},
	{Key: "OIDC_CLIENT_ID", Group: "OIDC", Restart: true},
	{Key: "OIDC_CLIENT_SECRET", Kind: Secret, Group: "OIDC", Restart: true},
	{Key: "OIDC_ID_TOKEN_DECRYPTION_KEY", Kind: Secret, Group: "OIDC", Restart: true, Help: "Private key if the IdP encrypts ID tokens."},
	{Key: "OIDC_SCOPES_EXTRA", Group: "OIDC", Help: "Additional scopes."},
	{Key: "OIDC_USERNAME_CLAIM", Default: "preferred_username", Group: "OIDC"},
	{Key: "OIDC_GROUPS_CLAIM", Default: "groups", Group: "OIDC"},
	{Key: "OIDC_ROUTES_CLAIM", Default: "vpn", Group: "OIDC", Help: "Claim with per-group vpnRoutes."},
	{Key: "OIDC_REVALIDATE_INTERVAL", Default: "5m", Kind: Duration, Group: "OIDC", Help: "How often sessions are checked with the IdP."},
	{Key: "OIDC_GRACE_PERIOD", Default: "15m", Kind: Duration, Group: "OIDC", Help: "How long sessions survive an IdP outage."},
	{Key: "OIDC_MAX_CONCURRENCY", Default: "10", Kind: Int, Group: "OIDC", Help: "Parallel IdP requests."},
	{Key: "OIDC_INTROSPECTION", Default: "false", Kind: Bool, Group: "OIDC", Help: "Also check access tokens (RFC 7662)."},
	{Key: "OIDC_LOGOUT", Default: "app", Group: "OIDC", Help: "Sign-out: app (back to this sign-in page; the IdP asks for the password next time) or idp (RP-initiated logout at the IdP)."},
	{Key: "ADMIN_GROUP", Group: "OIDC", Help: "IdP group with admin panel access."},
	{Key: "ADMIN_MAX_AUTH_AGE", Default: "12h", Kind: Duration, Group: "OIDC", Help: "Admin changes need a sign-in this recent."},

	{Key: "EMERGENCY_USER", Required: true, Group: "Admin", Restart: true, Help: "Local administrator, works without the IdP."},
	{Key: "EMERGENCY_PASS", Required: true, Kind: Secret, Group: "Admin", Restart: true},
	{Key: "EMERGENCY_ROUTES", Default: "0.0.0.0/0", Group: "Admin", Help: "Networks the local administrator may reach."},
	{Key: "EMERGENCY_GATEWAY", Group: "Admin", Help: "Tunnel peer for the administrator's internet."},
	{Key: "EMERGENCY_DOMAINS", Group: "Admin", Help: "Domains the administrator reaches through EMERGENCY_GATEWAY (like vpnDomains)."},

	{Key: "VPN_POOLS", Default: "anyconnect=10.250.0.0/20,openvpn=10.250.16.0/20,ikev2=10.250.32.0/20", Group: "Network", Restart: true, Help: "Client address pool per protocol."},
	{Key: "VPN_EGRESS_IFACE", Group: "Network", Help: "NAT interface. Empty: default route."},
	{Key: "VPN_DOMAIN_POOL", Default: "198.18.0.0/16", Group: "Network", Restart: true, Help: "Addresses the gateway's DNS gives to vpnDomains names; the first one is the DNS server."},
	{Key: "VPN_DNS", Group: "Network", Help: "DNS servers for clients without group DNS."},
	{Key: "VPN_DNS_DOMAIN", Group: "Network", Help: "DNS search domain."},
	{Key: "VPN_FULL_TUNNEL_DNS", Default: "1.1.1.1 1.0.0.1", Group: "Network", Help: "DNS for full-tunnel groups without vpnDNS and VPN_DNS. Empty: none."},
	{Key: "CLIENT_TO_CLIENT", Default: "false", Kind: Bool, Group: "Network", Help: "Allow traffic between VPN clients."},
	{Key: "DOCKER_COMPAT", Default: "true", Kind: Bool, Group: "Network", Help: "Allow forwarding past Docker's DROP policy."},
	{Key: "SESSION_LIMIT", Default: "3", Kind: Int, Group: "Network", Help: "VPN sessions per user."},
	{Key: "ANYCONNECT_ROUTE_LIMIT", Default: "200", Kind: Int, Group: "Network", Help: "Max split routes for AnyConnect; more are merged into wider ones (the firewall still allows only the exact networks)."},
	{Key: "OPENVPN_ROUTE_LIMIT", Default: "1000", Kind: Int, Group: "Network", Help: "Max routes pushed to OpenVPN clients (thousands make clients slow to connect); more are merged like ANYCONNECT_ROUTE_LIMIT."},
	{Key: "IKEV2_ROUTE_LIMIT", Default: "200", Kind: Int, Group: "Network", Help: "Max traffic selectors for IKEv2 (clients reject large IKE messages); more are merged like ANYCONNECT_ROUTE_LIMIT. Applies to new connections after a restart of IKEv2."},

	{Key: "ENABLE_ANYCONNECT", Default: "true", Kind: Bool, Group: "Protocols", Restart: true},
	{Key: "ENABLE_OPENVPN", Default: "true", Kind: Bool, Group: "Protocols", Restart: true},
	{Key: "ENABLE_IKEV2", Default: "true", Kind: Bool, Group: "Protocols", Restart: true},
	{Key: "OPENVPN_PORT", Default: "1194", Kind: Int, Group: "Protocols", Restart: true},
	{Key: "OPENVPN_PROTO", Default: "udp", Group: "Protocols", Restart: true, Help: "udp or tcp."},
	{Key: "OPENVPN_MTU", Default: "1420", Kind: Int, Group: "Protocols", Restart: true, Help: "Tunnel MTU pushed to clients; TCP MSS is clamped to MTU − 60."},
	{Key: "IKEV2_LOCAL_ID", Default: "auto", Group: "Protocols", Help: "IKEv2 server identity; auto picks a certificate name."},
	{Key: "IKEV2_KERNEL_LIBIPSEC", Default: "false", Kind: Bool, Group: "Protocols", Restart: true, Help: "Userspace IPsec instead of kernel XFRM."},

	{Key: "TUNNEL_PRIVATE_KEY", Kind: Secret, Group: "Tunnels", Restart: true, Help: "Node key. Empty: generated and stored."},
	{Key: "TUNNEL_ADDRESS", Group: "Tunnels", Restart: true, Help: "This node's tunnel address. Empty: 10.255.250.1, or 10.255.x.1 (x from the node key) with TUNNEL_LISTEN. Sites that connect here get addresses from its /24."},
	{Key: "TUNNEL_LISTEN", Group: "Tunnels", Restart: true, Help: "Accept sites on host:port. Empty: connect out only."},
	{Key: "TUNNEL_TRANSPORT", Default: "udp", Group: "Tunnels", Restart: true, Help: "udp, aead or tls."},
	{Key: "TUNNEL_PSK", Kind: Secret, Group: "Tunnels", Restart: true, Help: "Default pre-shared key."},
	{Key: "TUNNEL_MTU", Default: "1320", Kind: Int, Group: "Tunnels", Restart: true, Help: "Path MTU minus 52 (udp), same on both sides."},
	{Key: "TUNNEL_IFNAME", Default: "gp0", Group: "Tunnels", Restart: true, Help: "Node TUN name."},
	{Key: "TUNNEL_TLS_INSECURE", Default: "true", Kind: Bool, Group: "Tunnels", Restart: true, Help: "Accept self-signed certificates of tls peers."},
	{Key: "TUNNEL_TRANSIT_SOURCES", Group: "Tunnels", Help: "Local networks that use this node as gateway to the sites."},
	{Key: "TUNNEL_LOCAL_NETWORKS", Group: "Tunnels", Help: "This site's own networks besides ALLOW and TRANSIT_SOURCES: always via the host's routes, also with vpnGateway."},
	{Key: "TUNNEL_TRANSIT_GATEWAY", Group: "Tunnels", Help: "Internet exit site for TUNNEL_TRANSIT_SOURCES. Empty: the host's default gateway."},
	{Key: "TUNNEL_TRANSIT_DOMAINS", Group: "Tunnels", Help: "Domains TUNNEL_TRANSIT_SOURCES reach through TUNNEL_TRANSIT_DOMAINS_GATEWAY; their DNS server is the first address of VPN_DOMAIN_POOL."},
	{Key: "TUNNEL_TRANSIT_DOMAINS_GATEWAY", Group: "Tunnels", Help: "Exit site for TUNNEL_TRANSIT_DOMAINS. Empty: TUNNEL_TRANSIT_GATEWAY."},
	{Key: "TUNNEL_TRANSIT_DOMAINS_DNS", Group: "Tunnels", Help: "DNS servers that resolve TUNNEL_TRANSIT_DOMAINS, queried through their exit. Empty: this host's resolvers."},
	{Key: "TUNNEL_LOG_CONNECTIONS", Default: "false", Kind: Bool, Group: "Tunnels", Restart: true, Help: "Log every connection through tunnels."},

	{Key: "SOCKS_LISTEN", Group: "Proxy", Help: "SOCKS5 proxy on host:port, e.g. 0.0.0.0:1080. Empty: off."},
	{Key: "SOCKS_ALLOWED_NETWORKS", Group: "Proxy", Help: "Client networks that may use the proxy. Empty: nobody."},
	{Key: "SOCKS_GATEWAY", Group: "Proxy", Help: "Exit site for the proxy's connections (networks behind the sites always use their tunnels). Empty: the host's default gateway."},
	{Key: "SOCKS_DNS", Group: "Proxy", Help: "DNS servers that resolve names for proxy clients, queried like their connections. Empty: this host's resolvers."},

	{Key: "TLS_CERT_FILE", Group: "Certificates", Help: "PEM chain. Empty: DATA_DIR/tls/tls.crt."},
	{Key: "TLS_KEY_FILE", Group: "Certificates", Help: "Empty: DATA_DIR/tls/tls.key."},
	{Key: "ACME_ENABLED", Default: "false", Group: "Certificates", Help: "Let's Encrypt when there is no certificate file."},
	{Key: "ACME_EMAIL", Group: "Certificates"},
	{Key: "ACME_STAGING", Default: "false", Kind: Bool, Group: "Certificates", Help: "Use the Let's Encrypt staging CA."},

	{Key: "MASTER_KEY", Kind: Secret, Group: "Security", Restart: true, Help: "Encryption key. Empty: generated in DATA_DIR."},
	{Key: "AUTH_FAIL_LIMIT", Default: "10", Kind: Int, Group: "Security", Help: "Failed logins before blocking."},
	{Key: "AUTH_FAIL_WINDOW", Default: "5m", Kind: Duration, Group: "Security"},
	{Key: "AUTH_BLOCK_DURATION", Default: "15m", Kind: Duration, Group: "Security"},
	{Key: "AUDIT_RETENTION_DAYS", Default: "90", Kind: Int, Group: "Security"},
	{Key: "METRICS_ALLOWED_NETWORKS", Group: "Security", Help: "Networks that may read /metrics (e.g. Prometheus). Empty: localhost and METRICS_TOKEN only."},
	{Key: "METRICS_TOKEN", Kind: Secret, Group: "Security", Help: "Bearer token for /metrics; with allowed networks set, required in addition."},
}

var defIndex = func() map[string]*Def {
	m := make(map[string]*Def, len(Defs))
	for i := range Defs {
		m[Defs[i].Key] = &Defs[i]
	}
	return m
}()

// Lookup returns the definition of key.
func Lookup(key string) (*Def, bool) {
	d, ok := defIndex[key]
	return d, ok
}

// Source tells where a resolved value came from.
type Source string

const (
	SourceDefault Source = "default"
	SourceEnv     Source = "env"
	SourceAdmin   Source = "admin"
)

// Config holds resolved settings. It is safe for concurrent use.
type Config struct {
	mu       sync.RWMutex
	env      map[string]string
	override map[string]string
	onChange []func(keys []string)
}

// New builds a Config from the process environment.
func New() *Config {
	env := map[string]string{}
	for _, d := range Defs {
		if v, ok := os.LookupEnv(d.Key); ok {
			env[d.Key] = strings.TrimSpace(v)
		}
	}
	return &Config{env: env, override: map[string]string{}}
}

// NewFromMap builds a Config with explicit environment values (tests).
func NewFromMap(env map[string]string) *Config {
	c := &Config{env: map[string]string{}, override: map[string]string{}}
	for k, v := range env {
		c.env[k] = v
	}
	return c
}

// SetOverrides replaces admin overrides (loaded from the database).
func (c *Config) SetOverrides(m map[string]string) {
	c.mu.Lock()
	c.override = map[string]string{}
	for k, v := range m {
		if _, ok := defIndex[k]; ok {
			c.override[k] = v
		}
	}
	c.mu.Unlock()
}

// OnChange registers a callback for admin changes.
func (c *Config) OnChange(fn func(keys []string)) {
	c.mu.Lock()
	c.onChange = append(c.onChange, fn)
	c.mu.Unlock()
}

// Apply sets (value != nil) or clears (nil) admin overrides and notifies listeners.
func (c *Config) Apply(changes map[string]*string) error {
	for k, v := range changes {
		d, ok := defIndex[k]
		if !ok {
			return fmt.Errorf("unknown setting %s", k)
		}
		if _, env := c.EnvValue(k); env {
			return fmt.Errorf("%s is set in the environment and cannot be changed here", k)
		}
		if v != nil {
			if err := Validate(d, *v); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	}
	c.mu.Lock()
	keys := make([]string, 0, len(changes))
	for k, v := range changes {
		if v == nil {
			delete(c.override, k)
		} else {
			c.override[k] = *v
		}
		keys = append(keys, k)
	}
	cbs := append([]func([]string){}, c.onChange...)
	c.mu.Unlock()
	sort.Strings(keys)
	for _, fn := range cbs {
		fn(keys)
	}
	return nil
}

// Validate checks that v parses as the setting's kind.
func Validate(d *Def, v string) error {
	if v == "" {
		if d.Required {
			return fmt.Errorf("value required")
		}
		return nil
	}
	switch d.Kind {
	case Int:
		n, err := strconv.Atoi(v)
		if err != nil {
			return errors.New("a whole number")
		}
		if strings.HasSuffix(d.Key, "_PORT") && (n < 1 || n > 65535) {
			return errors.New("a port number 1-65535")
		}
		return nil
	case Bool:
		if _, err := strconv.ParseBool(v); err != nil {
			return errors.New("true or false")
		}
		return nil
	case Duration:
		if _, err := time.ParseDuration(v); err != nil {
			return errors.New("a duration such as 5m or 1h")
		}
		return nil
	}
	if d.Key == "VPN_POOLS" {
		_, err := ParsePools(v)
		return err
	}
	if d.Key == "TUNNEL_TRANSIT_SOURCES" || d.Key == "TUNNEL_LOCAL_NETWORKS" || d.Key == "METRICS_ALLOWED_NETWORKS" || d.Key == "SOCKS_ALLOWED_NETWORKS" {
		for _, item := range SplitList(v) {
			if p, err := netip.ParsePrefix(item); err != nil || !p.Addr().Is4() {
				return fmt.Errorf("%q: need IPv4 CIDRs", item)
			}
		}
		return nil
	}
	switch d.Key {
	case "VPN_DOMAIN_POOL":
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 24 {
			return errors.New("an IPv4 network from /8 to /24, e.g. 198.18.0.0/16")
		}
	case "EMERGENCY_DOMAINS", "TUNNEL_TRANSIT_DOMAINS":
		for _, item := range SplitList(v) {
			if _, err := policy.NormalizeDomain(item); err != nil {
				return err
			}
		}
	case "TUNNEL_TRANSPORT":
		if v != "udp" && v != "aead" && v != "tls" {
			return errors.New("udp, aead or tls")
		}
	case "LOG_LEVEL":
		if v != "debug" && v != "info" && v != "warn" && v != "error" {
			return errors.New("debug, info, warn or error")
		}
	case "TUNNEL_ADDRESS":
		if p, err := netip.ParsePrefix(v); err != nil || !p.Addr().Is4() {
			return errors.New("an IPv4 address with prefix, e.g. 10.255.250.1/32")
		}
	case "TUNNEL_LISTEN", "SOCKS_LISTEN":
		_, port, err := net.SplitHostPort(v)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
			return errors.New("host:port, e.g. 0.0.0.0:444")
		}
	case "EMERGENCY_GATEWAY", "TUNNEL_TRANSIT_GATEWAY", "TUNNEL_TRANSIT_DOMAINS_GATEWAY", "SOCKS_GATEWAY":
		return policy.ValidGateway(v)
	case "EMERGENCY_ROUTES":
		p, err := policy.Build("", []policy.GroupRoutes{{Routes: SplitList(v)}}, nil, "")
		if err != nil {
			return err
		}
		if len(p.Warnings) > 0 {
			return errors.New(strings.Join(p.Warnings, "; "))
		}
	}
	if d.Key == "VPN_DNS" || d.Key == "VPN_FULL_TUNNEL_DNS" || d.Key == "TUNNEL_TRANSIT_DOMAINS_DNS" || d.Key == "SOCKS_DNS" {
		for _, item := range SplitList(v) {
			if a, err := netip.ParseAddr(item); err != nil || !a.Is4() {
				return fmt.Errorf("%q: need IPv4 addresses", item)
			}
		}
		return nil
	}
	if d.Key == "OIDC_LOGOUT" && v != "app" && v != "idp" {
		return errors.New("app or idp")
	}
	if d.Key == "OPENVPN_PROTO" && v != "udp" && v != "tcp" {
		return errors.New("udp or tcp")
	}
	if d.Key == "VPN_ENDPOINTS" {
		_, err := ParseEndpoints(v)
		return err
	}
	return nil
}

// Resolve returns the value and its source.
func (c *Config) Resolve(key string) (string, Source) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// The environment is fixed: a value set there wins and cannot be
	// changed in the panel.
	if v, ok := c.env[key]; ok && v != "" {
		return v, SourceEnv
	}
	if v, ok := c.override[key]; ok {
		return v, SourceAdmin
	}
	if d, ok := defIndex[key]; ok {
		return d.Default, SourceDefault
	}
	return "", SourceDefault
}

// EnvValue returns the environment value of key, if set.
func (c *Config) EnvValue(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.env[key]
	return v, ok && v != ""
}

func (c *Config) Str(key string) string {
	v, _ := c.Resolve(key)
	if v == "" && key == "VPN_HOSTNAME" {
		v, _ = c.Resolve("PORTAL_HOSTNAME")
	}
	return v
}

// VPNEnabled reports whether user VPN (OIDC sign-in with AnyConnect,
// OpenVPN and IKEv2) is configured. Without it only tunnels run.
func (c *Config) VPNEnabled() bool { return c.Str("OIDC_ISSUER") != "" }

func (c *Config) Int(key string) int {
	v, _ := c.Resolve(key)
	n, err := strconv.Atoi(v)
	if err != nil {
		n, _ = strconv.Atoi(defIndex[key].Default)
	}
	return n
}

func (c *Config) Bool(key string) bool {
	v, _ := c.Resolve(key)
	b, err := strconv.ParseBool(v)
	if err != nil {
		b, _ = strconv.ParseBool(defIndex[key].Default)
	}
	return b
}

func (c *Config) Dur(key string) time.Duration {
	v, _ := c.Resolve(key)
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		d, _ = time.ParseDuration(defIndex[key].Default)
	}
	return d
}

// List splits a comma/space separated setting.
func (c *Config) List(key string) []string { return SplitList(c.Str(key)) }

// SplitList splits on commas and whitespace, dropping empty items.
func SplitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';' })
	out := f[:0]
	for _, x := range f {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// settingPrefixes are the first words of setting names: an unknown
// variable starting with one of them is most likely a typo.
var settingPrefixes = []string{"VPN_", "OIDC_", "TUNNEL_", "OPENVPN_", "IKEV2_", "ANYCONNECT_", "PORTAL_", "EMERGENCY_",
	"ACME_", "TLS_", "ADMIN_", "AUTH_", "ENABLE_", "SESSION_", "METRICS_", "NODE_"}

// CheckEnv validates the environment: every setting's value, and unknown
// variables that look like settings. Tunnel peers (TUNNEL_PEER_*) are
// checked by the tunnels package.
func CheckEnv(environ []string) []string {
	var problems []string
	sort.Strings(environ)
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if d, ok := defIndex[k]; ok {
			if err := Validate(d, strings.TrimSpace(v)); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", k, err))
			}
			continue
		}
		if strings.HasPrefix(k, "TUNNEL_PEER_") {
			continue
		}
		for _, pre := range settingPrefixes {
			if strings.HasPrefix(k, pre) {
				msg := "unknown setting " + k
				if s := Suggest(k, keys()); s != "" {
					msg += " (did you mean " + s + "?)"
				}
				problems = append(problems, msg)
				break
			}
		}
	}
	env := map[string]string{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = strings.TrimSpace(v)
	}
	if dp, err := netip.ParsePrefix(env["VPN_DOMAIN_POOL"]); err == nil {
		if pools, err := ParsePools(env["VPN_POOLS"]); err == nil {
			for _, p := range pools {
				if p.Overlaps(dp) {
					problems = append(problems, fmt.Sprintf("VPN_DOMAIN_POOL: overlaps the client pool %s", p))
					break
				}
			}
		}
	}
	return problems
}

func keys() []string {
	out := make([]string, 0, len(Defs))
	for _, d := range Defs {
		out = append(out, d.Key)
	}
	return out
}

// Suggest returns the candidate closest to s (a few edits at most), or "".
func Suggest(s string, candidates []string) string {
	best, bestD := "", 4
	for _, c := range candidates {
		if d := editDistance(s, c); d < bestD {
			best, bestD = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// CheckRequired returns the missing required settings.
func (c *Config) CheckRequired() []string {
	var missing []string
	for _, d := range Defs {
		if d.Required && c.Str(d.Key) == "" {
			missing = append(missing, d.Key)
		}
	}
	if c.VPNEnabled() {
		for _, k := range []string{"OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "ADMIN_GROUP"} {
			if c.Str(k) == "" {
				missing = append(missing, k+" (required with OIDC_ISSUER)")
			}
		}
	}
	return missing
}

// Protocols.
const (
	AnyConnect = "anyconnect"
	OpenVPN    = "openvpn"
	IKEv2      = "ikev2"
)

// Protocols lists protocol identifiers in display order.
var Protocols = []string{AnyConnect, OpenVPN, IKEv2}

// ProtocolTitle returns a human readable protocol name.
func ProtocolTitle(p string) string {
	switch p {
	case AnyConnect:
		return "AnyConnect"
	case OpenVPN:
		return "OpenVPN"
	case IKEv2:
		return "IKEv2"
	}
	return p
}

// ParsePools parses "proto=cidr,..." into a map.
func ParsePools(s string) (map[string]netip.Prefix, error) {
	out := map[string]netip.Prefix{
		AnyConnect: netip.MustParsePrefix("10.250.0.0/20"),
		OpenVPN:    netip.MustParsePrefix("10.250.16.0/20"),
		IKEv2:      netip.MustParsePrefix("10.250.32.0/20"),
	}
	for _, item := range SplitList(s) {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("pool %q: expected proto=cidr", item)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, known := out[k]; !known {
			return nil, fmt.Errorf("pool %q: unknown protocol", k)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(v))
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("pool %q: invalid IPv4 prefix", v)
		}
		if p.Bits() > 29 {
			return nil, fmt.Errorf("pool %q: prefix too small", v)
		}
		out[k] = p.Masked()
	}
	ps := []netip.Prefix{out[AnyConnect], out[OpenVPN], out[IKEv2]}
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			if ps[i].Overlaps(ps[j]) {
				return nil, fmt.Errorf("pools %s and %s overlap", ps[i], ps[j])
			}
		}
	}
	return out, nil
}

// Pools returns the configured pools.
func (c *Config) Pools() map[string]netip.Prefix {
	p, err := ParsePools(c.Str("VPN_POOLS"))
	if err != nil {
		p, _ = ParsePools("")
	}
	return p
}

// PortalSeparatePort reports whether the portal needs its own port: port
// 443 also serves AnyConnect, and both use the same name.
func (c *Config) PortalSeparatePort() bool {
	return c.VPNEnabled() && c.Bool("ENABLE_ANYCONNECT") && strings.EqualFold(c.Str("PORTAL_HOSTNAME"), c.Str("VPN_HOSTNAME"))
}

// PortalPort is the port the portal listens on; 443 means it shares port
// 443 with AnyConnect through the SNI router. Without user VPN nothing needs
// 443, so the portal stays on PORTAL_PORT.
func (c *Config) PortalPort() int {
	if !c.VPNEnabled() || c.PortalSeparatePort() {
		return c.Int("PORTAL_PORT")
	}
	return 443
}

// PortalURL is the external base URL of the portal.
// SiteName is how other sites (and vpnGateway values) name this node:
// NODE_NAME, or the first label of VPN_HOSTNAME, limited to letters,
// digits, '-' and '_'.
func (c *Config) SiteName() string {
	n := c.Str("NODE_NAME")
	if n == "" {
		n = strings.Split(c.Str("VPN_HOSTNAME"), ".")[0]
	}
	n = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, n)
	if len(n) > 32 {
		n = n[:32]
	}
	if n == "" {
		n = "GW"
	}
	return n
}

// IsSelf reports whether a gateway name (vpnGateway, TUNNEL_TRANSIT_GATEWAY)
// is this node: its traffic then leaves through the host's default route.
func (c *Config) IsSelf(gw string) bool { return gw != "" && strings.EqualFold(gw, c.SiteName()) }

// NodeName names this gateway in the panel and for other sites.
func (c *Config) NodeName() string {
	if n := c.Str("NODE_NAME"); n != "" {
		return n
	}
	return c.Str("VPN_HOSTNAME")
}

func (c *Config) PortalURL() string {
	h := c.Str("PORTAL_HOSTNAME")
	if p := c.PortalPort(); p != 443 {
		return fmt.Sprintf("https://%s:%d", h, p)
	}
	return "https://" + h
}

// Endpoint is an address clients connect to.
type Endpoint struct {
	Label string
	Host  string
}

// ParseEndpoints parses VPN_ENDPOINTS ("label=host" or "host" items).
func ParseEndpoints(s string) ([]Endpoint, error) {
	var out []Endpoint
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		label, host, ok := strings.Cut(item, "=")
		if !ok {
			label, host = "", item
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if !validHost(host) {
			return nil, fmt.Errorf("endpoint %q: not a host name or IPv4 address", host)
		}
		out = append(out, Endpoint{Label: strings.TrimSpace(label), Host: host})
	}
	return out, nil
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Is4()
	}
	for _, part := range strings.Split(h, ".") {
		if part == "" || len(part) > 63 {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Endpoints returns VPN_HOSTNAME followed by the extra endpoints, without duplicates.
func (c *Config) Endpoints() []Endpoint {
	out := []Endpoint{{Host: strings.ToLower(c.Str("VPN_HOSTNAME"))}}
	extra, _ := ParseEndpoints(c.Str("VPN_ENDPOINTS"))
	for _, e := range extra {
		if e.Host == out[0].Host {
			if e.Label != "" {
				out[0].Label = e.Label
			}
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o.Host == e.Host
		}
		if !dup {
			out = append(out, e)
		}
	}
	return out
}

// TransitSources returns TUNNEL_TRANSIT_SOURCES.
func (c *Config) TransitSources() []netip.Prefix { return c.prefixes("TUNNEL_TRANSIT_SOURCES") }

// MetricsNetworks returns METRICS_ALLOWED_NETWORKS.
func (c *Config) MetricsNetworks() []netip.Prefix { return c.prefixes("METRICS_ALLOWED_NETWORKS") }

// SocksNetworks returns the client networks of the SOCKS proxy.
func (c *Config) SocksNetworks() []netip.Prefix { return c.prefixes("SOCKS_ALLOWED_NETWORKS") }

// LocalNetworks returns TUNNEL_LOCAL_NETWORKS.
func (c *Config) LocalNetworks() []netip.Prefix { return c.prefixes("TUNNEL_LOCAL_NETWORKS") }

func (c *Config) prefixes(key string) []netip.Prefix {
	var out []netip.Prefix
	for _, item := range c.List(key) {
		if p, err := netip.ParsePrefix(item); err == nil && p.Addr().Is4() {
			out = append(out, p.Masked())
		}
	}
	return out
}

// DomainPool returns the domain proxy pool and its DNS server address (the
// first host); invalid when unset or overlapping a client pool.
func (c *Config) DomainPool() (netip.Prefix, netip.Addr) {
	p, err := netip.ParsePrefix(c.Str("VPN_DOMAIN_POOL"))
	if err != nil || !p.Addr().Is4() || p.Bits() > 24 {
		return netip.Prefix{}, netip.Addr{}
	}
	p = p.Masked()
	for _, pool := range c.Pools() {
		if pool.Overlaps(p) {
			return netip.Prefix{}, netip.Addr{}
		}
	}
	return p, p.Addr().Next()
}

// TransitDomains returns TUNNEL_TRANSIT_DOMAINS, normalized.
func (c *Config) TransitDomains() []string {
	var out []string
	for _, d := range c.List("TUNNEL_TRANSIT_DOMAINS") {
		if n, err := policy.NormalizeDomain(d); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// TransitDomainsGateway is the exit of TUNNEL_TRANSIT_DOMAINS: its own
// setting, else TUNNEL_TRANSIT_GATEWAY; "" means the host's routes (also
// when it names this node).
func (c *Config) TransitDomainsGateway() string {
	gw := c.Str("TUNNEL_TRANSIT_DOMAINS_GATEWAY")
	if gw == "" {
		gw = c.Str("TUNNEL_TRANSIT_GATEWAY")
	}
	if c.IsSelf(gw) {
		return ""
	}
	return gw
}

// DNS returns the default DNS servers.
func (c *Config) DNS() []netip.Addr { return c.Addrs("VPN_DNS") }

// Addrs parses a list of IPv4 addresses (invalid items are skipped).
func (c *Config) Addrs(key string) []netip.Addr {
	var out []netip.Addr
	for _, s := range c.List(key) {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			out = append(out, a)
		}
	}
	return out
}
