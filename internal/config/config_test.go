package config

import (
	"strings"
	"testing"
	"time"
)

func TestResolveOrder(t *testing.T) {
	c := NewFromMap(map[string]string{"SESSION_LIMIT": "5"})
	if v, src := c.Resolve("SESSION_LIMIT"); v != "5" || src != SourceEnv {
		t.Fatalf("env: %s %s", v, src)
	}
	if v, src := c.Resolve("OIDC_GRACE_PERIOD"); v != "15m" || src != SourceDefault {
		t.Fatalf("default: %s %s", v, src)
	}
	var changed []string
	c.OnChange(func(k []string) { changed = k })
	v := "7"
	if err := c.Apply(map[string]*string{"SESSION_LIMIT": &v}); err == nil || c.Int("SESSION_LIMIT") != 5 {
		t.Fatal("a setting from the environment must be fixed")
	}
	c.SetOverrides(map[string]string{"SESSION_LIMIT": "9"})
	if c.Int("SESSION_LIMIT") != 5 {
		t.Fatal("environment must win over a stored value")
	}
	if err := c.Apply(map[string]*string{"OIDC_GRACE_PERIOD": &v}); err == nil {
		t.Fatal("invalid duration must be rejected")
	}
	g := "30m"
	if err := c.Apply(map[string]*string{"OIDC_GRACE_PERIOD": &g}); err != nil || c.Dur("OIDC_GRACE_PERIOD") != 30*time.Minute || len(changed) != 1 {
		t.Fatal("admin value must apply")
	}
	if err := c.Apply(map[string]*string{"OIDC_GRACE_PERIOD": nil}); err != nil || c.Dur("OIDC_GRACE_PERIOD") != 15*time.Minute {
		t.Fatal("reset must return to the default")
	}
	bad := "abc"
	if err := c.Apply(map[string]*string{"OIDC_MAX_CONCURRENCY": &bad}); err == nil {
		t.Fatal("invalid int must be rejected")
	}
	if c.Dur("OIDC_REVALIDATE_INTERVAL") != 5*time.Minute {
		t.Fatal("duration default")
	}
}

func TestPools(t *testing.T) {
	p, err := ParsePools("openvpn=10.99.0.0/24")
	if err != nil || p[OpenVPN].String() != "10.99.0.0/24" || p[AnyConnect].String() != "10.250.0.0/20" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := ParsePools("openvpn=10.250.0.0/24"); err == nil {
		t.Fatal("overlapping pools must be rejected")
	}
	if _, err := ParsePools("ftp=10.1.0.0/24"); err == nil {
		t.Fatal("unknown protocol must be rejected")
	}
}

func TestPortalURL(t *testing.T) {
	c := NewFromMap(map[string]string{"VPN_HOSTNAME": "vpn.x", "PORTAL_HOSTNAME": "vpn.x", "OIDC_ISSUER": "https://idp"})
	if c.PortalURL() != "https://vpn.x:8443" {
		t.Fatal(c.PortalURL())
	}
	c = NewFromMap(map[string]string{"VPN_HOSTNAME": "vpn.x", "PORTAL_HOSTNAME": "portal.x", "OIDC_ISSUER": "https://idp"})
	if c.PortalURL() != "https://portal.x" {
		t.Fatal(c.PortalURL())
	}
}

func TestEndpoints(t *testing.T) {
	c := NewFromMap(map[string]string{"VPN_HOSTNAME": "vpn.x", "VPN_ENDPOINTS": "Riga=VPN-Riga.x, vpn2.x, vpn.x, Main=vpn.x, 192.0.2.10"})
	eps := c.Endpoints()
	if len(eps) != 4 || eps[0] != (Endpoint{"Main", "vpn.x"}) || eps[1] != (Endpoint{"Riga", "vpn-riga.x"}) || eps[3].Host != "192.0.2.10" {
		t.Fatalf("%+v", eps)
	}
	for _, bad := range []string{"a b", "x=", "ex ample.com", "::1"} {
		if _, err := ParseEndpoints(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestTunnelsOnlyMode(t *testing.T) {
	c := NewFromMap(map[string]string{"PORTAL_HOSTNAME": "gw.x", "EMERGENCY_USER": "a", "EMERGENCY_PASS": "b"})
	if c.VPNEnabled() || len(c.CheckRequired()) != 0 || c.Str("VPN_HOSTNAME") != "gw.x" || c.PortalURL() != "https://gw.x:8443" {
		t.Fatalf("tunnels-only: vpn=%v missing=%v url=%s", c.VPNEnabled(), c.CheckRequired(), c.PortalURL())
	}
	c = NewFromMap(map[string]string{"PORTAL_HOSTNAME": "gw.x", "EMERGENCY_USER": "a", "EMERGENCY_PASS": "b", "OIDC_ISSUER": "https://idp"})
	if !c.VPNEnabled() || len(c.CheckRequired()) != 3 || c.PortalURL() != "https://gw.x:8443" {
		t.Fatalf("vpn: missing=%v url=%s", c.CheckRequired(), c.PortalURL())
	}
}

func TestCheckEnv(t *testing.T) {
	problems := CheckEnv([]string{
		"PATH=/usr/bin", "HOSTNAME=x", // not ours
		"OPENVPN_PROTO=tcp", "OPENVPN_PORT=444", "LOG_LEVEL=debug", // fine
		"OPENVPN_PORT=70000", "OPENVPN_PROTO=sctp", "LOG_LEVEL=loud", "ENABLE_IKEV2=yes", "OIDC_REVALIDATE_INTERVAL=5",
		"TUNNEL_TRANSPORT=quic", "TUNNEL_LISTEN=444", "EMERGENCY_ROUTES=10.0.0.0/33", "EMERGENCY_GATEWAY=bad name",
		"OPENVPN_PROTOCOL=tcp",             // typo
		"TUNNEL_PEER_X_SUBNETS=10.0.0.0/8", // checked by the tunnels package
	})
	want := []string{"OPENVPN_PORT: a port number", "OPENVPN_PROTO: udp or tcp", "LOG_LEVEL: debug, info", "ENABLE_IKEV2: true or false",
		"OIDC_REVALIDATE_INTERVAL: a duration", "TUNNEL_TRANSPORT: udp, aead or tls", "TUNNEL_LISTEN: host:port",
		"EMERGENCY_ROUTES:", "EMERGENCY_GATEWAY:", "unknown setting OPENVPN_PROTOCOL (did you mean OPENVPN_PROTO?)"}
	all := strings.Join(problems, "\n")
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Errorf("missing %q in:\n%s", w, all)
		}
	}
	if len(problems) != len(want) {
		t.Errorf("%d problems, want %d:\n%s", len(problems), len(want), all)
	}
}

func TestSiteName(t *testing.T) {
	c := NewFromMap(map[string]string{"VPN_HOSTNAME": "gw-lat.example.com"})
	if c.SiteName() != "gw-lat" || !c.IsSelf("GW-LAT") || c.IsSelf("") {
		t.Fatalf("site name from the host name: %q", c.SiteName())
	}
	c = NewFromMap(map[string]string{"VPN_HOSTNAME": "gw-lat.example.com", "NODE_NAME": "LV-EXIT"})
	if c.SiteName() != "LV-EXIT" || !c.IsSelf("lv-exit") || c.IsSelf("KZ-EXIT") {
		t.Fatalf("NODE_NAME wins: %q", c.SiteName())
	}
}
