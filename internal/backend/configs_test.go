package backend

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestGolden(t *testing.T) {
	cases := map[string]map[string]any{
		"ocserv.conf.tmpl": {
			"Dir": "/data/run/ocserv", "RunDir": "/run/vpngw/ocserv", "TCPPort": 4443, "UDPPort": 443,
			"CertFile": "/data/run/tls/server.crt", "KeyFile": "/data/run/tls/server.key",
			"PoolNetwork": "10.250.0.0", "PoolNetmask": "255.255.240.0", "ProfileFile": "vpn.example.com.xml",
		},
		"ocserv-radiusclient.conf.tmpl": {"NASIdentifier": "vpngw-anyconnect", "AuthServer": "127.0.0.1:1812", "AcctServer": "127.0.0.1:1813", "Dir": "/data/run/ocserv"},
		"openvpn.conf.tmpl": {
			"Port": 1194, "Proto": "udp", "MTU": 1420, "MSS": 1360, "Device": "vpngw-ovpn", "PoolNetwork": "10.250.16.0", "PoolNetmask": "255.255.240.0",
			"Dir": "/data/openvpn", "VerifyCommand": "/usr/local/bin/vpngw tls-verify", "ManagementSocket": "/run/vpngw/openvpn.sock",
			"CertNote": "certificate of the portal (Let's Encrypt), clients trust ISRG Root X1", "CAFile": "/data/openvpn/ca.crt",
			"CertFile": "/data/run/tls/server.crt", "KeyFile": "/data/run/tls/server.key", "DHFile": "/data/openvpn/dh.pem",
		},
		"strongswan.conf.tmpl": {
			"ViciSocket": "/run/vpngw/charon.vici", "NASIdentifier": "vpngw-ikev2", "AuthPort": 1812, "AcctPort": 1813,
			"Secret": "RADIUS-SECRET", "KernelLibipsec": false,
		},
	}
	for name, data := range cases {
		got, err := Render(name, data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		golden := filepath.Join("testdata", name+".golden")
		if *update {
			_ = os.MkdirAll("testdata", 0o755)
			if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%s: %v (run go test -update)", name, err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s:\n%s", name, golden, got)
		}
	}
}
