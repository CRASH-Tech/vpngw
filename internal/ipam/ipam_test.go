package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func TestPool(t *testing.T) {
	p := NewPool(netip.MustParsePrefix("10.250.0.0/29"))
	if p.Size() != 5 || p.Gateway().String() != "10.250.0.1" {
		t.Fatalf("size %d gateway %s", p.Size(), p.Gateway())
	}
	seen := map[netip.Addr]bool{}
	for i := 0; i < 5; i++ {
		a, err := p.Allocate("u")
		if err != nil {
			t.Fatal(err)
		}
		if seen[a] || a.String() == "10.250.0.0" || a.String() == "10.250.0.1" || a.String() == "10.250.0.7" {
			t.Fatalf("bad address %s", a)
		}
		seen[a] = true
	}
	if _, err := p.Allocate("u"); !errors.Is(err, ErrExhausted) {
		t.Fatal("pool must be exhausted")
	}
	p.Release(netip.MustParseAddr("10.250.0.4"))
	if a, err := p.Allocate("v"); err != nil || a.String() != "10.250.0.4" {
		t.Fatalf("reuse after release: %s %v", a, err)
	}
	if err := p.Reserve(netip.MustParseAddr("10.250.1.1"), "x"); err == nil {
		t.Fatal("reserve outside the pool must fail")
	}
}

func TestIPAM(t *testing.T) {
	m := New(map[string]netip.Prefix{"openvpn": netip.MustParsePrefix("10.250.16.0/20"), "ikev2": netip.MustParsePrefix("10.250.32.0/20")})
	a, _ := m.Pool("openvpn").Allocate("x")
	if proto, ok := m.ProtocolOf(a); !ok || proto != "openvpn" {
		t.Fatalf("ProtocolOf(%s) = %s", a, proto)
	}
	// Round robin: the next allocation is a different address.
	b, _ := m.Pool("openvpn").Allocate("y")
	m.Pool("openvpn").Release(a)
	c, _ := m.Pool("openvpn").Allocate("z")
	if a == b || c == a {
		t.Fatalf("addresses must not be reused immediately: %s %s %s", a, b, c)
	}
}
