package dnsproxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"vpngw/internal/policy"
)

type writer struct {
	remote net.Addr
	msg    *dns.Msg
}

func (w *writer) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *writer) RemoteAddr() net.Addr        { return w.remote }
func (w *writer) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *writer) Write(b []byte) (int, error) { return len(b), nil }
func (w *writer) Close() error                { return nil }
func (w *writer) TsigStatus() error           { return nil }
func (w *writer) TsigTimersOnly(bool)         {}
func (w *writer) Hijack()                     {}

type query struct {
	name, server string
	mark         uint32
}

var grants []string

func newServer(t *testing.T) (*Server, map[netip.Addr]netip.Addr, *[]query) {
	nat := map[netip.Addr]netip.Addr{}
	grants = nil
	var queries []query
	clients := map[netip.Addr]Policy{
		netip.MustParseAddr("10.250.0.2"): {Domains: policy.NewDomainSet([]string{"example.com", "!skip.example.com"}), Upstream: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, Gateway: "lat", Mark: 0x76670001},
		netip.MustParseAddr("10.250.0.3"): {Domains: policy.NewDomainSet([]string{"example.com"}), Gateway: "kz", Mark: 0x76670002},
	}
	s := &Server{
		Pool:       netip.MustParsePrefix("198.18.0.0/16"),
		Lookup:     func(c netip.Addr) (Policy, bool) { p, ok := clients[c]; return p, ok },
		Forwarders: func() []string { return []string{"127.0.0.53:53"} },
		Map:        func(f, r netip.Addr) error { nat[f] = r; return nil },
		Grant: func(c, f netip.Addr) error {
			grants = append(grants, c.String()+" "+f.String())
			return nil
		},
		Unmap: func(fs []netip.Addr) error {
			for _, f := range fs {
				delete(nat, f)
			}
			return nil
		},
		Exchange: func(_ context.Context, m *dns.Msg, server string, mark uint32) (*dns.Msg, error) {
			q := m.Question[0]
			queries = append(queries, query{q.Name, server, mark})
			r := new(dns.Msg)
			r.SetReply(m)
			switch q.Name {
			case "missing.example.com.":
				r.Rcode = dns.RcodeNameError
			case "v6only.example.com.":
			default:
				r.Answer = []dns.RR{
					&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "edge.cdn.net."},
					&dns.A{Hdr: dns.RR_Header{Name: "edge.cdn.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.IPv4(93, 184, 216, 34)},
				}
			}
			return r, nil
		},
	}
	return s, nat, &queries
}

func ask(s *Server, client, name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	w := &writer{remote: &net.UDPAddr{IP: net.ParseIP(client), Port: 5000}}
	s.ServeDNS(w, m)
	return w.msg
}

func TestDomainProxy(t *testing.T) {
	s, nat, queries := newServer(t)
	r := ask(s, "10.250.0.2", "WWW.Example.com.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("answer: %v", r)
	}
	fake, _ := netip.AddrFromSlice(r.Answer[0].(*dns.A).A.To4())
	if !s.Pool.Contains(fake) || fake == s.Pool.Addr().Next() || nat[fake].String() != "93.184.216.34" {
		t.Fatalf("fake %s nat %v", fake, nat)
	}
	if len(grants) != 1 || grants[0] != "10.250.0.2 "+fake.String() {
		t.Fatalf("the client must be granted its address: %v", grants)
	}
	if q := (*queries)[0]; q.server != "8.8.8.8:53" || q.mark != 0x76670001 {
		t.Fatalf("upstream query %+v", q)
	}
	// Cached for the record's TTL: same address, no new query.
	r2 := ask(s, "10.250.0.2", "www.example.com.", dns.TypeA)
	if r2.Answer[0].(*dns.A).A.String() != fake.String() || len(*queries) != 1 {
		t.Fatal("second answer must be cached")
	}
	// Another gateway: another address, the host's resolvers.
	r3 := ask(s, "10.250.0.3", "www.example.com.", dns.TypeA)
	if r3.Answer[0].(*dns.A).A.String() == fake.String() || (*queries)[1].server != "127.0.0.53:53" || (*queries)[1].mark != 0x76670002 {
		t.Fatalf("other gateway: %v %+v", r3.Answer, (*queries)[1])
	}
	if r := ask(s, "10.250.0.2", "www.example.com.", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatal("AAAA must be empty")
	}
	if r := ask(s, "10.250.0.2", "missing.example.com.", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatal("NXDOMAIN must pass through")
	}
	if r := ask(s, "10.250.0.2", "v6only.example.com.", dns.TypeA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatal("no IPv4 address: empty answer")
	}
	// Other names go to the forwarders unchanged, without a mark.
	n := len(*queries)
	if r := ask(s, "10.250.0.2", "other.org.", dns.TypeA); len(r.Answer) != 2 || (*queries)[n].server != "127.0.0.53:53" || (*queries)[n].mark != 0 {
		t.Fatalf("forward: %v %+v", r, (*queries)[n])
	}
	n = len(*queries)
	if r := ask(s, "10.250.0.2", "a.skip.example.com.", dns.TypeA); len(r.Answer) != 2 || (*queries)[n].server != "127.0.0.53:53" || (*queries)[n].mark != 0 {
		t.Fatalf("excluded name must be forwarded: %v", r)
	}
	if r := ask(s, "10.250.9.9", "www.example.com.", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Fatal("unknown clients are refused")
	}
	// Idle translations are removed.
	s.Idle = time.Nanosecond
	time.Sleep(time.Millisecond)
	s.GC()
	if len(nat) != 0 || len(s.Mappings()) != 0 {
		t.Fatalf("gc: %v", nat)
	}
}

func TestAllocateStable(t *testing.T) {
	s, _, _ := newServer(t)
	s.Pool = netip.MustParsePrefix("198.18.0.0/29") // 5 usable addresses
	s.init()
	a, _ := s.entryFor("a.example.com", Policy{})
	s2, _, _ := newServer(t)
	s2.Pool = s.Pool
	s2.init()
	b, _ := s2.entryFor("a.example.com", Policy{})
	if a.addr != b.addr {
		t.Fatal("same name, same address")
	}
	seen := map[netip.Addr]bool{}
	for _, n := range []string{"1.x", "2.x", "3.x", "4.x", "5.x", "6.x"} {
		e, err := s.entryFor(n, Policy{})
		if err != nil {
			t.Fatal(err)
		}
		first, last := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.6")
		if e.addr.Less(first) || last.Less(e.addr) {
			t.Fatalf("address %s outside hosts", e.addr)
		}
		seen[e.addr] = true
	}
	if len(s.byKey) != 5 || len(seen) != 5 {
		t.Fatalf("full pool reuses the least recently used: %d %d", len(s.byKey), len(seen))
	}
}
