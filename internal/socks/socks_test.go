package socks

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// start runs a proxy for clients from 127.0.0.0/8 that may reach the test
// targets on loopback.
func start(t *testing.T, s *Server) string {
	t.Helper()
	s.allowLocal = true
	if s.Allowed == nil {
		s.Allowed = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} }
	}
	if s.Mark == nil {
		s.Mark = func(netip.Addr) uint32 { return 0 } // SO_MARK needs CAP_NET_ADMIN
	}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s.ln.Addr().String()
}

func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// connect sends a greeting and a request; it returns the connection and
// the reply code (0xff: the method was refused, -1: closed at once).
func connect(t *testing.T, proxy string, methods []byte, cmd byte, dst []byte, port uint16) (net.Conn, int) {
	t.Helper()
	c, err := net.Dial("tcp4", proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(append([]byte{5, byte(len(methods))}, methods...))
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return c, -1
	}
	if sel[1] != methodNone {
		return c, int(sel[1])
	}
	req := append([]byte{5, cmd, 0}, dst...)
	req = binary.BigEndian.AppendUint16(req, port)
	_, _ = c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return c, -1
	}
	return c, int(rep[1])
}

func ipv4(a netip.Addr) []byte { b := a.As4(); return append([]byte{atypIPv4}, b[:]...) }

func domain(name string) []byte { return append([]byte{atypDomain, byte(len(name))}, name...) }

func TestConnect(t *testing.T) {
	echo := echoServer(t)
	var mu sync.Mutex
	var marked []netip.Addr
	proxy := start(t, &Server{Mark: func(dst netip.Addr) uint32 {
		mu.Lock()
		defer mu.Unlock()
		marked = append(marked, dst)
		return 0
	}})
	c, code := connect(t, proxy, []byte{2, methodNone}, cmdConnect, ipv4(echo.Addr()), echo.Port())
	if code != repOK {
		t.Fatalf("reply %d", code)
	}
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay: %q %v", buf, err)
	}
	// Half close: the client ends its writes and still gets the rest.
	_ = c.(*net.TCPConn).CloseWrite()
	if n, err := c.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("after half close: %d %v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(marked) != 1 || marked[0] != echo.Addr() {
		t.Fatalf("mark asked for %v", marked)
	}
}

func TestRefusals(t *testing.T) {
	echo := echoServer(t)
	proxy := start(t, &Server{Denied: func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.2") }})
	if _, code := connect(t, proxy, []byte{2}, cmdConnect, ipv4(echo.Addr()), echo.Port()); code != methodBad {
		t.Errorf("username/password only: %d", code)
	}
	if _, code := connect(t, proxy, []byte{methodNone}, 0x02, ipv4(echo.Addr()), echo.Port()); code != repCmdNotSupported {
		t.Errorf("BIND: %d", code)
	}
	if _, code := connect(t, proxy, []byte{methodNone}, cmdConnect, append([]byte{atypIPv6}, make([]byte, 16)...), 80); code != repAddrNotSupported {
		t.Errorf("IPv6: %d", code)
	}
	if _, code := connect(t, proxy, []byte{methodNone}, cmdConnect, ipv4(netip.MustParseAddr("127.0.0.2")), echo.Port()); code != repNotAllowed {
		t.Errorf("denied destination: %d", code)
	}
	for _, a := range []string{"0.0.0.0", "169.254.1.1", "224.0.0.1", "255.255.255.255"} {
		if _, code := connect(t, proxy, []byte{methodNone}, cmdConnect, ipv4(netip.MustParseAddr(a)), 80); code != repNotAllowed {
			t.Errorf("%s: %d", a, code)
		}
	}
	ln, _ := net.Listen("tcp4", "127.0.0.1:0") // a port nobody listens on any more
	port := ln.Addr().(*net.TCPAddr).AddrPort().Port()
	ln.Close()
	if _, code := connect(t, proxy, []byte{methodNone}, cmdConnect, ipv4(echo.Addr()), port); code != repRefused {
		t.Errorf("closed port: %d", code)
	}
}

func TestClientNotAllowed(t *testing.T) {
	proxy := start(t, &Server{Allowed: func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")} }})
	if _, code := connect(t, proxy, []byte{methodNone}, cmdConnect, ipv4(netip.MustParseAddr("127.0.0.1")), 80); code != -1 {
		t.Fatalf("a client outside the allowed networks must be disconnected, got %d", code)
	}
}

func TestNamesResolvedByTheConfiguredServer(t *testing.T) {
	echo := echoServer(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "echo.test." && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "echo.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IP(echo.Addr().AsSlice())})
		} else if r.Question[0].Qtype == dns.TypeA {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	proxy := start(t, &Server{Resolvers: func() []string { return []string{pc.LocalAddr().String()} }})
	c, code := connect(t, proxy, []byte{methodNone}, cmdConnect, domain("echo.test"), echo.Port())
	if code != repOK {
		t.Fatalf("reply %d", code)
	}
	_, _ = c.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("relay: %q %v", buf, err)
	}
	if _, code := connect(t, proxy, []byte{methodNone}, cmdConnect, domain("nx.test"), 80); code != repHostUnreachable {
		t.Errorf("unknown name: %d", code)
	}
}

func TestLocalAddressesRefused(t *testing.T) {
	if !isLocal(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("loopback must be refused")
	}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok && n.IP.To4() != nil {
			a, _ := netip.AddrFromSlice(n.IP.To4())
			if !isLocal(a) {
				t.Errorf("host address %s must be refused", a)
			}
		}
	}
	if isLocal(netip.MustParseAddr("192.0.2.1")) {
		t.Error("a foreign address is not local")
	}
}
