// Package dnsproxy is the gateway's DNS server for profiles with
// vpnDomains. A listed name (or a subdomain) gets an address from the
// domain pool; the gateway resolves the real address through the profile's
// gateway with its upstream servers and the firewall translates the pool
// address to it, so the connection leaves through that gateway. Other
// names are forwarded to the gateway's resolvers.
package dnsproxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"vpngw/internal/policy"
)

// Port is the local port the firewall redirects the DNS server to.
const Port = 15053

// Policy is what the DNS server needs to know about a client.
type Policy struct {
	Domains  *policy.DomainSet
	Upstream []netip.Addr // servers for Domains; empty: Forwarders
	Gateway  string       // vpnGateway (part of the address key)
	Mark     uint32       // SO_MARK of upstream queries: the gateway's route
}

// Server answers VPN clients with domain profiles.
type Server struct {
	Pool netip.Prefix // domain pool; its first host is the DNS server
	// Lookup returns the policy of a client address; false: refused.
	Lookup func(client netip.Addr) (Policy, bool)
	// Forwarders resolve other names (host:port).
	Forwarders func() []string
	// Map and Unmap program the firewall translation; Grant lets one
	// client use a pool address it was given (no other client can).
	Map   func(fake, real netip.Addr) error
	Unmap func(fakes []netip.Addr) error
	Grant func(client, fake netip.Addr) error
	TTL   time.Duration // TTL of pool answers (default 30s)
	Idle  time.Duration // translations unused this long are removed (default 1h)

	// Exchange sends a query (tests replace it).
	Exchange func(ctx context.Context, m *dns.Msg, server string, mark uint32) (*dns.Msg, error)

	mu     sync.Mutex
	byKey  map[string]*entry
	byAddr map[netip.Addr]*entry
	srv    []*dns.Server
}

type entry struct {
	key, name string
	addr      netip.Addr

	mu      sync.Mutex // one resolution at a time
	real    netip.Addr
	rcode   int
	expires time.Time
	used    time.Time
}

// Mapping is one name with its pool and real addresses (admin panel).
type Mapping struct {
	Name, Gateway string
	Addr, Real    netip.Addr
	Used          time.Time
}

func (s *Server) init() {
	if s.byKey == nil {
		s.byKey, s.byAddr = map[string]*entry{}, map[netip.Addr]*entry{}
	}
	if s.TTL == 0 {
		s.TTL = 30 * time.Second
	}
	if s.Idle == 0 {
		s.Idle = time.Hour
	}
	if s.Exchange == nil {
		s.Exchange = exchange
	}
}

// Start listens on UDP and TCP port Port and removes idle translations
// until ctx ends.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.init()
	s.mu.Unlock()
	addr := fmt.Sprintf(":%d", Port)
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		pc.Close()
		return err
	}
	s.srv = []*dns.Server{{PacketConn: pc, Handler: s}, {Listener: ln, Handler: s}}
	for _, srv := range s.srv {
		go func() {
			if err := srv.ActivateAndServe(); err != nil && ctx.Err() == nil {
				slog.Error("domain proxy DNS server stopped", "err", err)
			}
		}()
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				for _, srv := range s.srv {
					_ = srv.Shutdown()
				}
				return
			case <-t.C:
				s.GC()
			}
		}
	}()
	return nil
}

// GC removes translations unused for Idle.
func (s *Server) GC() {
	s.mu.Lock()
	var old []netip.Addr
	cutoff := time.Now().Add(-s.Idle)
	for k, e := range s.byKey {
		e.mu.Lock()
		idle := e.used.Before(cutoff)
		e.mu.Unlock()
		if idle {
			old = append(old, e.addr)
			delete(s.byKey, k)
			delete(s.byAddr, e.addr)
		}
	}
	s.mu.Unlock()
	if len(old) > 0 && s.Unmap != nil {
		if err := s.Unmap(old); err != nil {
			slog.Warn("domain proxy: remove translations", "err", err)
		}
	}
}

// Mappings lists the current translations.
func (s *Server) Mappings() []Mapping {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Mapping, 0, len(s.byKey))
	for _, e := range s.byKey {
		e.mu.Lock()
		gw := strings.SplitN(e.key, "|", 3)[1]
		out = append(out, Mapping{Name: e.name, Gateway: gw, Addr: e.addr, Real: e.real, Used: e.used})
		e.mu.Unlock()
	}
	return out
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	client := addrOf(w.RemoteAddr())
	pol, ok := s.Lookup(client)
	if !ok || len(r.Question) != 1 {
		s.reply(w, r, dns.RcodeRefused)
		return
	}
	q := r.Question[0]
	if q.Qclass == dns.ClassINET && pol.Domains.Match(q.Name) {
		switch q.Qtype {
		case dns.TypeA:
			s.answerA(w, r, pol, client)
			return
		case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
			// IPv4 only; HTTPS records could carry real address hints.
			s.reply(w, r, dns.RcodeSuccess)
			return
		}
		s.forward(w, r, servers(pol.Upstream, s.Forwarders), pol.Mark)
		return
	}
	s.forward(w, r, s.Forwarders(), 0)
}

func servers(up []netip.Addr, def func() []string) []string {
	if len(up) == 0 {
		return def()
	}
	out := make([]string, len(up))
	for i, a := range up {
		out[i] = net.JoinHostPort(a.String(), "53")
	}
	return out
}

func (s *Server) answerA(w dns.ResponseWriter, r *dns.Msg, pol Policy, client netip.Addr) {
	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	e, err := s.entryFor(name, pol)
	if err != nil {
		slog.Warn("domain proxy: no address", "name", name, "err", err)
		s.reply(w, r, dns.RcodeServerFailure)
		return
	}
	rcode, real, err := s.resolve(e, pol)
	if err != nil {
		slog.Warn("domain proxy: resolve", "name", name, "gateway", pol.Gateway, "err", err)
		s.reply(w, r, dns.RcodeServerFailure)
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.Rcode = rcode
	if rcode == dns.RcodeSuccess && real.IsValid() {
		if s.Grant != nil {
			if err := s.Grant(client, e.addr); err != nil {
				slog.Warn("domain proxy: grant", "name", name, "client", client, "err", err)
				s.reply(w, r, dns.RcodeServerFailure)
				return
			}
		}
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(s.TTL / time.Second)},
			A: net.IP(e.addr.AsSlice())}}
	}
	_ = w.WriteMsg(m)
}

// entryFor returns the pool address of a name for a gateway and upstream
// set: the same name through another gateway needs its own address.
func (s *Server) entryFor(name string, pol Policy) (*entry, error) {
	ups := make([]string, len(pol.Upstream))
	for i, u := range pol.Upstream {
		ups[i] = u.String()
	}
	key := name + "|" + pol.Gateway + "|" + strings.Join(ups, ",")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if e, ok := s.byKey[key]; ok {
		return e, nil
	}
	addr, ok := s.allocate(key)
	if !ok {
		return nil, errors.New("domain pool is full")
	}
	e := &entry{key: key, name: name, addr: addr, used: time.Now()}
	s.byKey[key], s.byAddr[addr] = e, e
	return e, nil
}

// allocate picks a free pool address from the key's hash, so a name keeps
// its address across restarts; when the pool is full the least recently
// used one is taken over. Called with s.mu held.
func (s *Server) allocate(key string) (netip.Addr, bool) {
	base := s.Pool.Masked().Addr().As4()
	first := binary.BigEndian.Uint32(base[:])
	size := uint32(1) << (32 - s.Pool.Bits())
	if size < 8 {
		return netip.Addr{}, false
	}
	// Hosts 2 .. size-2: not the network, the DNS server or broadcast.
	n := size - 3
	sum := sha256.Sum256([]byte(key))
	start := binary.BigEndian.Uint32(sum[:4]) % n
	for i := uint32(0); i < n; i++ {
		addr := u32addr(first + 2 + (start+i)%n)
		if _, used := s.byAddr[addr]; !used {
			return addr, true
		}
	}
	var lru *entry
	for _, e := range s.byKey {
		if lru == nil || e.used.Before(lru.used) {
			lru = e
		}
	}
	if lru == nil {
		return netip.Addr{}, false
	}
	delete(s.byKey, lru.key)
	delete(s.byAddr, lru.addr)
	// The address serves another name now: drop its translation and the
	// clients' grants first.
	if s.Unmap != nil {
		if err := s.Unmap([]netip.Addr{lru.addr}); err != nil {
			slog.Warn("domain proxy: reuse address", "addr", lru.addr, "err", err)
		}
	}
	return lru.addr, true
}

func u32addr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// resolve finds the real address of an entry (cached for the record's
// TTL) and installs the translation. An invalid address with success
// means the name has no IPv4 address.
func (s *Server) resolve(e *entry, pol Policy) (int, netip.Addr, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.used = time.Now()
	if time.Now().Before(e.expires) {
		return e.rcode, e.real, nil
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(e.name), dns.TypeA)
	q.RecursionDesired = true
	var lastErr error
	for _, srv := range servers(pol.Upstream, s.Forwarders) {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		resp, err := s.Exchange(ctx, q, srv, pol.Mark)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			if resp.Rcode == dns.RcodeNameError {
				e.rcode, e.real, e.expires = dns.RcodeNameError, netip.Addr{}, time.Now().Add(s.TTL)
				return e.rcode, e.real, nil
			}
			lastErr = fmt.Errorf("%s: %s", srv, dns.RcodeToString[resp.Rcode])
			continue
		}
		var real netip.Addr
		ttl := uint32(3600)
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
					if !real.IsValid() {
						real = ip
					}
					ttl = min(ttl, a.Hdr.Ttl)
				}
			}
		}
		if !real.IsValid() {
			// The name exists without an IPv4 address.
			e.rcode, e.real, e.expires = dns.RcodeSuccess, netip.Addr{}, time.Now().Add(s.TTL)
			return e.rcode, e.real, nil
		}
		if s.Map != nil {
			if err := s.Map(e.addr, real); err != nil {
				return 0, netip.Addr{}, err
			}
		}
		if real != e.real {
			slog.Debug("domain proxy", "name", e.name, "addr", e.addr, "real", real, "gateway", pol.Gateway)
		}
		e.real, e.rcode = real, dns.RcodeSuccess
		e.expires = time.Now().Add(max(time.Duration(ttl)*time.Second, s.TTL))
		return e.rcode, e.real, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers")
	}
	return 0, netip.Addr{}, lastErr
}

// forward relays a query and its answer.
func (s *Server) forward(w dns.ResponseWriter, r *dns.Msg, srvs []string, mark uint32) {
	var lastErr error
	for _, srv := range srvs {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		resp, err := s.Exchange(ctx, r, srv, mark)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		resp.Id = r.Id
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			size := dns.MinMsgSize
			if o := r.IsEdns0(); o != nil {
				size = int(o.UDPSize())
			}
			resp.Truncate(size)
		}
		_ = w.WriteMsg(resp)
		return
	}
	if lastErr != nil {
		slog.Debug("domain proxy: forward", "name", r.Question[0].Name, "err", lastErr)
	}
	s.reply(w, r, dns.RcodeServerFailure)
}

func (s *Server) reply(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	_ = w.WriteMsg(m)
}

func addrOf(a net.Addr) netip.Addr {
	var ip netip.Addr
	switch t := a.(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(t.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(t.IP)
	}
	return ip.Unmap()
}

// exchange sends a query over UDP (TCP when truncated) with a socket mark,
// so it follows the routes of the client's vpnGateway.
func exchange(ctx context.Context, m *dns.Msg, server string, mark uint32) (*dns.Msg, error) {
	d := &net.Dialer{}
	if mark != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			}); err != nil {
				return err
			}
			return serr
		}
	}
	c := &dns.Client{Net: "udp", Dialer: d}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, server)
	}
	return resp, err
}

// SystemResolvers returns the servers of /etc/resolv.conf.
func SystemResolvers() []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out
}
