// Package socks is an optional SOCKS5 proxy (RFC 1928: CONNECT, no
// authentication). Hosts of allowed networks open TCP connections that
// leave like those of a VPN client with vpnGateway: networks behind the
// sites through their tunnels, the rest through the chosen exit.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// MaxConns limits simultaneous proxied connections.
const MaxConns = 4096

const (
	handshakeTimeout = 15 * time.Second
	dialTimeout      = 10 * time.Second
)

// Protocol values (RFC 1928).
const (
	methodNone = 0x00
	methodBad  = 0xff
	cmdConnect = 0x01
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repOK               = 0x00
	repFailure          = 0x01
	repNotAllowed       = 0x02
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repRefused          = 0x05
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// Server is the proxy. The functions are read for every connection, so
// changed settings apply without a restart.
type Server struct {
	// Allowed lists the client networks; others are disconnected at once.
	Allowed func() []netip.Prefix
	// Mark is the routing mark (SO_MARK) for a connection to dst.
	Mark func(dst netip.Addr) uint32
	// Resolvers are the DNS servers (host:port) for names, queried with
	// the mark of the exit.
	Resolvers func() []string
	// Denied reports destinations clients must not reach besides the
	// gateway itself (loopback and this host's addresses are always
	// refused), e.g. the VPN client pools.
	Denied func(netip.Addr) bool

	allowLocal bool // tests: targets on loopback
	mu         sync.Mutex
	ln         net.Listener
	conns      atomic.Int64
}

// Start listens on addr (host:port) and serves until Stop.
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	go s.serve(ln)
	return nil
}

// Stop closes the listener; proxied connections continue.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func (s *Server) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("socks: accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		client := addrPort(c.RemoteAddr()).Addr()
		if !s.allowed(client) {
			slog.Debug("socks: client not allowed", "client", client)
			_ = c.Close()
			continue
		}
		if s.conns.Add(1) > MaxConns {
			s.conns.Add(-1)
			slog.Warn("socks: too many connections", "client", client, "limit", MaxConns)
			_ = c.Close()
			continue
		}
		go func() {
			defer s.conns.Add(-1)
			s.handle(c, client)
		}()
	}
}

func (s *Server) allowed(a netip.Addr) bool {
	if s.Allowed == nil {
		return false
	}
	for _, p := range s.Allowed() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Server) handle(c net.Conn, client netip.Addr) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	host, port, err := s.request(c)
	if err != nil {
		slog.Debug("socks: request", "client", client, "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	up, code, err := s.dial(ctx, host, port)
	if err != nil {
		slog.Debug("socks: connection failed", "client", client, "to", net.JoinHostPort(host, strconv.Itoa(int(port))), "err", err)
		_ = reply(c, code, netip.AddrPort{})
		return
	}
	defer up.Close()
	if err := reply(c, repOK, addrPort(up.LocalAddr())); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	slog.Debug("socks: connected", "client", client, "to", up.RemoteAddr())
	relay(c, up)
}

// request reads the greeting and the CONNECT request; errors that the
// client should know about are answered here.
func (s *Server) request(c net.Conn) (host string, port uint16, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 5 {
		return "", 0, errors.New("not SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == methodNone
	}
	if !ok {
		_, _ = c.Write([]byte{5, methodBad})
		return "", 0, errors.New("client needs authentication")
	}
	if _, err = c.Write([]byte{5, methodNone}); err != nil {
		return
	}
	var req [4]byte
	if _, err = io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[0] != 5 {
		return "", 0, errors.New("bad request")
	}
	switch req[3] {
	case atypIPv4:
		var b [4]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(b).String()
	case atypDomain:
		var n [1]byte
		if _, err = io.ReadFull(c, n[:]); err != nil {
			return
		}
		name := make([]byte, n[0])
		if _, err = io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	case atypIPv6:
		_ = reply(c, repAddrNotSupported, netip.AddrPort{})
		return "", 0, errors.New("IPv6 destination")
	default:
		_ = reply(c, repAddrNotSupported, netip.AddrPort{})
		return "", 0, errors.New("unknown address type")
	}
	var p [2]byte
	if _, err = io.ReadFull(c, p[:]); err != nil {
		return
	}
	if req[1] != cmdConnect {
		_ = reply(c, repCmdNotSupported, netip.AddrPort{})
		return "", 0, errors.New("only CONNECT is supported")
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

// dial resolves host through the exit and connects to the first allowed
// address that answers.
func (s *Server) dial(ctx context.Context, host string, port uint16) (net.Conn, byte, error) {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else {
		ips, err := s.resolver().LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, repHostUnreachable, err
		}
		for _, a := range ips {
			addrs = append(addrs, a.Unmap())
		}
	}
	code, lastErr := byte(repNotAllowed), error(errors.New("destination not allowed"))
	for _, a := range addrs {
		if s.denied(a) {
			continue
		}
		d := markedDialer(s.Mark(a))
		c, err := d.DialContext(ctx, "tcp4", netip.AddrPortFrom(a, port).String())
		if err == nil {
			return c, repOK, nil
		}
		code, lastErr = errCode(err), err
	}
	return nil, code, lastErr
}

// resolver queries the configured servers; each query leaves like a
// connection to that server would.
func (s *Server) resolver() *net.Resolver {
	var servers []string
	if s.Resolvers != nil {
		servers = s.Resolvers()
	}
	var next atomic.Uint32
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if len(servers) > 0 {
			addr = servers[int(next.Add(1)-1)%len(servers)]
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		return markedDialer(s.Mark(ap.Addr().Unmap())).DialContext(ctx, network, ap.String())
	}}
}

// denied refuses the gateway itself and addresses that are not unicast
// hosts; Denied adds more.
func (s *Server) denied(a netip.Addr) bool {
	if !a.Is4() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || a.As4()[0] == 0 {
		return true
	}
	if s.Denied != nil && s.Denied(a) {
		return true
	}
	return !s.allowLocal && isLocal(a)
}

// isLocal reports loopback and the addresses of this host: its services
// (RADIUS, OpenVPN management, the portal) must not be reachable through
// the proxy.
func isLocal(a netip.Addr) bool {
	if a.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == a {
				return true
			}
		}
	}
	return false
}

func markedDialer(mark uint32) *net.Dialer {
	d := &net.Dialer{Timeout: dialTimeout}
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
	return d
}

func errCode(err error) byte {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.As(err, &ne) && ne.Timeout():
		return repHostUnreachable
	}
	return repFailure
}

func reply(c net.Conn, code byte, bound netip.AddrPort) error {
	b := []byte{5, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0}
	if a := bound.Addr(); a.Is4() {
		ip := a.As4()
		copy(b[4:8], ip[:])
		binary.BigEndian.PutUint16(b[8:], bound.Port())
	}
	_, err := c.Write(b)
	return err
}

// relay copies both ways; when one side ends its writes the other learns
// it (half close), and both are closed when both directions are done.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if t, ok := dst.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}
