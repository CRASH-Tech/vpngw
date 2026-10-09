// Package sni routes TCP 443 by the TLS SNI: the portal hostname is served
// in-process, everything else is proxied to ocserv with PROXY protocol v2
// so ocserv sees the real client address.
package sni

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Router accepts connections and dispatches them.
type Router struct {
	// PortalHost is served by Portal; empty means everything goes to the backend.
	PortalHost func() string
	// Portal receives connections for PortalHost (already peeked).
	Portal *ChanListener
	// Backend is the ocserv TCP address.
	Backend string
}

// Serve accepts on l until it is closed.
func (r *Router) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go r.handle(c)
	}
}

func (r *Router) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	host, peeked, err := peekSNI(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil && len(peeked) == 0 {
		c.Close()
		return
	}
	pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(peeked), c)}
	ph := ""
	if r.PortalHost != nil {
		ph = r.PortalHost()
	}
	if ph != "" && strings.EqualFold(host, ph) && r.Portal != nil {
		r.Portal.Push(pc)
		return
	}
	r.proxy(pc, c)
}

func (r *Router) proxy(client net.Conn, raw net.Conn) {
	defer client.Close()
	up, err := net.DialTimeout("tcp", r.Backend, 5*time.Second)
	if err != nil {
		slog.Warn("sni: backend unavailable", "backend", r.Backend, "err", err)
		return
	}
	defer up.Close()
	if _, err := up.Write(proxyHeader(raw.RemoteAddr(), raw.LocalAddr())); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, client)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, up)
		if tc, ok := raw.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// proxyHeader builds a PROXY protocol v2 header.
func proxyHeader(src, dst net.Addr) []byte {
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	s, _ := netip.ParseAddrPort(src.String())
	d, _ := netip.ParseAddrPort(dst.String())
	sa, da := s.Addr().Unmap(), d.Addr().Unmap()
	var b bytes.Buffer
	b.Write(sig)
	b.WriteByte(0x21) // v2, PROXY
	if sa.Is4() && da.Is4() {
		b.WriteByte(0x11) // TCP over IPv4
		_ = binary.Write(&b, binary.BigEndian, uint16(12))
		a4, d4 := sa.As4(), da.As4()
		b.Write(a4[:])
		b.Write(d4[:])
	} else {
		b.WriteByte(0x21) // TCP over IPv6
		_ = binary.Write(&b, binary.BigEndian, uint16(36))
		a16, d16 := sa.As16(), da.As16()
		b.Write(a16[:])
		b.Write(d16[:])
	}
	_ = binary.Write(&b, binary.BigEndian, s.Port())
	_ = binary.Write(&b, binary.BigEndian, d.Port())
	return b.Bytes()
}

// peekSNI reads the ClientHello and returns the server name and the bytes read.
func peekSNI(c net.Conn) (string, []byte, error) {
	rec := &recordingConn{r: c}
	var host string
	_ = tls.Server(readOnly{rec}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			host = h.ServerName
			return nil, errStop
		},
	}).Handshake()
	if host == "" && len(rec.buf.Bytes()) == 0 {
		return "", nil, errors.New("no client hello")
	}
	return host, rec.buf.Bytes(), nil
}

var errStop = errors.New("stop")

type recordingConn struct {
	r   io.Reader
	buf bytes.Buffer
}

func (r *recordingConn) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

// readOnly is a net.Conn whose writes are discarded (the handshake is aborted).
type readOnly struct{ r io.Reader }

func (c readOnly) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnly) Write(p []byte) (int, error)      { return 0, io.ErrClosedPipe }
func (readOnly) Close() error                     { return nil }
func (readOnly) LocalAddr() net.Addr              { return nil }
func (readOnly) RemoteAddr() net.Addr             { return nil }
func (readOnly) SetDeadline(time.Time) error      { return nil }
func (readOnly) SetReadDeadline(time.Time) error  { return nil }
func (readOnly) SetWriteDeadline(time.Time) error { return nil }

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// ChanListener is a net.Listener fed by the router.
type ChanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

// NewChanListener creates a listener reporting addr.
func NewChanListener(addr net.Addr) *ChanListener {
	return &ChanListener{ch: make(chan net.Conn, 64), addr: addr, closed: make(chan struct{})}
}

// Push hands a connection to Accept.
func (l *ChanListener) Push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		c.Close()
	}
}

// Accept implements net.Listener.
func (l *ChanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (l *ChanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// Addr implements net.Listener.
func (l *ChanListener) Addr() net.Addr { return l.addr }
