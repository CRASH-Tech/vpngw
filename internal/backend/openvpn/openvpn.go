// Package openvpn manages OpenVPN 2.6 in management-client-auth mode:
// every connection is approved by vpngw, which also pushes the address
// and routes.
package openvpn

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpngw/internal/backend"
	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/pki"
	"vpngw/internal/supervisor"
)

// Device is the tun device name.
const Device = "vpngw-ovpn"

// Backend is the OpenVPN adapter.
type Backend struct {
	Core    *core.Core
	Cfg     *config.Config
	Configs *backend.Configs
	CA      *pki.CA    // internal CA, used when the portal has no public certificate
	Cert    CertSource // the portal's certificate; nil = internal CA only
	Dir     string     // /data/openvpn
	RunDir  string     // /run/vpngw
	SelfBin string     // path of the vpngw binary (tls-crypt-v2-verify)

	Proc *supervisor.Process

	mu      sync.Mutex
	conn    net.Conn
	w       *bufio.Writer
	replies chan string
	cmdMu   sync.Mutex
	clients map[string]*client // by CID
}

type client struct {
	cid      string
	ip       netip.Addr
	trusted  string
	username string
	in, out  uint64
	since    time.Time
	est      bool
}

// Protocol implements core.Backend.
func (b *Backend) Protocol() string { return config.OpenVPN }

// ManagementSocket is the management unix socket path.
func (b *Backend) ManagementSocket() string { return filepath.Join(b.RunDir, "openvpn.sock") }

// Setup prepares keys, certificates and config files.
func (b *Backend) Setup() error {
	b.clients = map[string]*client{}
	if err := os.MkdirAll(b.Dir, 0o700); err != nil {
		return err
	}
	if err := b.ensureInternalCert(); err != nil {
		return err
	}
	srvKey := filepath.Join(b.Dir, "tls-crypt-v2-server.key")
	if _, err := os.Stat(srvKey); err != nil {
		if out, err := exec.Command("openvpn", "--genkey", "tls-crypt-v2-server", srvKey).CombinedOutput(); err != nil {
			return fmt.Errorf("generate tls-crypt-v2 server key: %v: %s", err, out)
		}
		_ = os.Chmod(srvKey, 0o600)
	}
	tokKey := filepath.Join(b.Dir, "auth-token.key")
	if _, err := os.Stat(tokKey); err != nil {
		if out, err := exec.Command("openvpn", "--genkey", "auth-token", tokKey).CombinedOutput(); err != nil {
			return fmt.Errorf("generate auth-token key: %v: %s", err, out)
		}
		_ = os.Chmod(tokKey, 0o600)
	}
	if _, err := os.Stat(b.dhFile()); err != nil {
		go b.generateDH()
	}
	b.Configs.Register(&backend.ConfigFile{Name: "openvpn.conf", Backend: config.OpenVPN, Path: filepath.Join(b.Dir, "server.conf"), Generate: b.generate})
	return nil
}

// ensureInternalCert keeps a server certificate from the internal CA: valid
// for 30 more days and issued by the current CA (the CA is recreated with a
// new database; profiles carry the new one).
func (b *Backend) ensureInternalCert() error {
	crt, key := filepath.Join(b.Dir, "server.crt"), filepath.Join(b.Dir, "server.key")
	if fileValid(crt, 30*24*time.Hour) && b.issuedByCA(crt) {
		return nil
	}
	c, k, err := b.CA.IssueServer(b.Cfg.Str("VPN_HOSTNAME"), 5*365*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.WriteFile(key, k, 0o600); err != nil {
		return err
	}
	return os.WriteFile(crt, c, 0o644)
}

func (b *Backend) issuedByCA(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	c, err := parseCert(data)
	ca, err2 := parseCert(b.CA.CertPEM)
	return err == nil && err2 == nil && c.CheckSignatureFrom(ca) == nil && c.Subject.CommonName == b.Cfg.Str("VPN_HOSTNAME")
}

// trust picks the portal's public certificate when clients can verify it
// with a well-known root, else the internal CA.
func (b *Backend) trust() trust {
	if b.Cert != nil && !b.Cert.IsSelfSigned() {
		root, cn, err := publicTrust(b.Cert.ChainPEM(), SystemRoots)
		if err == nil {
			rc, _ := parseCert(root)
			return trust{Public: true, CAPEM: root, CertFile: b.Cert.RuntimeCert(), KeyFile: b.Cert.RuntimeKey(), Name: cn,
				Note: fmt.Sprintf("certificate of the portal (CN %s); clients trust %s", cn, rc.Subject.CommonName)}
		}
		b.warnOnce("openvpn-trust", "OpenVPN uses the internal CA: the portal certificate cannot be used", "err", err)
	}
	return trust{CAPEM: b.CA.CertPEM, CertFile: filepath.Join(b.Dir, "server.crt"), KeyFile: filepath.Join(b.Dir, "server.key"),
		Name: b.Cfg.Str("VPN_HOSTNAME"), Note: "internal CA of this gateway"}
}

var warned sync.Map

func (b *Backend) warnOnce(key, msg string, args ...any) {
	if _, loaded := warned.LoadOrStore(key+fmt.Sprint(args...), true); !loaded {
		slog.Warn(msg, args...)
	}
}

func (b *Backend) dhFile() string { return filepath.Join(b.Dir, "dh.pem") }

// generateDH creates 2048-bit DH parameters (finding a safe prime takes minutes;
// until then the server offers ECDHE only) and applies them while no client
// is connected.
func (b *Backend) generateDH() {
	slog.Info("generating OpenVPN DH parameters in the background (takes a few minutes)")
	tmp := b.dhFile() + ".tmp"
	if out, err := exec.Command("openssl", "dhparam", "-out", tmp, "2048").CombinedOutput(); err != nil {
		slog.Warn("OpenVPN DH parameters", "err", err, "out", strings.TrimSpace(string(out)))
		return
	}
	if err := os.Rename(tmp, b.dhFile()); err != nil {
		return
	}
	slog.Info("OpenVPN DH parameters ready")
	for b.Proc != nil {
		b.mu.Lock()
		n := len(b.clients)
		b.mu.Unlock()
		if n == 0 {
			b.Proc.Restart()
			return
		}
		time.Sleep(time.Minute)
	}
}

// CertificateChanged restarts OpenVPN to load a renewed portal certificate
// (clients reconnect with their session token).
func (b *Backend) CertificateChanged() {
	if b.Proc != nil && b.trust().Public {
		slog.Info("restarting OpenVPN for the new certificate")
		b.Proc.Restart()
	}
}

func fileValid(path string, minLeft time.Duration) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	c, err := parseCert(data)
	if err != nil {
		return false
	}
	return time.Until(c.NotAfter) > minLeft
}

func (b *Backend) generate() (string, error) {
	pool := b.Core.IPAM.Pool(config.OpenVPN).Prefix()
	mask := net.IP(net.CIDRMask(pool.Bits(), 32)).String()
	t := b.trust()
	caFile := filepath.Join(b.Dir, "ca.crt")
	if err := os.WriteFile(caFile, t.CAPEM, 0o644); err != nil {
		return "", err
	}
	dh := ""
	if _, err := os.Stat(b.dhFile()); err == nil {
		dh = b.dhFile()
	}
	mtu := b.Cfg.Int("OPENVPN_MTU")
	return backend.Render("openvpn.conf.tmpl", map[string]any{
		"Port":             b.Cfg.Int("OPENVPN_PORT"),
		"Proto":            b.Cfg.Str("OPENVPN_PROTO"),
		"MTU":              mtu,
		"MSS":              mtu - 60,
		"Device":           Device,
		"PoolNetwork":      pool.Addr().String(),
		"PoolNetmask":      mask,
		"Dir":              b.Dir,
		"CertNote":         t.Note,
		"CAFile":           caFile,
		"CertFile":         t.CertFile,
		"KeyFile":          t.KeyFile,
		"DHFile":           dh,
		"VerifyCommand":    b.SelfBin + " tls-verify",
		"ManagementSocket": b.ManagementSocket(),
	})
}

// Process returns the supervised process.
func (b *Backend) Process() *supervisor.Process {
	if b.Proc == nil {
		b.Proc = &supervisor.Process{
			Name: "openvpn",
			BeforeStart: func() error {
				_ = os.Remove(b.ManagementSocket())
				// Also for an edited config, which may keep "ca ca.crt".
				if err := os.WriteFile(filepath.Join(b.Dir, "ca.crt"), b.trust().CAPEM, 0o644); err != nil {
					return err
				}
				return b.Configs.WriteBackend(config.OpenVPN)
			},
			Command: func() *exec.Cmd {
				return exec.Command("openvpn", "--config", filepath.Join(b.Dir, "server.conf"))
			},
		}
	}
	return b.Proc
}

// Run keeps the management connection alive.
func (b *Backend) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := b.manage(ctx); err != nil && ctx.Err() == nil {
			slog.Debug("openvpn management disconnected", "err", err)
		}
		b.dropAll("OpenVPN restarted")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (b *Backend) dropAll(reason string) {
	b.mu.Lock()
	clients := b.clients
	b.clients = map[string]*client{}
	b.mu.Unlock()
	for _, c := range clients {
		if c.ip.IsValid() {
			b.Core.SessionStopped(c.ip, reason, c.in, c.out)
		}
	}
}

func (b *Backend) manage(ctx context.Context) error {
	conn, err := net.DialTimeout("unix", b.ManagementSocket(), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	b.mu.Lock()
	b.conn = conn
	b.w = bufio.NewWriter(conn)
	b.replies = make(chan string, 16)
	b.mu.Unlock()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	slog.Info("connected to OpenVPN management interface")
	errc := make(chan error, 1)
	go func() { errc <- b.readLoop(conn) }()
	if _, err := b.command("bytecount 5"); err != nil {
		slog.Warn("openvpn bytecount", "err", err)
	}
	return <-errc
}

func (b *Backend) readLoop(conn net.Conn) error {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var cur *event
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(line, ">CLIENT:ENV,"):
			kv := strings.TrimPrefix(line, ">CLIENT:ENV,")
			if kv == "END" {
				if cur != nil {
					ev := cur
					cur = nil
					go b.handleEvent(ev)
				}
				continue
			}
			if cur != nil {
				k, v, _ := strings.Cut(kv, "=")
				cur.env[k] = v
			}
		case strings.HasPrefix(line, ">CLIENT:"):
			parts := strings.Split(strings.TrimPrefix(line, ">CLIENT:"), ",")
			cur = &event{kind: parts[0], args: parts[1:], env: map[string]string{}}
		case strings.HasPrefix(line, ">BYTECOUNT_CLI:"):
			f := strings.Split(strings.TrimPrefix(line, ">BYTECOUNT_CLI:"), ",")
			if len(f) == 3 {
				in, _ := strconv.ParseUint(f[1], 10, 64)
				out, _ := strconv.ParseUint(f[2], 10, 64)
				b.mu.Lock()
				if c, ok := b.clients[f[0]]; ok {
					c.in, c.out = in, out
				}
				b.mu.Unlock()
			}
		case strings.HasPrefix(line, ">INFO:"), strings.HasPrefix(line, ">BYTECOUNT:"), strings.HasPrefix(line, ">HOLD:"):
			if strings.HasPrefix(line, ">HOLD:") {
				go func() { _, _ = b.command("hold release") }()
			}
		case strings.HasPrefix(line, ">"):
			slog.Debug("openvpn management", "line", line)
		default:
			b.mu.Lock()
			ch := b.replies
			b.mu.Unlock()
			select {
			case ch <- line:
			default:
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("management connection closed")
}

type event struct {
	kind string
	args []string
	env  map[string]string
}

// command sends one command and waits for SUCCESS/ERROR.
func (b *Backend) command(cmd string) (string, error) {
	b.cmdMu.Lock()
	defer b.cmdMu.Unlock()
	b.mu.Lock()
	w, ch := b.w, b.replies
	b.mu.Unlock()
	if w == nil {
		return "", errors.New("management not connected")
	}
	for len(ch) > 0 {
		<-ch
	}
	if _, err := w.WriteString(cmd + "\n"); err != nil {
		return "", err
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	for {
		select {
		case line := <-ch:
			if strings.HasPrefix(line, "SUCCESS:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "SUCCESS:")), nil
			}
			if strings.HasPrefix(line, "ERROR:") {
				return "", errors.New(strings.TrimSpace(strings.TrimPrefix(line, "ERROR:")))
			}
		case <-time.After(5 * time.Second):
			return "", fmt.Errorf("timeout waiting for reply to %q", strings.Fields(cmd)[0])
		}
	}
}

func (b *Backend) handleEvent(ev *event) {
	switch ev.kind {
	case "CONNECT":
		b.onConnect(ev)
	case "REAUTH":
		b.onReauth(ev)
	case "ESTABLISHED":
		b.onEstablished(ev)
	case "DISCONNECT":
		b.onDisconnect(ev)
	}
}

func (b *Backend) onConnect(ev *event) {
	if len(ev.args) < 2 {
		return
	}
	cid, kid := ev.args[0], ev.args[1]
	cr := core.Credentials{Protocol: config.OpenVPN, Login: ev.env["username"], ClientIP: ev.env["untrusted_ip"]}
	sess, err := b.Core.AuthenticatePassword(cr, ev.env["password"])
	if err != nil {
		reason := "authentication failed"
		var de *core.DenyError
		if errors.As(err, &de) {
			reason = de.Reason
		}
		if _, err := b.command(fmt.Sprintf("client-deny %s %s %q %q", cid, kid, reason, reason)); err != nil {
			slog.Warn("openvpn client-deny", "err", err)
		}
		return
	}
	b.mu.Lock()
	b.clients[cid] = &client{cid: cid, ip: sess.VPNIP, trusted: cr.ClientIP, username: sess.Username, since: time.Now()}
	b.mu.Unlock()
	var lines []string
	pool := b.Core.IPAM.Pool(config.OpenVPN).Prefix()
	lines = append(lines, fmt.Sprintf("ifconfig-push %s %s", sess.VPNIP, net.IP(net.CIDRMask(pool.Bits(), 32))))
	prof := sess.Profile
	if prof.FullTunnel {
		lines = append(lines, `push "redirect-gateway def1 bypass-dhcp"`)
	} else {
		for _, r := range prof.Routes() {
			lines = append(lines, fmt.Sprintf(`push "route %s %s"`, r.Addr(), net.IP(net.CIDRMask(r.Bits(), 32))))
		}
	}
	for _, d := range prof.DNS {
		lines = append(lines, fmt.Sprintf(`push "dhcp-option DNS %s"`, d))
	}
	if prof.Domain != "" {
		lines = append(lines, fmt.Sprintf(`push "dhcp-option DOMAIN %s"`, prof.Domain))
	}
	if len(prof.DNS) > 0 && (prof.FullTunnel || len(prof.Domains) > 0) {
		// Windows: no answers from other interfaces' resolvers (for
		// vpnDomains they would bypass the gateway).
		lines = append(lines, `push "block-outside-dns"`)
	}
	cmd := fmt.Sprintf("client-auth %s %s\n%s\nEND", cid, kid, strings.Join(lines, "\n"))
	if _, err := b.command(cmd); err != nil {
		slog.Error("openvpn client-auth failed", "err", err)
		b.Core.SessionStopped(sess.VPNIP, "client-auth failed", 0, 0)
	}
}

// onReauth handles TLS renegotiation: the client presents the auth token
// generated by OpenVPN; access is re-checked against the live session.
func (b *Backend) onReauth(ev *event) {
	if len(ev.args) < 2 {
		return
	}
	cid, kid := ev.args[0], ev.args[1]
	b.mu.Lock()
	c, ok := b.clients[cid]
	b.mu.Unlock()
	if ok {
		if _, live := b.Core.SessionByIP(c.ip); live && strings.HasPrefix(ev.env["session_state"], "Authenticated") {
			_, _ = b.command(fmt.Sprintf("client-auth-nt %s %s", cid, kid))
			return
		}
	}
	_, _ = b.command(fmt.Sprintf("client-deny %s %s \"session expired\"", cid, kid))
}

func (b *Backend) onEstablished(ev *event) {
	cid := ev.args[0]
	b.mu.Lock()
	c, ok := b.clients[cid]
	if ok {
		c.est = true
	}
	b.mu.Unlock()
	if !ok {
		_, _ = b.command("client-kill " + cid)
		return
	}
	b.Core.SessionStarted(c.ip, cid, ev.env["trusted_ip"])
}

func (b *Backend) onDisconnect(ev *event) {
	cid := ev.args[0]
	b.mu.Lock()
	c, ok := b.clients[cid]
	delete(b.clients, cid)
	b.mu.Unlock()
	if !ok {
		return
	}
	in, _ := strconv.ParseUint(ev.env["bytes_received"], 10, 64)
	out, _ := strconv.ParseUint(ev.env["bytes_sent"], 10, 64)
	b.Core.SessionStopped(c.ip, "", in, out)
}

// Disconnect implements core.Backend.
func (b *Backend) Disconnect(s *core.Session) error {
	cid := s.BackendRef
	if cid == "" {
		b.mu.Lock()
		for id, c := range b.clients {
			if c.ip == s.VPNIP {
				cid = id
			}
		}
		b.mu.Unlock()
	}
	if cid == "" {
		return errors.New("unknown OpenVPN client")
	}
	// HALT makes the client exit; the default (RESTART) has it reconnect
	// at once with its saved password.
	_, err := b.command("client-kill " + cid + " HALT")
	return err
}

// Poll implements core.Backend.
func (b *Backend) Poll(context.Context) ([]core.LiveSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.w == nil {
		return nil, errors.New("management not connected")
	}
	out := make([]core.LiveSession, 0, len(b.clients))
	for _, c := range b.clients {
		if !c.est {
			continue
		}
		out = append(out, core.LiveSession{VPNIP: c.ip, BackendRef: c.cid, ClientIP: c.trusted, Username: c.username,
			BytesIn: c.in, BytesOut: c.out, Since: c.since})
	}
	return out, nil
}

// ClientKey generates a tls-crypt-v2 client key bound to metadata.
func (b *Backend) ClientKey(meta string) (string, error) {
	tmp, err := os.MkdirTemp("", "tcv2")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "client.key")
	cmd := exec.Command("openvpn", "--tls-crypt-v2", filepath.Join(b.Dir, "tls-crypt-v2-server.key"),
		"--genkey", "tls-crypt-v2-client", out, base64.StdEncoding.EncodeToString([]byte(meta)))
	if o, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("genkey: %v: %s", err, o)
	}
	k, err := os.ReadFile(out)
	return string(k), err
}

// ProfileOptions personalise a client profile.
type ProfileOptions struct {
	Name     string // connection name shown by the client (FRIENDLY_NAME)
	Login    string // user@group; saved in the profile when set
	Password string // saved with Login (inline auth-user-pass) when set
}

// Profile renders a .ovpn client profile. Remotes are tried in order
// (the first is the preferred server); empty means VPN_HOSTNAME.
func (b *Backend) Profile(username, meta string, remotes []string, opt ProfileOptions) (string, error) {
	key, err := b.ClientKey(meta)
	if err != nil {
		return "", err
	}
	var s strings.Builder
	server := remotes0(remotes, b.Cfg.Str("VPN_HOSTNAME"))
	name := opt.Name
	if name == "" {
		name = server
	}
	fmt.Fprintf(&s, "# vpngw OpenVPN profile for %s, server %s\n", username, server)
	if opt.Password != "" {
		s.WriteString("# Contains the VPN password: keep this file private.\n")
	}
	fmt.Fprintf(&s, "setenv FRIENDLY_NAME %q\n", name)
	// No client certificate: users sign in with a password. Without this
	// OpenVPN Connect asks to pick a certificate from the system store.
	s.WriteString("setenv CLIENT_CERT 0\n")
	if len(remotes) == 0 {
		remotes = []string{b.Cfg.Str("VPN_HOSTNAME")}
	}
	proto := b.Cfg.Str("OPENVPN_PROTO")
	t := b.trust()
	fmt.Fprintf(&s, "client\ndev tun\nproto %s\n", proto)
	for _, r := range remotes {
		fmt.Fprintf(&s, "remote %s %d\n", r, b.Cfg.Int("OPENVPN_PORT"))
	}
	if len(remotes) > 1 {
		s.WriteString("server-poll-timeout 10\n")
	}
	s.WriteString("resolv-retry infinite\nnobind\npersist-key\npersist-tun\n")
	s.WriteString("remote-cert-tls server\n")
	fmt.Fprintf(&s, "verify-x509-name %s name\n", t.Name)
	s.WriteString("tls-version-min 1.2\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\n")
	if opt.Login != "" && opt.Password != "" {
		// Inline credentials (OpenVPN Connect, OpenVPN 2.6+).
		fmt.Fprintf(&s, "<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n", opt.Login, opt.Password)
	} else {
		s.WriteString("auth-user-pass\nauth-nocache\n")
	}
	s.WriteString("auth-retry interact\n")
	if proto != "tcp" {
		s.WriteString("explicit-exit-notify 1\n")
	}
	s.WriteString("verb 3\n")
	login := opt.Login
	if login == "" {
		login = username
	}
	fmt.Fprintf(&s, "setenv UV_LOGIN %s\n", login)
	fmt.Fprintf(&s, "<ca>\n%s</ca>\n", strings.TrimSpace(string(t.CAPEM))+"\n")
	fmt.Fprintf(&s, "<tls-crypt-v2>\n%s</tls-crypt-v2>\n", key)
	return s.String(), nil
}

func remotes0(remotes []string, def string) string {
	if len(remotes) > 0 {
		return remotes[0]
	}
	return def
}
