// Package strongswan manages charon over VICI: certificates, one
// connection per route profile (selected through RADIUS Class groups),
// SA listing and termination.
package strongswan

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/strongswan/govici/vici"

	"vpngw/internal/backend"
	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/policy"
	"vpngw/internal/radius"
	"vpngw/internal/supervisor"
)

// IKE and ESP proposals: modern first, then Windows/Apple defaults.
var (
	ikeProposals = []string{
		"aes256gcm16-prfsha384-ecp384", "aes256gcm16-prfsha256-ecp256", "aes256gcm16-prfsha256-x25519",
		"aes256-sha384-ecp384", "aes256-sha256-ecp256", "aes256-sha256-modp2048", "aes128-sha256-modp2048",
	}
	espProposals = []string{"aes256gcm16", "aes256gcm16-ecp384", "aes256-sha256", "aes256-sha256-modp2048", "aes128-sha256", "default"}
)

const baseConn = "vpngw-base"

// Backend is the strongSwan adapter.
type Backend struct {
	Core     *core.Core
	Cfg      *config.Config
	Configs  *backend.Configs
	Radius   *radius.Server
	Dir      string
	RunDir   string
	CertFile string // chain PEM (leaf first)
	KeyFile  string
	// Identity returns the IKE identity of the server.
	Identity func() string

	Proc *supervisor.Process

	mu     sync.Mutex
	sess   *vici.Session
	loaded map[string]bool // profile conns
}

// Protocol implements core.Backend.
func (b *Backend) Protocol() string { return config.IKEv2 }

func (b *Backend) viciSocket() string { return filepath.Join(b.RunDir, "charon.vici") }
func (b *Backend) confFile() string   { return filepath.Join(b.Dir, "strongswan.conf") }

// Setup registers config files.
func (b *Backend) Setup() error {
	b.loaded = map[string]bool{}
	if err := os.MkdirAll(b.Dir, 0o700); err != nil {
		return err
	}
	b.Configs.Register(&backend.ConfigFile{Name: "strongswan.conf", Backend: config.IKEv2, Path: b.confFile(), Mode: 0o600, Secret: true,
		Generate: func() (string, error) {
			_, authPort, _ := splitHostPort(b.Radius.AuthAddr)
			_, acctPort, _ := splitHostPort(b.Radius.AcctAddr)
			return backend.Render("strongswan.conf.tmpl", map[string]any{
				"ViciSocket": b.viciSocket(), "NASIdentifier": radius.NASIKEv2, "AuthPort": authPort, "AcctPort": acctPort,
				"Secret": string(b.Radius.Secret), "KernelLibipsec": b.Cfg.Bool("IKEV2_KERNEL_LIBIPSEC"),
			})
		}})
	return nil
}

func splitHostPort(s string) (string, int, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return "", 0, err
	}
	return ap.Addr().String(), int(ap.Port()), nil
}

// Process returns the supervised charon process.
func (b *Backend) Process() *supervisor.Process {
	if b.Proc == nil {
		b.Proc = &supervisor.Process{
			Name: "charon",
			BeforeStart: func() error {
				_ = os.Remove(b.viciSocket())
				b.mu.Lock()
				if b.sess != nil {
					b.sess.Close()
					b.sess = nil
				}
				b.loaded = map[string]bool{}
				b.mu.Unlock()
				return b.Configs.WriteBackend(config.IKEv2)
			},
			Command: func() *exec.Cmd {
				cmd := exec.Command(charonPath())
				cmd.Env = append(os.Environ(), "STRONGSWAN_CONF="+b.confFile())
				return cmd
			},
		}
	}
	return b.Proc
}

func charonPath() string {
	for _, p := range []string{"/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon", "/usr/lib/strongswan/charon"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "charon"
}

// Run waits for charon and loads credentials and the base connection
// every time it (re)starts.
func (b *Backend) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		b.mu.Lock()
		connected := b.sess != nil
		b.mu.Unlock()
		if connected {
			if _, err := b.call("version", nil); err == nil {
				continue
			}
			b.mu.Lock()
			if b.sess != nil {
				b.sess.Close()
			}
			b.sess = nil
			b.loaded = map[string]bool{}
			b.mu.Unlock()
		}
		if err := b.connect(); err != nil {
			slog.Debug("vici not ready", "err", err)
			continue
		}
		if err := b.loadAll(); err != nil {
			slog.Error("strongswan: load configuration", "err", err)
		}
	}
}

func (b *Backend) connect() error {
	s, err := vici.NewSession(vici.WithSocketPath(b.viciSocket()))
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.sess = s
	b.mu.Unlock()
	slog.Info("connected to charon over VICI")
	return nil
}

func (b *Backend) call(cmd string, msg *vici.Message) (*vici.Message, error) {
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	if s == nil {
		return nil, errors.New("vici not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := s.Call(ctx, cmd, msg)
	if err != nil {
		return nil, err
	}
	if v, ok := m.Get("success").(string); ok && v != "yes" {
		return m, fmt.Errorf("%s: %v", cmd, m.Get("errmsg"))
	}
	return m, nil
}

// loadAll loads key, certificates, base connection and active profiles.
func (b *Backend) loadAll() error {
	if err := b.loadCredentials(); err != nil {
		return err
	}
	if err := b.loadConn(baseConn, nil); err != nil {
		return err
	}
	b.mu.Lock()
	b.loaded = map[string]bool{}
	b.mu.Unlock()
	b.SyncProfiles(b.Core.WantedProfiles(config.IKEv2))
	return nil
}

func (b *Backend) loadCredentials() error {
	keyPEM, err := os.ReadFile(b.KeyFile)
	if err != nil {
		return err
	}
	m := vici.NewMessage()
	_ = m.Set("type", "any")
	_ = m.Set("data", string(keyPEM))
	if _, err := b.call("load-key", m); err != nil {
		return err
	}
	chain, err := os.ReadFile(b.CertFile)
	if err != nil {
		return err
	}
	for i, der := range pemBlocks(chain) {
		cm := vici.NewMessage()
		_ = cm.Set("type", "X509")
		if i == 0 {
			_ = cm.Set("flag", "NONE")
		} else {
			_ = cm.Set("flag", "CA")
		}
		_ = cm.Set("data", string(der))
		if _, err := b.call("load-cert", cm); err != nil {
			return err
		}
	}
	return nil
}

func pemBlocks(data []byte) [][]byte {
	var out [][]byte
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return out
		}
		if blk.Type == "CERTIFICATE" {
			out = append(out, blk.Bytes)
		}
	}
}

// ReloadCertificate loads a renewed certificate without restarting charon.
func (b *Backend) ReloadCertificate() {
	b.mu.Lock()
	connected := b.sess != nil
	b.mu.Unlock()
	if !connected {
		return
	}
	if err := b.loadAll(); err != nil {
		slog.Error("strongswan: reload certificate", "err", err)
	} else {
		slog.Info("strongswan: certificate reloaded")
	}
}

func (b *Backend) leafPEM() string {
	chain, _ := os.ReadFile(b.CertFile)
	blocks := pemBlocks(chain)
	if len(blocks) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blocks[0]}))
}

// loadConn loads a connection; p == nil is the catch-all base connection
// that only serves to start EAP before the profile is known.
func (b *Backend) loadConn(name string, p *policy.Profile) error {
	local := vici.NewMessage()
	_ = local.Set("auth", "pubkey")
	_ = local.Set("id", b.Identity())
	_ = local.Set("certs", []string{b.leafPEM()})
	remote := vici.NewMessage()
	_ = remote.Set("auth", "eap-radius")
	_ = remote.Set("eap_id", "%any")
	group := "vpngw-no-profile"
	ts := []string{"0.0.0.0/32"}
	if p != nil {
		group = p.ID
		ts = nil
		for _, a := range p.Allow {
			ts = append(ts, a.String())
		}
	}
	_ = remote.Set("groups", []string{group})
	child := vici.NewMessage()
	_ = child.Set("local_ts", ts)
	_ = child.Set("esp_proposals", espProposals)
	_ = child.Set("dpd_action", "clear")
	_ = child.Set("rekey_time", "0s")
	_ = child.Set("life_time", "24h")
	children := vici.NewMessage()
	_ = children.Set("net", child)
	conn := vici.NewMessage()
	_ = conn.Set("version", "2")
	_ = conn.Set("pools", []string{"radius"})
	_ = conn.Set("proposals", ikeProposals)
	_ = conn.Set("send_cert", "always")
	_ = conn.Set("unique", "never")
	_ = conn.Set("fragmentation", "yes")
	_ = conn.Set("mobike", "yes")
	_ = conn.Set("dpd_delay", "30s")
	_ = conn.Set("rekey_time", "0s")
	_ = conn.Set("reauth_time", "0s")
	_ = conn.Set("local-1", local)
	_ = conn.Set("remote-1", remote)
	_ = conn.Set("children", children)
	m := vici.NewMessage()
	_ = m.Set(name, conn)
	_, err := b.call("load-conn", m)
	return err
}

// PrepareProfile implements core.ProfilePreparer.
func (b *Backend) PrepareProfile(p *policy.Profile) error {
	b.mu.Lock()
	done := b.loaded[p.ID]
	b.mu.Unlock()
	if done {
		return nil
	}
	if err := b.loadConn(p.ID, p); err != nil {
		return err
	}
	b.mu.Lock()
	b.loaded[p.ID] = true
	b.mu.Unlock()
	slog.Info("strongswan: profile connection loaded", "profile", p.ID, "networks", p.AllowStrings())
	return nil
}

// SyncProfiles implements core.ProfilePreparer: load wanted profile
// connections and unload the others.
func (b *Backend) SyncProfiles(wanted map[string]*policy.Profile) {
	b.mu.Lock()
	connected := b.sess != nil
	var unload []string
	for id := range b.loaded {
		if _, ok := wanted[id]; !ok {
			unload = append(unload, id)
		}
	}
	b.mu.Unlock()
	if !connected {
		return
	}
	for _, p := range wanted {
		if err := b.PrepareProfile(p); err != nil {
			slog.Error("strongswan: load profile", "profile", p.ID, "err", err)
		}
	}
	for _, id := range unload {
		m := vici.NewMessage()
		_ = m.Set("name", id)
		if _, err := b.call("unload-conn", m); err != nil {
			slog.Debug("strongswan: unload conn", "profile", id, "err", err)
		}
		b.mu.Lock()
		delete(b.loaded, id)
		b.mu.Unlock()
	}
}

// LoadedProfiles returns the profile connections currently loaded.
func (b *Backend) LoadedProfiles() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.loaded))
	for id := range b.loaded {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Poll implements core.Backend.
func (b *Backend) Poll(ctx context.Context) ([]core.LiveSession, error) {
	b.mu.Lock()
	s := b.sess
	b.mu.Unlock()
	if s == nil {
		return nil, errors.New("vici not connected")
	}
	var out []core.LiveSession
	for m, err := range s.CallStreaming(ctx, "list-sas", "list-sa", nil) {
		if err != nil {
			return nil, err
		}
		for _, name := range m.Keys() {
			ike, ok := m.Get(name).(*vici.Message)
			if !ok {
				continue
			}
			ls := core.LiveSession{BackendRef: str(ike.Get("uniqueid")), ClientIP: str(ike.Get("remote-host"))}
			if v, ok := ike.Get("remote-vips").([]string); ok && len(v) > 0 {
				ls.VPNIP, _ = netip.ParseAddr(v[0])
			}
			ls.Username = str(ike.Get("remote-eap-id"))
			if est, err := strconv.ParseInt(str(ike.Get("established")), 10, 64); err == nil {
				ls.Since = time.Now().Add(-time.Duration(est) * time.Second)
			}
			if children, ok := ike.Get("child-sas").(*vici.Message); ok {
				for _, cn := range children.Keys() {
					c, ok := children.Get(cn).(*vici.Message)
					if !ok {
						continue
					}
					in, _ := strconv.ParseUint(str(c.Get("bytes-in")), 10, 64)
					outB, _ := strconv.ParseUint(str(c.Get("bytes-out")), 10, 64)
					ls.BytesIn += in
					ls.BytesOut += outB
				}
			}
			if ls.VPNIP.IsValid() && str(ike.Get("state")) == "ESTABLISHED" {
				out = append(out, ls)
			}
		}
	}
	return out, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// Disconnect implements core.Backend.
func (b *Backend) Disconnect(s *core.Session) error {
	ref := s.BackendRef
	if ref == "" {
		live, err := b.Poll(context.Background())
		if err != nil {
			return err
		}
		for _, l := range live {
			if l.VPNIP == s.VPNIP {
				ref = l.BackendRef
			}
		}
	}
	if ref == "" {
		return errors.New("IKE SA not found")
	}
	m := vici.NewMessage()
	_ = m.Set("ike-id", ref)
	_ = m.Set("force", "yes")
	_ = m.Set("timeout", "-1")
	b.mu.Lock()
	sess := b.sess
	b.mu.Unlock()
	if sess == nil {
		return errors.New("vici not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, err := range sess.CallStreaming(ctx, "terminate", "control-log", m) {
		if err != nil {
			return err
		}
	}
	return nil
}
