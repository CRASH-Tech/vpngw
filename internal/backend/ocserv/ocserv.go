// Package ocserv manages ocserv (Cisco AnyConnect / OpenConnect).
// Authentication and addressing go through the vpngw RADIUS server.
package ocserv

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vpngw/internal/backend"
	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/radius"
	"vpngw/internal/supervisor"
)

// TCPPort is the local TCP port behind the SNI router.
const TCPPort = 4443

// Backend is the ocserv adapter.
type Backend struct {
	Core     *core.Core
	Cfg      *config.Config
	Configs  *backend.Configs
	Radius   *radius.Server
	Dir      string // generated config dir
	RunDir   string
	CertFile string
	KeyFile  string

	Proc *supervisor.Process
}

// Protocol implements core.Backend.
func (b *Backend) Protocol() string { return config.AnyConnect }

func (b *Backend) occtlSocket() string { return filepath.Join(b.RunDir, "occtl.socket") }

// Setup registers config files.
func (b *Backend) Setup() error {
	if err := os.MkdirAll(b.Dir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(b.RunDir, 0o755); err != nil {
		return err
	}
	b.Configs.Register(&backend.ConfigFile{Name: "ocserv.conf", Backend: config.AnyConnect, Path: filepath.Join(b.Dir, "ocserv.conf"), Generate: b.generate})
	// Client profile: Cisco Secure Client stores it under this file name, so
	// it is unique per gateway and does not replace other gateways' entries.
	// Workers (nobody) read it, hence the runtime directory.
	b.Configs.Register(&backend.ConfigFile{Name: "anyconnect-profile.xml", Backend: config.AnyConnect, Path: b.profileFile(), Mode: 0o644,
		Generate: b.clientProfile})
	b.Configs.Register(&backend.ConfigFile{Name: "ocserv-radiusclient.conf", Backend: config.AnyConnect, Path: filepath.Join(b.Dir, "radiusclient.conf"),
		Generate: func() (string, error) {
			return backend.Render("ocserv-radiusclient.conf.tmpl", map[string]any{
				"NASIdentifier": radius.NASAnyConnect, "AuthServer": b.Radius.AuthAddr, "AcctServer": b.Radius.AcctAddr, "Dir": b.Dir,
			})
		}})
	// The stock radcli dictionary leaves out Microsoft's attributes, so
	// ocserv would drop the per-session DNS servers (MS-Primary-DNS-Server).
	b.Configs.Register(&backend.ConfigFile{Name: "ocserv-radius-dictionary", Backend: config.AnyConnect, Path: filepath.Join(b.Dir, "dictionary"),
		Generate: func() (string, error) {
			return "$INCLUDE /etc/radcli/dictionary\n$INCLUDE /etc/radcli/dictionary.microsoft\n", nil
		}})
	b.Configs.Register(&backend.ConfigFile{Name: "ocserv-radius-servers", Backend: config.AnyConnect, Path: filepath.Join(b.Dir, "radius-servers"),
		Mode: 0o600, Secret: true,
		Generate: func() (string, error) {
			host, _, _ := strings.Cut(b.Radius.AuthAddr, ":")
			return fmt.Sprintf("%s %s\n", host, b.Radius.Secret), nil
		}})
	return nil
}

// profileFile is the client profile path: <VPN_HOSTNAME>.xml.
func (b *Backend) profileFile() string {
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, b.Cfg.Str("VPN_HOSTNAME"))
	return filepath.Join(b.RunDir, name+".xml")
}

// clientProfile is the AnyConnect XML profile: one server entry per VPN
// endpoint.
func (b *Backend) clientProfile() (string, error) {
	var s strings.Builder
	s.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
  <ClientInitialization>
    <UseStartBeforeLogon UserControllable="false">false</UseStartBeforeLogon>
    <AutomaticCertSelection UserControllable="false">true</AutomaticCertSelection>
    <ShowPreConnectMessage>false</ShowPreConnectMessage>
    <CertificateStore>All</CertificateStore>
    <CertificateStoreOverride>false</CertificateStoreOverride>
    <ProxySettings>Native</ProxySettings>
    <AllowLocalProxyConnections>true</AllowLocalProxyConnections>
    <AuthenticationTimeout>30</AuthenticationTimeout>
    <AutoConnectOnStart UserControllable="true">false</AutoConnectOnStart>
    <MinimizeOnConnect UserControllable="true">true</MinimizeOnConnect>
    <LocalLanAccess UserControllable="true">false</LocalLanAccess>
    <AutoReconnect UserControllable="false">true
      <AutoReconnectBehavior UserControllable="false">ReconnectAfterResume</AutoReconnectBehavior>
    </AutoReconnect>
    <AutoUpdate UserControllable="false">false</AutoUpdate>
    <RSASecurIDIntegration UserControllable="false">Automatic</RSASecurIDIntegration>
    <WindowsLogonEnforcement>SingleLocalLogon</WindowsLogonEnforcement>
    <WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
    <AutomaticVPNPolicy>false</AutomaticVPNPolicy>
    <PPPExclusion UserControllable="false">Disable</PPPExclusion>
    <EnableScripting UserControllable="false">false</EnableScripting>
    <EnableAutomaticServerSelection UserControllable="false">false</EnableAutomaticServerSelection>
    <RetainVpnOnLogoff>false</RetainVpnOnLogoff>
  </ClientInitialization>
  <ServerList>
`)
	for _, e := range b.Cfg.Endpoints() {
		// The domain first: clients list entries of several gateways
		// together, sorted by name.
		name := e.Host
		if e.Label != "" {
			name = e.Host + " (" + e.Label + ")"
		}
		s.WriteString("    <HostEntry>\n      <HostName>")
		_ = xml.EscapeText(&s, []byte(name))
		s.WriteString("</HostName>\n      <HostAddress>")
		_ = xml.EscapeText(&s, []byte(e.Host))
		s.WriteString("</HostAddress>\n    </HostEntry>\n")
	}
	s.WriteString("  </ServerList>\n</AnyConnectProfile>\n")
	return s.String(), nil
}

func (b *Backend) generate() (string, error) {
	pool := b.Core.IPAM.Pool(config.AnyConnect).Prefix()
	return backend.Render("ocserv.conf.tmpl", map[string]any{
		"Dir": b.Dir, "RunDir": b.RunDir, "TCPPort": TCPPort, "UDPPort": 443,
		"CertFile": b.CertFile, "KeyFile": b.KeyFile,
		"PoolNetwork": pool.Addr().String(), "PoolNetmask": net.IP(net.CIDRMask(pool.Bits(), 32)).String(),
		// Relative to the working directory (RunDir): clients see
		// "profiles/<name>.xml" and save the profile under that name.
		"ProfileFile": filepath.Base(b.profileFile()),
	})
}

// Process returns the supervised process.
func (b *Backend) Process() *supervisor.Process {
	if b.Proc == nil {
		b.Proc = &supervisor.Process{
			Name:        "ocserv",
			BeforeStart: func() error { return b.Configs.WriteBackend(config.AnyConnect) },
			Command: func() *exec.Cmd {
				cmd := exec.Command("ocserv", "--foreground", "--config", filepath.Join(b.Dir, "ocserv.conf"))
				cmd.Dir = b.RunDir // user-profile is relative to it
				return cmd
			},
		}
	}
	return b.Proc
}

func (b *Backend) occtl(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	full := append([]string{"--socket-file", b.occtlSocket()}, args...)
	out, err := exec.CommandContext(ctx, "occtl", full...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("occtl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Reload makes ocserv re-read its certificate without dropping sessions.
func (b *Backend) Reload(ctx context.Context) error {
	if b.Proc == nil || !b.Proc.Running() {
		return nil
	}
	_, err := b.occtl(ctx, "reload")
	return err
}

type occtlUser struct {
	ID       int64  `json:"ID"`
	Username string `json:"Username"`
	IPv4     string `json:"IPv4"`
	RemoteIP string `json:"Remote IP"`
	RX       any    `json:"RX"`
	TX       any    `json:"TX"`
	ConnAt   any    `json:"raw_connected_at"`
	State    string `json:"State"`
}

func num(v any) uint64 {
	switch t := v.(type) {
	case float64:
		return uint64(t)
	case string:
		n, _ := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
		return n
	}
	return 0
}

// Poll implements core.Backend.
func (b *Backend) Poll(ctx context.Context) ([]core.LiveSession, error) {
	if b.Proc == nil || !b.Proc.Running() {
		return nil, errors.New("ocserv not running")
	}
	out, err := b.occtl(ctx, "--json", "show", "users")
	if err != nil {
		return nil, err
	}
	var users []occtlUser
	if err := json.Unmarshal(out, &users); err != nil {
		return nil, fmt.Errorf("parse occtl output: %w", err)
	}
	res := make([]core.LiveSession, 0, len(users))
	for _, u := range users {
		ip, err := netip.ParseAddr(u.IPv4)
		if err != nil {
			continue
		}
		ls := core.LiveSession{VPNIP: ip, BackendRef: strconv.FormatInt(u.ID, 10), ClientIP: u.RemoteIP, Username: u.Username,
			BytesIn: num(u.RX), BytesOut: num(u.TX)}
		if ts := num(u.ConnAt); ts > 0 {
			ls.Since = time.Unix(int64(ts), 0)
		}
		res = append(res, ls)
	}
	return res, nil
}

// Disconnect implements core.Backend.
func (b *Backend) Disconnect(s *core.Session) error {
	if s.BackendRef != "" {
		_, err := b.occtl(context.Background(), "disconnect", "id", s.BackendRef)
		return err
	}
	live, err := b.Poll(context.Background())
	if err != nil {
		return err
	}
	for _, l := range live {
		if l.VPNIP == s.VPNIP {
			_, err := b.occtl(context.Background(), "disconnect", "id", l.BackendRef)
			return err
		}
	}
	return errors.New("session not found in ocserv")
}
