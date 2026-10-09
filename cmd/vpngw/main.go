// Command vpngw is the VPN gateway: it configures and supervises ocserv,
// OpenVPN and strongSwan, authenticates users via OIDC, assigns addresses,
// enforces routes with nftables and serves the user portal and admin panel.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"vpngw/internal/admin"
	"vpngw/internal/backend"
	"vpngw/internal/backend/ocserv"
	"vpngw/internal/backend/openvpn"
	"vpngw/internal/backend/strongswan"
	"vpngw/internal/config"
	"vpngw/internal/core"
	"vpngw/internal/dnsproxy"
	"vpngw/internal/firewall"
	gpkeys "vpngw/internal/goproxy/keys"
	"vpngw/internal/logx"
	"vpngw/internal/oidc"
	"vpngw/internal/pki"
	"vpngw/internal/portal"
	"vpngw/internal/radius"
	"vpngw/internal/secret"
	"vpngw/internal/sni"
	"vpngw/internal/store"
	"vpngw/internal/supervisor"
	"vpngw/internal/tlsmgr"
	"vpngw/internal/tunnels"
)

// version is set at build time.
var version = "dev"

const runDir = "/run/vpngw"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "tls-verify":
			os.Exit(tlsVerify())
		case "healthcheck":
			os.Exit(healthcheck())
		case "version":
			fmt.Println(version)
			return
		case "genkey", "keypair":
			// Tunnel node keys: vpngw keypair prints a private and a public key.
			k, err := gpkeys.GeneratePrivateKey()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if os.Args[1] == "genkey" {
				fmt.Println(k.String())
			} else {
				fmt.Printf("private: %s\npublic:  %s\n", k, k.Public())
			}
			return
		case "pubkey":
			b, _ := io.ReadAll(os.Stdin)
			k, err := gpkeys.ParsePrivateKey(strings.TrimSpace(string(b)))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(k.Public())
			return
		}
	}
	if err := run(); err != nil {
		// Plain text: configuration problems are a readable list.
		fmt.Fprintln(os.Stderr, "vpngw:", err)
		os.Exit(1)
	}
}

func ctlClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", filepath.Join(runDir, "ctl.sock"))
		},
	}}
}

// tlsVerify is invoked by OpenVPN (tls-crypt-v2-verify) before the TLS
// handshake; exit status 0 accepts the client key.
func tlsVerify() int {
	if os.Getenv("metadata_type") != "0" {
		return 1
	}
	meta, err := os.ReadFile(os.Getenv("metadata_file"))
	if err != nil {
		return 1
	}
	resp, err := ctlClient().Post("http://ctl/tls-verify", "text/plain", strings.NewReader(string(meta)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls-verify:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		fmt.Fprintln(os.Stderr, "tls-verify: rejected:", strings.TrimSpace(string(b)))
		return 1
	}
	return 0
}

func healthcheck() int {
	resp, err := ctlClient().Get("http://ctl/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(b)))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// configError lists configuration problems; the gateway does not start.
func configError(problems []string) error {
	return fmt.Errorf("invalid configuration, not starting:\n  - %s", strings.Join(problems, "\n  - "))
}

func run() error {
	cfg := config.New()
	logx.Setup(os.Stdout, cfg.Str("LOG_LEVEL"))
	if missing := cfg.CheckRequired(); len(missing) > 0 {
		return fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	if problems := append(config.CheckEnv(os.Environ()), tunnels.CheckEnv(cfg, prefixes(cfg))...); len(problems) > 0 {
		return configError(problems)
	}
	for _, k := range []string{"OIDC_CLIENT_SECRET", "EMERGENCY_PASS", "MASTER_KEY", "METRICS_TOKEN"} {
		logx.AddRedaction(cfg.Str(k))
	}
	slog.Info("starting vpngw", "version", version)

	// 1. Database and keys.
	dataDir := cfg.Str("DATA_DIR")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dataDir, 0o700)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	master, err := secret.LoadMasterKey(dataDir, cfg.Str("MASTER_KEY"))
	if err != nil {
		return err
	}
	box, err := secret.NewBox(master)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dataDir, "vpngw.db"))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()
	_ = os.Chmod(filepath.Join(dataDir, "vpngw.db"), 0o600)
	if ov, err := st.Settings(); err == nil {
		cfg.SetOverrides(ov)
		logx.SetLevel(cfg.Str("LOG_LEVEL"))
	}
	_ = st.CloseOrphanSessions("gateway restarted")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// 2. Certificate.
	tlsm := tlsmgr.New(cfg)
	if err := tlsm.Init(); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	// 3. Tunnels to remote sites and the firewall that routes into them.
	tun := &tunnels.Manager{Cfg: cfg, Store: st, Box: box, Dir: filepath.Join(dataDir, "tunnels")}
	if problems := tun.CheckTransitGateway(); len(problems) > 0 {
		return configError(problems)
	}
	if os.Getenv("TUNNEL_EXIT_NETWORKS") != "" {
		slog.Warn("TUNNEL_EXIT_NETWORKS is ignored: set what each site may reach with TUNNEL_PEER_<NAME>_ALLOW")
	}
	// Domain proxy (vpnDomains): the gateway's DNS server and its pool.
	domainPool, domainDNS := cfg.DomainPool()
	dnsPort := 0
	if domainPool.IsValid() {
		dnsPort = dnsproxy.Port
	}
	fw := firewall.New(firewall.Options{Pools: prefixes(cfg), EgressIface: cfg.Str("VPN_EGRESS_IFACE"),
		DomainPool: domainPool, DNSServer: domainDNS, DNSPort: dnsPort, TransitDomainsGateway: cfg.TransitDomainsGateway,
		ClientToClient: cfg.Bool("CLIENT_TO_CLIENT"), DockerCompat: cfg.Bool("DOCKER_COMPAT"),
		Resolve: func(gw string) firewall.Target {
			if p, ok := tun.Find(gw); ok {
				return firewall.Target{Dev: p.Interface(), Tunnel: true}
			}
			return firewall.Target{}
		},
		TransitSources: cfg.TransitSources,
		// This site's own networks: TUNNEL_LOCAL_NETWORKS, the hosts routed
		// through it and what it opens to other sites (ALLOW).
		LocalNetworks: func() []netip.Prefix {
			out := append(cfg.LocalNetworks(), cfg.TransitSources()...)
			for _, a := range tun.Allowances() {
				if a.Prefix.Bits() > 0 {
					out = append(out, a.Prefix)
				}
			}
			return out
		},
		TransitGateway: func() string {
			if gw := cfg.Str("TUNNEL_TRANSIT_GATEWAY"); !cfg.IsSelf(gw) {
				return gw
			}
			return "" // this node itself: the host's default route
		},
		Allowances: func() []firewall.Allowance {
			var out []firewall.Allowance
			for _, a := range tun.Allowances() {
				out = append(out, firewall.Allowance{Dev: a.Dev, Prefix: a.Prefix})
			}
			return out
		},
		PeerRoutes: func() []firewall.PeerRoute {
			var out []firewall.PeerRoute
			for _, r := range tun.Routes() {
				out = append(out, firewall.PeerRoute{Prefix: r.Prefix, Dev: r.Dev})
			}
			return out
		},
	})
	tun.OnChange = func() {
		tun.EnsureAddresses()
		fw.Reconcile()
	}
	if err := fw.Init(); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	defer fw.Shutdown()
	slog.Info("firewall ready", "egress", fw.EgressIface())

	oc := oidc.New(oidc.Config{
		Issuer: cfg.Str("OIDC_ISSUER"), ClientID: cfg.Str("OIDC_CLIENT_ID"), ClientSecret: cfg.Str("OIDC_CLIENT_SECRET"),
		RedirectURL: cfg.PortalURL() + "/oidc/callback", ExtraScopes: cfg.List("OIDC_SCOPES_EXTRA"),
		UsernameClaim: cfg.Str("OIDC_USERNAME_CLAIM"), GroupsClaim: cfg.Str("OIDC_GROUPS_CLAIM"), RoutesClaim: cfg.Str("OIDC_ROUTES_CLAIM"),
		DecryptionKey: cfg.Str("OIDC_ID_TOKEN_DECRYPTION_KEY"),
	})
	vpn := cfg.VPNEnabled()
	if vpn {
		go func() {
			if err := oc.Ready(ctx); err != nil {
				slog.Warn("identity provider discovery failed, will retry on demand", "err", err)
			}
		}()
	} else {
		slog.Info("OIDC_ISSUER is not set: user VPN (AnyConnect, OpenVPN, IKEv2) is off, only tunnels run")
	}

	c := core.New(cfg, st, master, box, oc, fw)
	var dp *dnsproxy.Server
	if dnsPort != 0 {
		system := dnsproxy.SystemResolvers()
		dp = &dnsproxy.Server{
			Pool: domainPool,
			Lookup: func(ip netip.Addr) (dnsproxy.Policy, bool) {
				if s, ok := c.SessionByIP(ip); ok {
					p := s.Profile
					if p == nil || len(p.Domains) == 0 {
						return dnsproxy.Policy{}, false
					}
					return dnsproxy.Policy{Domains: p.Domains, Upstream: p.Upstream, Gateway: p.Gateway, Mark: fw.GatewayMark(p.Gateway)}, true
				}
				// Hosts routed through this node (TUNNEL_TRANSIT_SOURCES).
				for _, src := range cfg.TransitSources() {
					if src.Contains(ip) {
						gw := cfg.TransitDomainsGateway()
						return dnsproxy.Policy{Domains: cfg.TransitDomains(), Upstream: cfg.Addrs("TUNNEL_TRANSIT_DOMAINS_DNS"), Gateway: gw, Mark: fw.GatewayMark(gw)}, true
					}
				}
				return dnsproxy.Policy{}, false
			},
			Forwarders: func() []string {
				if dns := cfg.DNS(); len(dns) > 0 {
					out := make([]string, len(dns))
					for i, a := range dns {
						out[i] = net.JoinHostPort(a.String(), "53")
					}
					return out
				}
				return system
			},
			Map:   fw.MapDomain,
			Unmap: fw.UnmapDomain,
			Grant: fw.GrantDomain,
		}
		if err := dp.Start(ctx); err != nil {
			// The rest of the gateway works; vpnDomains names do not resolve.
			slog.Error("domain proxy DNS server cannot start: vpnDomains do not work", "port", dnsproxy.Port, "err", err)
		} else {
			slog.Info("domain proxy ready", "pool", domainPool, "dns", domainDNS, "resolvers", system)
		}
	}

	// 4. Backends (only with user VPN).
	configs := backend.NewConfigs(st)
	var procs []*supervisor.Process
	byProto := map[string]*supervisor.Process{}
	var ovpn *openvpn.Backend
	var ocs *ocserv.Backend
	var sw *strongswan.Backend
	if vpn {
		rad := radius.New(c)
		rad.ServerName = cfg.Str("VPN_HOSTNAME")
		if err := rad.Start(ctx); err != nil {
			return err
		}
		ca, err := pki.LoadOrCreate(st, box)
		if err != nil {
			return fmt.Errorf("pki: %w", err)
		}
		self, _ := os.Executable()
		ovpn = &openvpn.Backend{Core: c, Cfg: cfg, Configs: configs, CA: ca, Cert: tlsm, Dir: filepath.Join(dataDir, "openvpn"), RunDir: runDir, SelfBin: self}
		if err := ovpn.Setup(); err != nil {
			return fmt.Errorf("openvpn: %w", err)
		}
		ocs = &ocserv.Backend{Core: c, Cfg: cfg, Configs: configs, Radius: rad, Dir: filepath.Join(dataDir, "run", "ocserv"),
			RunDir: filepath.Join(runDir, "ocserv"), CertFile: tlsm.RuntimeCert(), KeyFile: tlsm.RuntimeKey()}
		if err := ocs.Setup(); err != nil {
			return fmt.Errorf("ocserv: %w", err)
		}
		sw = &strongswan.Backend{Core: c, Cfg: cfg, Configs: configs, Radius: rad, Dir: filepath.Join(dataDir, "run", "strongswan"),
			RunDir: runDir, CertFile: tlsm.RuntimeCert(), KeyFile: tlsm.RuntimeKey(), Identity: tlsm.IKEIdentity}
		if err := sw.Setup(); err != nil {
			return fmt.Errorf("strongswan: %w", err)
		}
		c.RegisterBackend(ocs)
		c.RegisterBackend(ovpn)
		c.RegisterBackend(sw)
		if cfg.Bool("ENABLE_ANYCONNECT") {
			p := ocs.Process()
			procs = append(procs, p)
			byProto[config.AnyConnect] = p
		}
		if cfg.Bool("ENABLE_OPENVPN") {
			p := ovpn.Process()
			procs = append(procs, p)
			byProto[config.OpenVPN] = p
			go ovpn.Run(ctx)
		}
		if cfg.Bool("ENABLE_IKEV2") {
			p := sw.Process()
			procs = append(procs, p)
			byProto[config.IKEv2] = p
			go sw.Run(ctx)
		}
		for _, p := range procs {
			go p.Run(ctx)
		}
		tlsm.OnChange(func() {
			if err := ocs.Reload(context.Background()); err != nil {
				slog.Warn("ocserv reload failed", "err", err)
			}
			sw.ReloadCertificate()
			ovpn.CertificateChanged()
		})
	}
	restartBackend := func(proto string) {
		if p, ok := byProto[proto]; ok {
			p.Restart()
		}
	}
	cfg.OnChange(func(keys []string) {
		restart := map[string]bool{}
		restartTunnels := false
		for _, k := range keys {
			switch k {
			case "LOG_LEVEL":
				logx.SetLevel(cfg.Str("LOG_LEVEL"))
			case "TUNNEL_TRANSIT_SOURCES", "TUNNEL_TRANSIT_GATEWAY", "TUNNEL_LOCAL_NETWORKS", "TUNNEL_TRANSIT_DOMAINS_GATEWAY":
				fw.Reconcile()
				continue
			case "CLIENT_TO_CLIENT", "VPN_EGRESS_IFACE":
				if err := fw.Reconfigure(cfg.Str("VPN_EGRESS_IFACE"), cfg.Bool("CLIENT_TO_CLIENT")); err != nil {
					slog.Error("firewall reconfigure", "err", err)
				}
			case "OPENVPN_PORT", "OPENVPN_PROTO", "OPENVPN_MTU":
				restart[config.OpenVPN] = true
			case "VPN_DNS", "VPN_DNS_DOMAIN":
				restart[config.AnyConnect] = true
			case "IKEV2_KERNEL_LIBIPSEC":
				restart[config.IKEv2] = true
			case "IKEV2_LOCAL_ID":
				if sw != nil {
					sw.ReloadCertificate()
				}
			case "EMERGENCY_ROUTES", "EMERGENCY_GATEWAY":
				c.EmergencyPolicyChanged()
			case "TLS_CERT_FILE", "TLS_KEY_FILE":
				_ = tlsm.Init()
			default:
				if strings.HasPrefix(k, "TUNNEL_") {
					restartTunnels = true
				}
			}
		}
		for p := range restart {
			restartBackend(p)
		}
		if restartTunnels {
			tun.Restart()
		}
	})

	// 5. Portal and admin panel.
	deps := portal.Deps{Core: c, Cfg: cfg, Store: st, OIDC: oc, TLS: tlsm, Configs: configs, Processes: procs, Version: version}
	if ovpn != nil {
		deps.OVPNProfile = func(username, meta string, remotes []string, name, login, password string) (string, error) {
			return ovpn.Profile(username, meta, remotes, openvpn.ProfileOptions{Name: name, Login: login, Password: password})
		}
	}
	srv, err := portal.New(deps)
	if err != nil {
		return err
	}
	admin.Register(srv, admin.Hooks{
		RestartBackend:   restartBackend,
		FirewallCounters: fw.Counters,
		FirewallRuleset:  fw.Ruleset,
		Gateways:         fw.GatewayStatus,
		EgressIface:      fw.EgressIface,
		StrongswanConns:  strongswanConns(sw),
		Tunnels:          tun,
		DomainMappings: func() []dnsproxy.Mapping {
			if dp == nil {
				return nil
			}
			return dp.Mappings()
		},
		PeerRoutes: fw.PeerRoutesStatus,
	})
	health := &healthHandler{st: st, procs: procs, oc: oc, core: c, tls: tlsm}
	srv.Mux.Handle("GET /healthz", health)
	srv.Mux.Handle("GET /metrics", metricsAuth(cfg, health.metrics))
	handler := srv.SecurityHeaders(srv.Mux)

	tlsCfg := &tls.Config{GetCertificate: tlsm.GetCertificate, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	httpSrv := &http.Server{Handler: handler, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		ErrorLog: slogLogger()}

	var l443 net.Listener
	router := &sni.Router{Backend: fmt.Sprintf("127.0.0.1:%d", ocserv.TCPPort)}
	if cfg.PortalPort() != 443 {
		lp, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.PortalPort()))
		if err != nil {
			return fmt.Errorf("portal port: %w", err)
		}
		go serveTLS(httpSrv, lp)
		slog.Info("portal listening", "url", cfg.PortalURL())
	}
	if vpn {
		// AnyConnect (and the portal, when it shares the name) on 443.
		l443, err = net.Listen("tcp", ":443")
		if err != nil {
			return fmt.Errorf("AnyConnect port: %w", err)
		}
		if cfg.PortalPort() == 443 {
			portalL := sni.NewChanListener(l443.Addr())
			router.Portal = portalL
			router.PortalHost = func() string { return cfg.Str("PORTAL_HOSTNAME") }
			go serveTLS(httpSrv, portalL)
			slog.Info("portal listening via SNI router", "url", cfg.PortalURL())
		}
		go func() {
			if err := router.Serve(l443); err != nil && !errors.Is(err, net.ErrClosed) {
				slog.Error("sni router stopped", "err", err)
			}
		}()
	}
	// Port 80: ACME HTTP-01 and a redirect to HTTPS. Without user VPN it is
	// opened only for ACME.
	go func() {
		if !vpn && !tlsm.ACMEEnabled() {
			return
		}
		h80 := &http.Server{Addr: ":80", ReadHeaderTimeout: 10 * time.Second, Handler: tlsm.HTTPHandler(func(r *http.Request) string {
			return cfg.PortalURL() + r.URL.RequestURI()
		})}
		if err := h80.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("port 80 unavailable (ACME HTTP-01 disabled)", "err", err)
		}
	}()
	ctl, err := startCtl(c, health)
	if err != nil {
		return err
	}
	defer ctl.Close()

	c.Start(ctx)
	go tlsm.Watch(ctx)
	go tun.Run(ctx)
	slog.Info("vpngw ready", "vpn_hostname", cfg.Str("VPN_HOSTNAME"), "portal", cfg.PortalURL())

	<-ctx.Done()
	slog.Info("shutting down")
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	_ = httpSrv.Shutdown(sctx)
	if l443 != nil {
		l443.Close()
	}
	c.Shutdown()
	time.Sleep(500 * time.Millisecond)
	return nil
}

func strongswanConns(sw *strongswan.Backend) func() []string {
	if sw == nil {
		return nil
	}
	return sw.LoadedProfiles
}

func serveTLS(s *http.Server, l net.Listener) {
	if err := s.ServeTLS(l, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		slog.Error("portal server stopped", "err", err)
	}
}

func prefixes(cfg *config.Config) []netipPrefix {
	var out []netipPrefix
	for _, proto := range config.Protocols {
		out = append(out, cfg.Pools()[proto])
	}
	return out
}

// startCtl serves the local control socket used by helper commands.
func startCtl(c *core.Core, health *healthHandler) (net.Listener, error) {
	path := filepath.Join(runDir, "ctl.sock")
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tls-verify", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err := c.VerifyTLSMeta(string(b)); err != nil {
			slog.Info("openvpn tls-crypt-v2 key rejected", "reason", err.Error())
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("GET /healthz", health)
	go func() { _ = http.Serve(l, mux) }()
	return l, nil
}

type slogWriter struct{}

func (slogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	// TLS handshake noise from scanners and clients without SNI.
	if strings.Contains(msg, "TLS handshake error") {
		slog.Debug(msg, "component", "http")
	} else {
		slog.Warn(msg, "component", "http")
	}
	return len(p), nil
}
