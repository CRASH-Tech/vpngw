# vpngw — VPN gateway with OIDC sign-in

One Docker image that turns a host into a VPN gateway for **Cisco AnyConnect
(ocserv)**, **OpenVPN 2.6** and **IKEv2 (strongSwan, EAP-MSCHAPv2)**. Users sign
in to the portal with their company account (OIDC), get a VPN password and
ready-made profiles, and connect with any of the three protocols. Routes and
access come from the user's IdP groups and are enforced with nftables.

The operator never edits ocserv, OpenVPN or strongSwan configuration: the
application generates it, starts the servers and reloads them.

## Features

- Portal sign-in through OIDC (tested with Authentik); VPN password derived
  from the IdP session, shown on the portal, valid while the IdP session lives.
- Logins `user@group` choose the network: routes (`vpnRoutes`), exclusions
  (`!cidr`), DNS and an optional egress tunnel (`vpnGateway`) per group. The
  plain login `user` gets the networks of all groups except `0.0.0.0/0`:
  internet through the VPN only with an explicit group.
- Built-in RADIUS server: PAP for ocserv, EAP-MSCHAPv2 (RFC 2759/3079/2548/3579)
  for strongSwan.
- Addresses from per-protocol pools; firewall table `inet vpngw` allows each
  client only its networks, regardless of the routes on the client — the
  gateway host's own services included (clients may only ping it and use its
  DNS); sites through the tunnels likewise reach only what they are allowed.
- Session revalidation against the IdP every 5 minutes, grace period when the
  IdP is down (fail closed afterwards), back-channel logout, immediate
  firewall updates when groups change.
- Tunnels to remote sites (embedded goproxy): subnets behind each site are
  routed into its tunnel for every client allowed to reach them; `vpnGateway`
  sends a group's internet through a chosen site — see [docs/tunnels.md](docs/tunnels.md).
- Domain proxy: a group with `vpnDomains` (or routed hosts with
  `TUNNEL_TRANSIT_DOMAINS`) sends only those sites through its `vpnGateway`. The gateway's DNS answers them with addresses of a routed pool
  and forwards their connections; other traffic stays outside the tunnel.
- Emergency administrator that works for portal and all protocols without the IdP.
- Admin panel: live sessions with traffic and rates (SSE), users and traffic
  history with each login's networks and tunnels, journal with CSV export,
  status, settings, manual config overrides, certificate upload.
- Certificates: operator file (reloaded on change), upload in the panel,
  Let's Encrypt (HTTP-01) or a temporary self-signed certificate.

## Modes

- **VPN gateway** (`OIDC_ISSUER` set): user portal, AnyConnect, OpenVPN,
  IKEv2 and tunnels to remote sites.
- **Tunnel gateway** (`OIDC_ISSUER` empty): only the tunnels to remote sites
  run; ocserv, OpenVPN and strongSwan are not started. The admin panel is on
  `PORTAL_PORT` (8443) for the local administrator (`EMERGENCY_USER`/`EMERGENCY_PASS`);
  ports 443 and 80 stay free (80 is used only with `ACME_ENABLED=true`).
  Forwarded traffic from `TUNNEL_TRANSIT_SOURCES` is routed into the tunnels;
  the host's own traffic is not. Minimal configuration:

```yaml
    environment:
      PORTAL_HOSTNAME: gw.example.com
      EMERGENCY_USER: admin
      EMERGENCY_PASS: change-me
      TUNNEL_TRANSIT_SOURCES: 192.168.10.0/24
      TUNNEL_PEER_DC1_PUBLIC_KEY: ...
      TUNNEL_PEER_DC1_ENDPOINT: dc1.example.com:444
      TUNNEL_PEER_DC1_SUBNETS: 10.6.0.0/16
```

## Quick start

1. Configure the IdP — for Authentik follow [docs/authentik.md](docs/authentik.md)
   (scope mapping `vpn`, `offline_access`, refresh token validity, back-channel logout).
2. Point DNS for `VPN_HOSTNAME` (and `PORTAL_HOSTNAME`) to the host and open
   TCP 80/443, UDP 443/500/4500/1194 (OpenVPN: `OPENVPN_PROTO`/`OPENVPN_PORT`).
3. Create `docker-compose.yml`:

```yaml
services:
  vpngw:
    image: vpngw:latest
    network_mode: host
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun]
    volumes: [./data:/data]
    restart: unless-stopped
    environment:
      VPN_HOSTNAME: vpn.example.com
      PORTAL_HOSTNAME: portal.example.com      # same as VPN_HOSTNAME → portal on :8443
      OIDC_ISSUER: https://auth.example.com/application/o/vpn/
      OIDC_CLIENT_ID: vpngw
      OIDC_CLIENT_SECRET: change-me
      ADMIN_GROUP: vpn-admins
      EMERGENCY_USER: superadmin
      EMERGENCY_PASS: change-me-too
      ACME_ENABLED: "true"                       # optional: Let's Encrypt (off by default)
      ACME_EMAIL: admin@example.com
```

4. `docker compose up -d`, open the portal and sign in.

To use your own certificate, put `tls.crt` (full chain) and `tls.key` into
`./data/tls/` — replacing the files later reloads all services without
dropping sessions.

The host must have IPv4 forwarding enabled (`net.ipv4.ip_forward=1`; Docker
usually enables it). If Docker is installed, vpngw adds ACCEPT rules for the
VPN pools to the `DOCKER-USER` chain because Docker's `FORWARD` policy is DROP.

## Configuration

Every setting can be given as an environment variable or in the admin
panel (*Settings*). A setting given in the environment is fixed: the panel
shows it greyed out and it can only be changed in the environment
(docker-compose). The other settings are changed in the panel; *reset*
returns them to the default.

The environment is checked at startup, tunnel peers (`TUNNEL_PEER_*`)
included, with the same rules as the panel. Invalid values, unknown
variables that look like settings (typos) and invalid peers stop the
gateway with a list of all problems, e.g.:

```
vpngw: invalid configuration, not starting:
  - unknown setting OPENVPN_PROTOCOL (did you mean OPENVPN_PROTO?)
  - TUNNEL_PEER_DC1: networks behind the site: 0.0.0.0/0 would send everything into this tunnel; mark the site as internet exit instead
```

Defaults:

| Variable | Default | Meaning |
|---|---|---|
| `NODE_NAME` | `VPN_HOSTNAME` | name of this gateway in the panel header, page titles and for other sites |
| `VPN_ENDPOINTS` | | more addresses clients may use, e.g. `Riga=vpn-riga.example.com, vpn2.example.com`; the portal lists them all, `.ovpn` profiles fail over between them; the certificate must cover them for AnyConnect/IKEv2 |
| `OIDC_SCOPES_EXTRA` | | extra scopes |
| `OIDC_USERNAME_CLAIM` / `OIDC_GROUPS_CLAIM` / `OIDC_ROUTES_CLAIM` | `preferred_username` / `groups` / `vpn` | claim names |
| `OIDC_REVALIDATE_INTERVAL` / `OIDC_GRACE_PERIOD` | `5m` / `15m` | session checks |
| `OIDC_MAX_CONCURRENCY` | `10` | parallel refreshes |
| `OIDC_INTROSPECTION` | `false` | also check access tokens (RFC 7662) |
| `VPN_POOLS` | `anyconnect=10.250.0.0/20,openvpn=10.250.16.0/20,ikev2=10.250.32.0/20` | address pools |
| `VPN_EGRESS_IFACE` | default route | NAT interface |
| `VPN_DNS`, `VPN_DNS_DOMAIN` | | defaults when a full-tunnel group has no DNS. Split-tunnel logins get no DNS at all: clients keep their own resolvers |
| `VPN_FULL_TUNNEL_DNS` | `1.1.1.1 1.0.0.1` | DNS for full-tunnel groups that have none (clients' own resolvers are usually in their home network, which a full tunnel does not reach); empty disables |
| `SESSION_LIMIT` | `3` | sessions per user |
| `CLIENT_TO_CLIENT` | `false` | traffic between VPN clients |
| `OPENVPN_PORT` / `PORTAL_PORT` | `1194` / `8443` | ports |
| `OPENVPN_PROTO` / `OPENVPN_MTU` | `udp` / `1420` | OpenVPN transport (`udp`, `tcp`) and tunnel MTU pushed to clients (MSS clamped to MTU − 60) |
| `ENABLE_ANYCONNECT` / `ENABLE_OPENVPN` / `ENABLE_IKEV2` | `true` | protocols |
| `IKEV2_LOCAL_ID` | `auto` | IKE identity (see below) |
| `IKEV2_KERNEL_LIBIPSEC` | `false` | userspace IPsec instead of XFRM |
| `ACME_ENABLED` / `ACME_STAGING` / `ACME_EMAIL` | `false` / `false` | Let's Encrypt (HTTP-01 on port 80) when no certificate file is present |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | `/data/tls/tls.{crt,key}` | operator certificate |
| `MASTER_KEY` | generated in `/data/master.key` | encryption of secrets |
| `AUTH_FAIL_LIMIT` / `AUTH_FAIL_WINDOW` / `AUTH_BLOCK_DURATION` | `10` / `5m` / `15m` | brute-force protection |
| `AUDIT_RETENTION_DAYS` | `90` | journal retention |
| `METRICS_ALLOWED_NETWORKS` | | networks that may read `/metrics` (e.g. the Prometheus host); with `METRICS_TOKEN` set, the token is required as well |
| `METRICS_TOKEN` | | bearer token for `/metrics`; alone it allows any address with the token |
| `TUNNEL_*`, `TUNNEL_PEER_<NAME>_*` | | tunnels to remote sites, see [docs/tunnels.md](docs/tunnels.md) |
| `TUNNEL_TRANSIT_SOURCES` | | source networks whose forwarded traffic is routed into the tunnels |
| `TUNNEL_LOCAL_NETWORKS` | | this site's networks besides `ALLOW` and `TUNNEL_TRANSIT_SOURCES`: always via the host's routes, also with `vpnGateway` |
| `TUNNEL_TRANSIT_GATEWAY` | | internet exit site for those networks (empty: the host's default gateway) |
| `OIDC_LOGOUT` | `app` | sign-out returns to the portal and the next SSO sign-in asks for the password; `idp`: RP-initiated logout at the IdP |
| `VPN_DOMAIN_POOL` | `198.18.0.0/16` | addresses for `vpnDomains` names (domain proxy, see [docs/authentik.md](docs/authentik.md)); the first one is the gateway's DNS server for such logins |
| `TUNNEL_TRANSIT_DOMAINS` / `_GATEWAY` / `_DNS` | | domain proxy for `TUNNEL_TRANSIT_SOURCES`, see [docs/tunnels.md](docs/tunnels.md) |
| `EMERGENCY_DOMAINS` | | domains the emergency administrator reaches through `EMERGENCY_GATEWAY` |
| `CLIENTS_DIR` | `/usr/share/vpngw/clients` | client installers offered in the portal, see below |
| `LOG_LEVEL` | `info` | |

The full list with descriptions is in the admin panel and in
[internal/config/config.go](internal/config/config.go).

**Wildcard certificates and IKEv2.** strongSwan-based clients do not match
wildcard certificate names. With `IKEV2_LOCAL_ID=auto` the gateway uses
`VPN_HOSTNAME` when the certificate names it exactly, otherwise another
(non-wildcard) name from the certificate; the generated client profiles use
the same identity.

**AnyConnect profile.** ocserv hands Cisco Secure Client an XML profile
named after `VPN_HOSTNAME` (e.g. `vpn.example.com.xml`) listing the VPN
endpoints; the client stores profiles by file name, so gateways do not
replace each other's entries.

**Large lists.** Clients get at most `OPENVPN_ROUTE_LIMIT` (1000),
`ANYCONNECT_ROUTE_LIMIT` (200, and what fits into one RADIUS packet) and
`IKEV2_ROUTE_LIMIT` (200 traffic selectors) routes; longer lists are merged
into wider routes (the admin panel's user page says so), while the firewall
still allows only the exact networks. Excluded networks (`!`) inside a
merged route then go into the tunnel and are blocked there instead of
leaving through the client's own connection: with long lists keep the
exclusions few or wide. Tested with 20000 networks and 50000
`vpnDomains`: every protocol connects in a few seconds. Without the limits
OpenVPN clients spend long installing routes and IKEv2 clients reject the
IKE message (strongSwan above about 600 traffic selectors). The IdP sends
the lists in the token, so very long ones make tokens large; with
`OIDC_LOGOUT=idp` the token travels in the logout URL.

**Client downloads.** The installers and app store links listed in
`CLIENTS_DIR/info.txt` are shown in the portal's instructions, in the tab of
their protocol and operating system:

```yaml
anyconnect:                       # protocol: anyconnect, openvpn or ikev2
  - description: Cisco Secure Client
    os: windows                   # windows, macos, linux, ios or android
    file: anyconnect/client.msi   # relative to CLIENTS_DIR
  - description: Cisco Secure Client
    os: ios
    link: https://apps.apple.com/app/...
```

Images built with `CLIENTS=include` contain the repository's `clients/`
directory (the installers themselves are not in git: put them next to
`info.txt` before building); without it the list is empty and the portal
shows no clients. Mount another directory there to change the list without
rebuilding.
Only files listed in `info.txt` are served, and only to signed-in users;
clients of disabled protocols are hidden. Problems in `info.txt` (missing
files, bad paths) are logged and the rest of the list is shown.

**OpenVPN certificate.** OpenVPN uses the portal's certificate too. Its
clients do not read the system trust store, so `.ovpn` profiles carry the
root of the chain (taken from the system CA bundle, e.g. ISRG Root X1) and pin
the certificate's subject CN (`verify-x509-name`). If the certificate is
self-signed, has no CN or its root is unknown, OpenVPN falls back to an
internal CA. Profiles downloaded before such a switch must be downloaded
again. DH parameters (2048-bit) are generated on first start in the
background; ECDHE is used until they are ready.

## How it works

```
                 ┌──────────────────────── container (host network) ───────────────────────┐
 TCP 443 ──► SNI router ──► portal (Go)            ┌─► ocserv  ─┐
             └─(PROXY v2)──► ocserv :4443           │            │  RADIUS 127.0.0.1:1812/1813
 UDP 443 ─────────────────► ocserv DTLS             │            ▼
 UDP 1194 ────────────────► OpenVPN ── management ──┼──────► vpngw core ◄── OIDC (refresh, logout)
 UDP 500/4500 ────────────► charon ─── VICI ────────┘            │
                                                   nftables table inet vpngw + policy routing
```

- `cmd/vpngw` — entry point, process supervision, listeners.
- `internal/core` — users, passwords, authorization, sessions, revalidation.
- `internal/oidc`, `internal/radius`, `internal/eap`, `internal/policy`,
  `internal/ipam`, `internal/firewall`, `internal/backend/{ocserv,openvpn,strongswan}`,
  `internal/portal`, `internal/admin`, `internal/store`, `internal/tlsmgr`, `internal/supervisor`.
- `internal/tunnels` + `internal/goproxy` — links to remote sites (embedded goproxy node).
- `templates/` — backend config templates, HTML pages and static assets.

## Development

```sh
make test     # unit tests (EAP vectors, policy, RADIUS, revalidation with a mock IdP, golden configs)
make image    # build the image
make run-dev  # run deploy/dev (needs deploy/dev/.env)
make e2e      # end-to-end scenarios against deploy/dev and the test IdP
```

The image is built with or without VPN client installers (build argument
`CLIENTS`). `make image` includes them when installers lie next to
`clients/info.txt` (they are not in git); a plain `docker build .` and the
CI image (`ghcr.io/<owner>/<repo>`, pushed from `main` and `v*` tags) are
built with `CLIENTS=none`, and the portal then shows no client downloads:

```sh
docker build --build-arg CLIENTS=include -t vpngw .   # with clients/
docker build -t vpngw .                                # without (default)
```

An image without them can still offer clients: mount a directory with an
`info.txt` at `CLIENTS_DIR` (`/usr/share/vpngw/clients`).

See [docs/progress.md](docs/progress.md) and [docs/manual-testing.md](docs/manual-testing.md).

## Metrics

`/metrics` (portal port, Prometheus text format) is readable from localhost and
from `METRICS_ALLOWED_NETWORKS` (plus `METRICS_TOKEN` if set). Besides gateway
health (backends, IdP, certificate, pools, sessions per protocol) it has:

| Metric | Labels | Meaning |
|---|---|---|
| `vpngw_user_connections_total` | `user`, `protocol` | sessions established |
| `vpngw_user_traffic_bytes_total` | `user`, `protocol`, `direction` | traffic; `received` from the client, `sent` to it |
| `vpngw_user_sessions` | `user`, `protocol` | live sessions |
| `vpngw_user_last_connect_timestamp_seconds` | `user`, `protocol` | last session established |
| `vpngw_session_traffic_bytes` | `user`, `login`, `protocol`, `vpn_ip`, `client_ip`, `direction` | traffic of a live session |
| `vpngw_session_start_timestamp_seconds` | same, without `direction` | start of a live session |

The `_total` counters count since the gateway started; use `increase()` or
`rate()` in queries, e.g. traffic per user over 30 days:
`sum by (user) (increase(vpngw_user_traffic_bytes_total[30d]))`.

