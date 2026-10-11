# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

vpngw is one Go binary in one Docker image that runs ocserv (AnyConnect),
OpenVPN 2.6 and strongSwan (IKEv2) and does everything around them: OIDC
sign-in, VPN passwords, a RADIUS server, address pools, nftables, a portal,
an admin panel and tunnels to remote sites. The operator never edits the
servers' configs; vpngw generates them and reloads the servers. The product
(UI, docs, logs, code comments) is English only; the user talks to you in
Russian.

## Commands

```sh
make build                 # bin/vpngw (CGO_ENABLED=0)
make test                  # go test ./cmd/... ./internal/... ./templates/...
make lint                  # gofmt + go vet
go test ./internal/policy -run TestWiden -v    # one test
go test ./internal/backend -update             # rewrite golden backend configs in internal/backend/testdata
make image                 # docker image; CLIENTS=include|none (installers in clients/)
```

CI (`.github/workflows/ci.yml`) additionally runs `go test -race ./...`,
`govulncheck` and a Trivy scan of the image. It triggers on `main` and `v*`
tags; this repository's branch is `master`.

End-to-end tests need Docker and `vpngw:latest`:

- `make e2e-sites` (`test/e2e/sites.sh`) — two vpngw sites in tunnels-only
  mode in containers; self-contained.
- `make e2e` (`test/e2e/run.sh` → `e2e.py`) — real `openconnect`, `openvpn`
  and `swanctl` clients against the dev deployment (`deploy/dev`, the
  container `vpngw` on this host, secrets in `deploy/dev/.env`) and the test
  Authentik. Needs Python 3 with `requests` and `playwright` (`E2E_PYTHON`)
  and site values in `test/e2e/e2e.env` (both env files gitignored).
  `test/e2e/fakedc.sh` plays the remote site "fakedc": a tunnels-only vpngw
  container with 10.4.0.0/16 behind it and an internet exit.

## Architecture

```
TCP 443 → SNI router (internal/sni) → portal | ocserv :4443 (PROXY v2)
ocserv ── RADIUS PAP ─────────┐
charon ── RADIUS EAP-MSCHAPv2 ┼→ internal/radius → internal/core ← OIDC refresh / back-channel logout
OpenVPN ── management iface ──┘  (backend/openvpn)       │
                                     nftables table inet vpngw + policy routing
```

`cmd/vpngw/main.go` wires everything; `internal/supervisor` runs the server
processes. In tunnels-only mode (`OIDC_ISSUER` empty) the three VPN servers
and the portal are not started, only tunnels and the admin panel.

**Authentication path.** Each backend turns a connection attempt into
`core.Credentials` and calls the core: ocserv via RADIUS PAP
(`AuthenticatePassword`), strongSwan via RADIUS EAP-MSCHAPv2 (`NTHashFor`,
then `Authorize`), OpenVPN via `client-auth` on the management interface.
`Core.Authorize` (internal/core/auth.go) checks the IdP verification age,
session limit, resolves the route profile, allocates the pool address, adds
the firewall entry and returns a *pending* session; it becomes *active* when
the backend reports it (`SessionStarted`). Backends implement `core.Backend`
(`Poll`, `Disconnect`); the core reconciles polled sessions.

**Route profiles (internal/policy).** The routes claim (`OIDC_ROUTES_CLAIM`,
default `vpn`) maps IdP groups to `vpnRoutes` (with `!cidr` exclusions),
`vpnGateway`, `vpnDNS`, `vpnDomain`, `vpnDomains`. A login `user@group`
picks one group; a plain `user` gets all groups merged minus `0.0.0.0/0`.
`policy.Resolve`/`Build` produce a `Profile` whose `ID` is a hash of its
contents; identical profiles share one ID across users. That ID is used
everywhere:
- firewall: per-profile chain `p_<id>` and allow set `a_<id>`;
- strongSwan: one swanctl connection per profile, chosen by
  `remote.groups`; the RADIUS Access-Accept carries the ID in `Class`.
  Connections must be loaded before IKE_AUTH, hence `core.ProfilePreparer`
  (`PrepareProfile`, `SyncProfiles`).

**The firewall is the access boundary, not the client routes.**
`Profile.Allow` is enforced exactly by nftables. The routes pushed to clients
may be wider: `policy.Widen`/`WidenTo` shrinks them to `OPENVPN_ROUTE_LIMIT`,
`ANYCONNECT_ROUTE_LIMIT` (also within one 4096-byte RADIUS packet) and
`IKEV2_ROUTE_LIMIT`, because clients fail or stall on long lists. Code in
`internal/policy/cidr.go` runs on every login and every admin user page
view, so keep it near-linear; lists of tens of thousands of networks and
domains are supported.

**Firewall (internal/firewall).** Driven through `nft -f` transactions, one
atomic transaction per change. The `inet vpngw` table is created once at
start and never recreated. `Options.DryRun` prints scripts instead of
running them (tests). Policy routing marks traffic per session/profile to
send it into a tunnel for `vpnGateway`.

**Domain proxy (internal/dnsproxy).** For profiles with `vpnDomains` the
client's DNS is the gateway's own server (first address of
`VPN_DOMAIN_POOL`). It answers listed names with fake addresses from that
pool, then maps fake→real and grants the client in nftables
(`MapDomain`/`GrantDomain`), so only those sites go through `vpnGateway`.

**The gateway's own connections through an exit.** The domain proxy's
DNS queries and the SOCKS5 proxy (`internal/socks`, `SOCKS_*`) set
`SO_MARK` from `firewall.ExitMark`/`GatewayMark`, so they are routed like
a VPN client with that `vpnGateway` (rules 15000–15999, see
`docs/tunnels.md`); a missing site gets an unreachable table, never the
host's default route.

**Revalidation (internal/core/revalidate.go).** Every
`OIDC_REVALIDATE_INTERVAL` each user's refresh token is used against the IdP.
Group changes update profiles and the firewall live. `invalid_grant` revokes
the password. An unreachable IdP is tolerated for `OIDC_GRACE_PERIOD`, then
sessions are cut (fail closed). Back-channel logout is handled in the portal.

**Configuration (internal/config).** Every setting is a `Def` in
`config.Defs`; its key is also the environment variable. Resolution: env
(fixed, greyed out in the panel), then the value saved in the panel, then the
default. `CheckEnv` refuses to start on unknown variables that look like
settings, so a new setting must get a `Def` (and usually a README row).
`Restart: true` marks settings that need a backend restart.

**Backend configs.** Generated from `templates/config/*.tmpl`; the admin
panel can store a manual override per file (`internal/backend/configs.go`).
Template changes need the golden files updated (`-update`, see above).

**Tunnels.** `internal/tunnels` manages site-to-site links on top of
goproxy in `internal/goproxy`, which is this repository's own code now (no
separate goproxy repository). It is excluded from the gofmt lint.

**State.** SQLite (`internal/store`) under `DATA_DIR` (`/data`). Migrations
are an append-only list in `internal/store/store.go`: never edit an applied
one. Secrets (refresh tokens, NT hashes, ID tokens) are sealed with the
master key (`internal/secret`), never stored in cookies.

## Docs to keep in sync

`README.md` (settings table, behaviour), `docs/progress.md` (stage status,
verification, deviations from the spec), `docs/tunnels.md`,
`docs/authentik.md`, `docs/manual-testing.md`.
