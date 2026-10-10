# Progress

Status of the stages from the specification.

| # | Stage | State | Notes |
|---|---|---|---|
| 1 | Skeleton | done | Go project, env/DB settings, SQLite with migrations, master key, supervisor, Dockerfile, `/healthz`, CI |
| 2 | OIDC and portal | done | Login with PKCE+nonce, HS256/RS256 and JWE ID tokens, refresh token encrypted, password issue/reissue, claims → route profiles |
| 3 | OpenVPN + nftables + IPAM | done | management-client-auth, `.ovpn` with per-user tls-crypt-v2 key and revocation, firewall, NAT, policy routing for `vpnGateway` |
| 4 | AnyConnect | done | RADIUS PAP + accounting, ocserv, SNI router with PROXY v2, ACME (HTTP-01; not exercised here — ports are not public) |
| 5 | IKEv2 | done | EAP-MSCHAPv2 over RADIUS, VICI, connection per profile (`remote.groups`), Windows/Apple/Android/Linux profiles |
| 6 | Revalidation and revocation | done | refresh loop with jitter and concurrency limit, grace period, back-channel logout, group changes |
| 7 | Admin panel | done | live sessions (SSE), users, traffic history, journal + CSV, routes, status, settings, configs |
| 8 | Polishing | done | brute-force protection, security headers, metrics, README, Authentik guide, manual checklist |

| — | Tunnels to remote sites | done | goproxy embedded; peers in the panel or env; peer subnets for all clients; `vpnGateway` = peer for internet; tested with a local goproxy site and a real remote site |

## Verification

- `go test ./...` — EAP-MSCHAPv2/MPPE on RFC 2759/3079 vectors, CIDR logic,
  crypto, IPAM, firewall scripts, RADIUS PAP/EAP over UDP with
  Message-Authenticator and MPPE keys, revalidation with a mock IdP
  (rotation, `invalid_grant`, grace period, widened/narrowed groups,
  back-channel logout), golden backend configs.
- `make e2e` against the dev deployment and the Authentik test IdP, with real
  `openconnect`, `openvpn` 2.6 and strongSwan `swanctl` clients:
  connection and pool address, allowed/excluded/foreign networks (with a
  manual route on the client), traffic counters and admin disconnect, wrong
  password, session limit, password reissue, brute-force block, no secrets in
  logs, tunnels: peer subnets per profile, internet via the host or via a
  site (`vpnGateway`). A local vpngw node in tunnels-only mode
  (`test/e2e/fakedc.sh`) plays a remote site with 10.4.0.0/16 and an
  internet exit; optionally a real site (`E2E_REMOTE_TARGET`).

## Deviations from the specification

- The e2e stand uses the provided Authentik instead of a Keycloak container;
  IdP-side changes (blocking a user, changing groups) are covered by unit
  tests with a mock IdP and by the manual checklist.
- nftables is driven through `nft -f` transactions instead of the
  `google/nftables` library: each change is still one atomic transaction and
  the table is never recreated after start.
- ocserv cannot combine RADIUS with `config-per-group`, so `tunnel-all-dns`
  per profile is not used; full-tunnel profiles route DNS through the tunnel
  anyway.
- No admin "group → routes" fallback mappings: access comes only from the
  IdP routes claim, routing from tunnel peers. The emergency admin uses
  `EMERGENCY_ROUTES` and `EMERGENCY_GATEWAY`.
- When the IdP is unreachable beyond the grace period, sessions are
  terminated and new connections refused, but the password is kept: it works
  again after the next successful check. `invalid_grant` revokes the password.
- Authentik does not revoke offline refresh tokens on logout; immediate
  revocation needs back-channel logout (the IdP must reach the portal).
