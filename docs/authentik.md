# Configuring Authentik for vpngw

This guide sets up an Authentik OAuth2/OpenID provider so that vpngw receives
everything it needs: a refresh token (to re-check the session every few
minutes), the user's groups, and per-group VPN routes.

Tested with Authentik 2025.10.

## 1. VPN attributes on groups

vpngw reads routes from **group attributes**. Open
*Directory → Groups → (group) → Edit → Attributes* and add:

```yaml
vpnRoutes:            # list of CIDRs; "!" prefix excludes a network
  - 10.4.0.0/16
  - "!10.4.5.0/24"
vpnGateway: lat       # optional: tunnel peer for the internet (see docs/tunnels.md)
vpnDNS:               # optional: DNS servers pushed to clients
  - 10.4.0.53
vpnDomain: corp.lan   # optional: DNS search domain
```

A group can also send chosen **sites** through another site (domain proxy):

```yaml
vpnDomains:           # names and their subdomains; "*.com" for a whole top-level domain
  - youtube.com
  - googlevideo.com
  - "*.com"
  - "!google.com"     # "!" excludes a name with its subdomains (quote it in YAML)
vpnGateway: lat       # the site their traffic leaves through
vpnDNS:               # servers that resolve them, queried through vpnGateway
  - 8.8.8.8
vpnRoutes:            # optional here: networks as usual
  - 10.4.0.0/16
```

Like networks, the most specific entry decides: with `*.com` and
`!google.com` everything in .com goes through `vpnGateway` except
google.com and its subdomains; adding `maps.google.com` would send that one
through again. Excluded names are resolved and reached as usual.

With `vpnDomains` the client gets the gateway's own DNS server. It answers
the listed names with addresses from `VPN_DOMAIN_POOL` (default
`198.18.0.0/16`, routed to the client), resolves the real addresses with
`vpnDNS` through `vpnGateway`, and the gateway forwards the connections
there. Other names are resolved by the gateway's resolvers (`VPN_DNS` or
the host's) and their traffic does not enter the tunnel. `vpnDNS` is not
given to the client in this case. This works only with the group in the
login (`alice@vpn-proxy`); the plain login ignores `vpnDomains`.
Browsers with their own DNS (DNS over HTTPS) bypass it.

`vpnRoutes: [0.0.0.0/0]` means full tunnel. Subnets behind tunnel peers
(remote sites) are reached through their tunnels without any `vpnGateway`;
`vpnGateway` names the peer that carries the group's *other* traffic, e.g.
the internet through another data center. Without it that traffic leaves via
the gateway's default route. A single string (`vpnRoutes: 10.4.0.0/16`)
or a comma separated string is accepted as well.

Users pick the group when connecting: the VPN login is `username@group`
(for example `alice@vpn-dc1`). Only groups that have `vpnRoutes` or
`vpnDomains` can be used. The plain login (`alice`) gets the networks of all her groups
together, but never `0.0.0.0/0` and no `vpnGateway`: internet access
through the VPN needs the group in the login (`alice@vpn-internet`).

## 2. Scope mapping `vpn`

*Customization → Property Mappings → Create → Scope Mapping*

| Field        | Value |
|--------------|-------|
| Name         | `vpngw: vpn` |
| Scope name   | `vpn` |
| Description  | `VPN routes` |

Expression:

```python
def as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.replace(",", " ").split() if v.strip()]
    return [str(v).strip() for v in value if str(v).strip()]

user = request.user
try:
    groups = list(user.all_groups())          # includes parent groups
except Exception:
    groups = list(user.ak_groups.all())

result = {}
for group in groups:
    attrs = group.attributes or {}
    routes = as_list(attrs.get("vpnRoutes"))
    domains = as_list(attrs.get("vpnDomains"))
    if not routes and not domains:
        continue
    entry = {"vpnRoutes": routes}
    if domains:
        entry["vpnDomains"] = domains
    if attrs.get("vpnGateway"):
        entry["vpnGateway"] = str(attrs.get("vpnGateway"))
    if attrs.get("vpnDNS"):
        entry["vpnDNS"] = as_list(attrs.get("vpnDNS"))
    if attrs.get("vpnDomain"):
        entry["vpnDomain"] = str(attrs.get("vpnDomain"))
    result[group.name] = entry

return {"vpn": result}
```

Resulting claim:

```json
"vpn": {
  "vpn-dc1":  {"vpnRoutes": ["10.4.0.0/16"], "vpnGateway": "dc1"},
  "vpn-internet": {"vpnRoutes": ["0.0.0.0/0"]}
}
```

The claim name is configurable in vpngw with `OIDC_ROUTES_CLAIM` (default `vpn`).

## 3. Provider settings

*Applications → Providers → (your provider) → Edit*

1. **Redirect URIs**: `https://<PORTAL_HOSTNAME>[:<PORTAL_PORT>]/oidc/callback`
   (strict). Example: `https://vpn.example.com:8443/oidc/callback`.
2. **Advanced protocol settings → Scopes**: keep the defaults
   (`openid`, `email`, `profile`) and add
   - `authentik default OAuth Mapping: OpenID 'offline_access'`
   - `vpngw: vpn`
3. **Refresh Token validity**: how long a user stays connected without
   visiting the portal again, e.g. `days=30`. When it expires, the VPN password
   is revoked and the user has to log in to the portal again.
4. **Access code / Access token validity**: defaults are fine (`minutes=5`).
5. **Signing Key** (recommended): select a certificate (for example
   `authentik Self-signed Certificate`) so ID tokens are signed with RS256.
   Without a signing key Authentik uses HS256 with the client secret; vpngw
   supports both.
6. **Encryption Key**: leave **empty**. With an encryption key Authentik
   returns ID tokens as JWE, which vpngw can only read if you also give it
   the private key (`OIDC_ID_TOKEN_DECRYPTION_KEY`). Encryption adds nothing
   here: tokens travel only between Authentik and vpngw over TLS.
7. **Logout URI**: `https://<PORTAL_HOSTNAME>[:<PORTAL_PORT>]/oidc/backchannel-logout`,
   **Logout Method**: `Back-channel`. Revocation then happens instantly instead
   of at the next periodic check.
8. **Include claims in id_token**: enabled.
9. **Sign-out** (`OIDC_LOGOUT`): with the default `app`, *Sign out* in the
   portal ends the portal session and returns to its sign-in page; the next
   *Sign in with SSO* asks Authentik for the password again (`prompt=login`).
   With `idp` the portal sends the user to Authentik's end-session endpoint
   with `id_token_hint`. Authentik 2026.5 and newer then return to the portal
   if `https://<PORTAL_HOSTNAME>[:<PORTAL_PORT>]/` is listed under **Post
   logout redirect URIs**; older versions ignore it and show their own
   "logged out" page.

## 4. Admin group

Create a group (default name expected by vpngw is whatever you set in
`ADMIN_GROUP`, e.g. `vpn-admins`) and add administrators to it. Members get
access to the admin panel. The `groups` claim (from the `profile` scope) is
used to detect it.

## 5. Check

Discovery must list the new scopes:

```sh
curl -s https://<authentik>/application/o/<slug>/.well-known/openid-configuration \
  | jq .scopes_supported
# ["openid","profile","email","offline_access","vpn"]
```

After logging in to the vpngw portal, the page shows the available VPN logins
(`user@group`) with their routes. If the portal says *"Identity provider did
not return a refresh token"*, the `offline_access` mapping is missing.
