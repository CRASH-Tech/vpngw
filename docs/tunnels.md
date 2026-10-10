# Tunnels to remote sites

vpngw embeds a goproxy node (`internal/goproxy`). It links the gateway with
remote sites (data centers); VPN clients connected with AnyConnect, OpenVPN
or IKEv2 reach the sites' networks through these tunnels.

## Model

A **site** (peer) is another gateway — a data center or an office. Each one
answers three questions:

1. **Connection** — its public key and either its address (`host:port`, we
   connect to it) or nothing (it connects to us; needs `TUNNEL_LISTEN`).
   Tunnel addresses are automatic on both sides (see *Addresses and NAT*);
   there is nothing to enter.
2. **Behind the site** (`SUBNETS`, `EXIT`) — networks we reach through it, and
   whether it may carry our users' internet (internet exit).
3. **May reach here** (`ALLOW`) — our networks the site may use through this
   gateway; `0.0.0.0/0` = our internet. Its traffic is masqueraded with this
   gateway's address and replies return into its tunnel. New connections from
   a site to anything else are dropped (counter `tunnel_in_dropped`).

Every site gets an interface of its own, `gp-<name>`. You never point routes
at interfaces by hand. Routing applies to VPN clients and
`TUNNEL_TRANSIT_SOURCES` only; the host's own traffic is unchanged.

| What the client sends | Where it goes |
|---|---|
| to a network behind a site | into that site's tunnel — for **every** client whose profile allows the destination (the firewall still decides) |
| anything else, no `vpnGateway` | the host's default gateway |
| anything else, `vpnGateway: <site name>` | that site's tunnel (the site must be an internet exit) |
| a `vpnDomains` name (domain proxy) | `vpnGateway` as above; the gateway resolves the name with `vpnDNS` through it too |

The two sides mirror each other: what is *behind* site B for A is what B
*allows* A, and vice versa. *Tunnels → Other side* prints the environment for
the other gateway accordingly.

`vpnGateway` may still name a host interface or an IPv4 next hop. If the named
peer or interface is missing, that traffic is dropped rather than leaked
through the host's default route.

This site's own networks always leave through the host's routes, also for
logins whose internet goes through another site: everything the node opens
to other sites (`ALLOW`, except `0.0.0.0/0`), `TUNNEL_TRANSIT_SOURCES`, and
`TUNNEL_LOCAL_NETWORKS` for any other network the host reaches through its
own routers. Without that, a network reached via the host's default router
(not directly connected) would follow `vpnGateway` into the exit site.

A `vpnGateway` (or `EMERGENCY_GATEWAY`, `TUNNEL_TRANSIT_GATEWAY`) equal to this
node's own name (`NODE_NAME`, else the first label of `VPN_HOSTNAME`) means the
host's default route. Several gateways can therefore share one IdP: a group
with `vpnGateway: LV-EXIT` leaves through site LV-EXIT from every other
gateway, and directly on LV-EXIT itself.

Routing rules (installed by vpngw, priorities 15000–15999):

```
15000  fwmark 0x76670000/0xffff0000  lookup 15100                      # peer subnets
15001  fwmark 0x76670000/0xffff0000  lookup main suppress_prefixlength 0  # the host's specific routes
15010+i fwmark 0x7667000i            lookup 15100+i                     # vpnGateway i: default dev gp-<peer>
```

## Transit traffic

Devices that use this host as their gateway (a LAN behind it) can reach the
peers' subnets too: list their networks in `TUNNEL_TRANSIT_SOURCES`
(e.g. `192.168.10.0/24`). Forwarded packets from these sources to a peer
subnet are marked in the `steer` chain (sets `transit_src` and `tunnel_dst`)
and follow rule 15000 into the tunnel; with `NAT` the site sees them as this
node. Other sources and the host's own traffic keep the host's normal routes.

Their remaining traffic (the internet) leaves through the host's default
gateway, or through a site marked as internet exit: choose it under
*Tunnels → This node → Internet for routed hosts*, or set
`TUNNEL_TRANSIT_GATEWAY=<site>`. The exit site must allow `0.0.0.0/0` for
this node. Destinations the host has specific routes for (its LANs) stay
local; if the chosen site is down, that traffic is dropped rather than sent
through the host's default gateway.
With Docker installed, vpngw adds `DOCKER-USER` rules (comment
`vpngw-transit`) so these packets pass Docker's `FORWARD` policy.

Chosen **sites** can leave through an exit while the rest of the internet
does not (domain proxy, like `vpnDomains` for VPN groups):

```sh
TUNNEL_TRANSIT_DOMAINS="youtube.com googlevideo.com *.com !google.com"  # names and subdomains; ! excludes
TUNNEL_TRANSIT_DOMAINS_GATEWAY=lat     # their exit; empty: TUNNEL_TRANSIT_GATEWAY
TUNNEL_TRANSIT_DOMAINS_DNS=8.8.8.8     # resolves them, queried through the exit
```

The hosts use this node's DNS server, the first address of
`VPN_DOMAIN_POOL` (`198.18.0.1` by default), e.g. from DHCP. It answers the
listed names with pool addresses, which the node translates to the real
ones and sends through the exit; other names go to the node's resolvers.
When this node is not the hosts' default gateway they also need a route to
`VPN_DOMAIN_POOL` through it (DHCP option 121). This works with and
without `OIDC_ISSUER`.

Without `OIDC_ISSUER` the gateway runs only the tunnels (no AnyConnect,
OpenVPN or IKEv2); transit is then the way traffic uses them.

## Site roles

The same image serves every site; `OIDC_ISSUER` empty means tunnels only.

- **Exit into a network** — other sites reach this site's network through it:
  `TUNNEL_LISTEN`, and each connecting site as a peer with `ALLOW` = what it
  may reach (e.g. `10.6.0.0/16`, or also `0.0.0.0/0` for the internet).
- **Gateway for local hosts** — hosts of this site reach the networks behind
  the peers: `TUNNEL_TRANSIT_SOURCES` and a peer per remote site with its
  `SUBNETS`. The hosts route the remote networks via this node (or use it as
  their default gateway).
- **VPN gateway** — the above plus users (OIDC).

Keys: every node generates its own key pair on first start and keeps it
(encrypted) in its database; give each site the other's public key from
*Tunnels → This node*. *Regenerate* there replaces it (every site then needs
the new public key). To manage keys yourself, set `TUNNEL_PRIVATE_KEY`
(`docker run --rm vpngw:latest keypair` prints a pair).
`make e2e-sites` runs the first two roles in containers.

## Configuration

Sites can be added in the admin panel (*Tunnels*) or with environment
variables; sites from the environment are read-only in the panel.

```sh
TUNNEL_PRIVATE_KEY=...            # optional; generated and kept encrypted when empty
TUNNEL_PSK=...                    # default PSK
TUNNEL_TRANSPORT=udp              # udp | aead | tls
TUNNEL_MTU=1320                   # see "MTU" below
TUNNEL_LISTEN=0.0.0.0:444         # optional: let sites connect to us
TUNNEL_TRANSIT_SOURCES=...        # optional: local hosts that use this node as gateway

# a site we connect to
TUNNEL_PEER_DC1_PUBLIC_KEY=<public key of the site>
TUNNEL_PEER_DC1_ENDPOINT=dc1.example.com:444
TUNNEL_PEER_DC1_SUBNETS=10.20.0.0/16   # behind the site
TUNNEL_PEER_DC1_EXIT=true              # may carry our internet (vpnGateway: dc1)

# a site that connects to us (tunnel address assigned automatically)
TUNNEL_PEER_OFFICE_PUBLIC_KEY=<public key of the site>
TUNNEL_PEER_OFFICE_ALLOW=10.6.0.0/16   # what it may reach here; 0.0.0.0/0 = internet
```

Less common, per site: `_TRANSPORT`, `_PSK`, `_KEEPALIVE`, `_ADDRESS` (fixed
tunnel address for a site that connects to us), `_NAT=false` (VPN clients keep
their pool addresses at the site, see below), `_DISABLED`.

What a user may reach comes from the IdP (`vpnRoutes` of the group); where it
goes comes from the tunnels. The user's page in the admin panel shows, for
each login, the allowed networks, the tunnel each of them uses and where the
rest goes. The emergency admin uses `EMERGENCY_ROUTES` and `EMERGENCY_GATEWAY`.

In the IdP, a group whose internet should leave through that site gets
`vpnGateway: dc1` (the site name, case-insensitive). Groups that only need the
site's networks need no `vpnGateway` — e.g. `vpnRoutes: [10.20.0.0/16]`.

## Addresses and NAT

Tunnel addresses need no configuration:

- A node's own address defaults to `10.255.250.1` if it only connects out
  (the other side assigns it an address, or a plain goproxy node lists this
  one in its `ROUTES`), and to `10.255.x.1` with `x` derived from its key if
  it accepts sites (`TUNNEL_LISTEN`): sites see that address as the source of
  its traffic, so it must not equal their own. `TUNNEL_ADDRESS` sets it
  explicitly.
- A site that connects to us gets an address from our /24 in the handshake.
  The *Sites* table shows it as *tunnel address* on both sides; it is
  internal to the tunnel. The public address a site connects from is shown
  as *connects from*.
- Packets from a site are accepted from any source; what the site may reach
  is decided by its `ALLOW` (nftables set `site_allow`). Replies to
  connections a site opened go back into the tunnel they came from (conntrack
  mark per tunnel, rules 15500+i), whatever its source address — so nothing
  has to be routed back by address.
- With `NAT` (default) VPN clients and transit hosts arrive at the site as
  this gateway's tunnel address. Without `NAT` they keep their own addresses;
  a vpngw on the other side handles that too, a plain goproxy node needs
  routes for them.

## MTU

With the `udp` transport a tunnel packet is the inner packet plus 52 bytes
(IP, UDP, counter, tag), and random padding fills it up to the MTU. So
`TUNNEL_MTU` must not exceed the path MTU between the two nodes minus 52, on
**both** sides — goproxy does not negotiate the MTU from client to server.
Symptoms of a too large MTU: ping works, TCP downloads stall. Example: a path
MTU of 1320 needs `TUNNEL_MTU=1260` on both sides.

What happens with packets of each size:

- Inside the tunnel every interface `gp-*` has `TUNNEL_MTU`. TCP connections
  through it get their MSS clamped to fit, and larger packets with DF set get
  "fragmentation needed" back, so path MTU discovery works for VPN clients
  (OpenVPN, AnyConnect, IKEv2) and routed hosts alike.
- The tunnel's own UDP packets are sent without DF. On a path narrower than
  `TUNNEL_MTU` + 52 they are fragmented on the way and still arrive, but more
  slowly; if something on the path drops fragments, large packets vanish (the
  symptoms above). Set `TUNNEL_MTU` to the path MTU minus 52 in that case.

`make e2e` and `make e2e-sites` check both: 1260-byte packets pass, larger
ones are signalled, 10 MB TCP transfers complete, also over a path narrower
than the tunnel.

## Host requirements

- `net.ipv4.conf.all.rp_filter` 0 or 2 (loose). vpngw gives each `gp-*`
  interface the node's tunnel address, otherwise the kernel drops replies
  arriving on an interface without an address.
- The container needs `/dev/net/tun` and `NET_ADMIN` (already required).
