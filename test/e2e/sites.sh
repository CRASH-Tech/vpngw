#!/bin/sh
# Two sites in containers (each vpngw in tunnels-only mode in its own network
# namespace):
#   site A — exit into its network: lets site B reach 10.66.0.0/24
#            (its LAN 10.66.0.0/23 also has 10.66.1.10, which must stay closed)
#   site B — gateway for its hosts (10.77.0.0/24) to site A's network, and
#            lets hosts of site A reach its network back; its hosts reach
#            site.test (in site A's "internet") through the domain proxy;
#            a SOCKS5 proxy for its hosts with site A as exit
# Both keep the default (automatic) TUNNEL_ADDRESS; B connects to A and gets
# its tunnel address from A.
# Requires the image vpngw:latest and vpngw-testclient (test/e2e/client).
set -u
P=vpngw-sites
fail=0
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

cleanup() {
  docker stop -t 1 $P-a $P-b $P-host-b $P-target $P-closed $P-inet >/dev/null 2>&1
  for n in wan lan-a lan-b net-x; do docker network rm $P-$n >/dev/null 2>&1; done
}
cleanup
# The path between the sites is narrower (MTU 1300) than TUNNEL_MTU + 52
# (1312): the tunnel's outer packets must be fragmented, not lost.
docker network create --subnet 172.31.240.0/24 -o com.docker.network.driver.mtu=1300 $P-wan >/dev/null
# LANs without an address on the host: only the site nodes route into them.
docker network create --subnet 10.66.0.0/23 -o com.docker.network.bridge.inhibit_ipv4=true $P-lan-a >/dev/null
docker network create --subnet 10.77.0.0/24 -o com.docker.network.bridge.inhibit_ipv4=true $P-lan-b >/dev/null
# "Internet" of site A: a network only site A is connected to.
docker network create --subnet 10.88.0.0/24 -o com.docker.network.bridge.inhibit_ipv4=true $P-net-x >/dev/null

KEY_A=$(docker run --rm vpngw:latest genkey)
KEY_B=$(docker run --rm vpngw:latest genkey)
PUB_A=$(echo "$KEY_A" | docker run --rm -i vpngw:latest pubkey)
PUB_B=$(echo "$KEY_B" | docker run --rm -i vpngw:latest pubkey)
PSK=sites-test-psk

node() { # name ip lan lan-ip env...
  name=$1 ip=$2 lan=$3 lanip=$4; shift 4
  docker create --rm --name $P-$name --network $P-wan --ip $ip --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.rp_filter=2 \
    -e PORTAL_HOSTNAME=$name.example.com -e EMERGENCY_USER=admin -e EMERGENCY_PASS=admin-pass -e DATA_DIR=/tmp/data \
    -e TUNNEL_PSK=$PSK -e TUNNEL_MTU=1260 "$@" vpngw:latest >/dev/null
  docker network connect --ip $lanip $P-$lan $P-$name
  docker start $P-$name >/dev/null
}

# Site A: site B connects to it and may reach 10.66.0.0/24; A's hosts reach
# B's network.
node a 172.31.240.10 lan-a 10.66.0.2 \
  -e TUNNEL_PRIVATE_KEY=$KEY_A -e TUNNEL_LISTEN=0.0.0.0:444 -e TUNNEL_TRANSIT_SOURCES=10.66.0.0/24 \
  -e TUNNEL_PEER_SITEB_PUBLIC_KEY=$PUB_B -e "TUNNEL_PEER_SITEB_ALLOW=10.66.0.0/24 10.88.0.0/24" -e TUNNEL_PEER_SITEB_SUBNETS=10.77.0.0/24
# Site B: gateway for its hosts to site A's network; A may reach 10.77.0.0/24.
node b 172.31.240.20 lan-b 10.77.0.2 \
  -e TUNNEL_PRIVATE_KEY=$KEY_B -e TUNNEL_TRANSIT_SOURCES=10.77.0.0/24 -e TUNNEL_TRANSIT_GATEWAY=SITEA \
  -e TUNNEL_PEER_SITEA_PUBLIC_KEY=$PUB_A -e TUNNEL_PEER_SITEA_ENDPOINT=172.31.240.10:444 -e TUNNEL_PEER_SITEA_SUBNETS=10.66.0.0/23 \
  -e TUNNEL_PEER_SITEA_ALLOW=10.77.0.0/24 -e TUNNEL_PEER_SITEA_EXIT=true \
  -e "TUNNEL_TRANSIT_DOMAINS=site.test !private.site.test" -e TUNNEL_TRANSIT_DOMAINS_GATEWAY=SITEA -e TUNNEL_TRANSIT_DOMAINS_DNS=10.88.0.10 \
  -e SOCKS_LISTEN=0.0.0.0:1080 -e SOCKS_ALLOWED_NETWORKS=10.77.0.0/24 -e SOCKS_GATEWAY=SITEA -e SOCKS_DNS=10.88.0.10

client() { # name lan ip gateway
  docker run -d --rm --name $P-$1 --network $P-$2 --ip $3 --cap-add NET_ADMIN vpngw-testclient >/dev/null
  docker exec $P-$1 ip route replace default via $4
}
client host-b lan-b 10.77.0.10 10.77.0.2
client target lan-a 10.66.0.10 10.66.0.2
client closed lan-a 10.66.1.10 10.66.0.1
docker network connect --ip 10.88.0.2 $P-net-x $P-a
client inet net-x 10.88.0.10 10.88.0.1
# Bulk TCP targets on both sites (MTU checks).
STATE=$(cd "$(dirname "$0")" && pwd)/.state; mkdir -p "$STATE"
CGO_ENABLED=0 go build -C "$(dirname "$0")/fsrv" -o "$STATE/fsrv" .
for t in target host-b inet; do docker cp "$STATE/fsrv" $P-$t:/fsrv >/dev/null; done
docker exec -d $P-target /fsrv 10.66.0.10:8080
docker exec -d $P-host-b /fsrv 10.77.0.10:8080
# site A's "internet": web server and the DNS server for site.test, both
# reachable only through site A.
docker exec -d $P-inet /fsrv 10.88.0.10:8080
docker exec -d $P-inet /fsrv -dns 10.88.0.10:53 site.test=10.88.0.10

sleep 12
check "tunnel A<->B established" "docker logs $P-b 2>&1 | grep -q 'SITEA\] connected'"
check "site A gave site B an automatic tunnel address" "docker logs $P-b 2>&1 | grep -q 'SITEA\] connected.*tunnel IP 10\.255\.'"
check "host of site B reaches 10.66.0.10 behind site A" "docker exec $P-host-b ping -c3 -W3 10.66.0.10 >/dev/null"
check "site A NATs tunnel traffic into its LAN" "docker exec $P-a nft list chain inet vpngw postrouting | grep -E 'site_allow counter packets [1-9]' >/dev/null"
check "10.66.1.10 (not an exit network) stays closed" "! docker exec $P-host-b ping -c2 -W2 10.66.1.10 >/dev/null"
check "site A counted the refused connection" "docker exec $P-a nft list counter inet vpngw tunnel_in_dropped | grep -E 'packets [1-9]' >/dev/null"
check "host of site A reaches 10.77.0.10 behind site B (listener to connector)" "docker exec $P-target ping -c3 -W3 10.77.0.10 >/dev/null"
check "site B returned the replies into the tunnel they came from" "docker exec $P-b ip route show table 15501 | grep -q 'default dev gp-sitea'"
check "host of site B reaches site A's internet via TUNNEL_TRANSIT_GATEWAY" "docker exec $P-host-b ping -c3 -W3 10.88.0.10 >/dev/null"
check "MTU: 1260-byte packets pass B->A" "docker exec $P-host-b ping -c2 -W3 -M do -s 1232 10.66.0.10 >/dev/null"
check "MTU: larger packets get fragmentation-needed (mtu 1260)" "docker exec $P-host-b ping -c3 -W3 -M do -s 1300 10.66.0.10 2>&1 | grep -qE 'mtu ?=? ?1260|Message too long'"
check "MTU: 10 MB over TCP from site A to site B's host" "[ \"\$(docker exec $P-host-b curl -s -m 60 -o /dev/null -w '%{size_download}' http://10.66.0.10:8080/10M)\" = 10000000 ]"
check "MTU: 10 MB over TCP from site B to site A's host" "[ \"\$(docker exec $P-target curl -s -m 60 -o /dev/null -w '%{size_download}' http://10.77.0.10:8080/10M)\" = 10000000 ]"
check "site B node itself does not use the tunnel" "! docker exec $P-b ping -c1 -W2 10.66.0.10 >/dev/null"
# A site reaches only what it is allowed, the other node's own services
# included: site B drops a connection to its portal from site A's host.
BTUN=$(docker logs $P-b 2>&1 | grep -o 'tunnel IP 10\.255\.[0-9.]*' | head -1 | cut -d' ' -f3)
drops() { docker exec $P-b nft list counter inet vpngw tunnel_in_dropped | grep -o 'packets [0-9]*' | cut -d' ' -f2; }
D0=$(drops)
check "host of site A cannot open site B's own services (portal :8443 on $BTUN)" "! docker exec $P-target timeout 4 bash -c '</dev/tcp/$BTUN/8443' 2>/dev/null"
check "site B dropped it (tunnel_in_dropped grew from $D0)" "[ \"\$(drops)\" -gt \"$D0\" ]"
check "control: site B's portal listens on :8443" "docker exec $P-b timeout 4 bash -c '</dev/tcp/127.0.0.1/8443' 2>/dev/null"
# Domain proxy for routed hosts: site B's DNS (198.18.0.1) resolves
# site.test with 10.88.0.10 through site A and gives a pool address.
FAKE=$(docker exec $P-host-b dig +short +time=3 @198.18.0.1 www.site.test A | tail -1)
check "domain proxy: routed host gets a pool address for a listed name ($FAKE)" "echo '$FAKE' | grep -q '^198\.18\.'"
check "domain proxy: its connections reach the name's real address through the exit site" "[ \"\$(docker exec $P-host-b curl -s -m 60 -o /dev/null -w '%{size_download}' http://$FAKE:8080/10M)\" = 10000000 ]"
check "domain proxy: an excluded subdomain (!private.site.test) is not given a pool address" "! docker exec $P-host-b dig +short +time=3 @198.18.0.1 www.private.site.test A | grep -q '^198\.18\.'"
check "domain proxy: unknown names are not given pool addresses" "! docker exec $P-host-b dig +short +time=3 @198.18.0.1 other.test A | grep -q '^198\.18\.'"
check "domain proxy: site A without TUNNEL_TRANSIT_DOMAINS gives its hosts no pool addresses" "! docker exec $P-target dig +short +time=3 @198.18.0.1 www.site.test A | grep -q '^198\.18\.'"
# SOCKS5 proxy on site B: its connections leave like a VPN client's with
# vpnGateway SITEA; names resolved by SOCKS_DNS through the exit.
S="--socks5 10.77.0.2:1080"
check "socks: a host reaches the network behind site A through the proxy" "[ \"\$(docker exec $P-host-b curl -s -m 60 $S -o /dev/null -w '%{size_download}' http://10.66.0.10:8080/10M)\" = 10000000 ]"
check "socks: a name is resolved by SOCKS_DNS through the exit site" "[ \"\$(docker exec $P-host-b curl -s -m 60 --socks5-hostname 10.77.0.2:1080 -o /dev/null -w '%{size_download}' http://www.site.test:8080/10M)\" = 10000000 ]"
check "socks: the node's own services are refused (loopback)" "! docker exec $P-host-b curl -s -m 5 $S -o /dev/null http://127.0.0.1:8443/"
check "socks: the node's own services are refused (its LAN address)" "! docker exec $P-host-b curl -sk -m 5 $S -o /dev/null https://10.77.0.2:8443/healthz"
check "control: the portal answers without the proxy" "[ \"\$(docker exec $P-host-b curl -sk -m 5 -o /dev/null -w '%{http_code}' https://10.77.0.2:8443/healthz)\" = 200 ]"
check "socks: clients outside SOCKS_ALLOWED_NETWORKS are refused (site A's host)" "! docker exec $P-target curl -s -m 5 --socks5 10.77.0.2:1080 -o /dev/null http://10.77.0.10:8080/1"

[ -n "${KEEP:-}" ] || cleanup
exit $fail
