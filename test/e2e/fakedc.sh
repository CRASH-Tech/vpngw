#!/bin/sh
# Starts a fake remote site in containers: a vpngw node in tunnels-only mode
# with the network 10.4.0.0/16 behind it (a host with the targets 10.4.0.1
# and the excluded 10.4.5.1) and an internet exit through the node's own
# NAT. The gateway connects to it as peer "fakedc".
#   fakedc.sh up <gateway-public-key> | down | ip
# FAKEDC_MTU sets the node's TUNNEL_MTU; it must equal the gateway's.
# Requires the images vpngw:latest and vpngw-testclient (test/e2e/client).
set -e
NAME=vpngw-fakedc
LAN=$NAME-lan
down() {
  docker stop -t 1 $NAME $NAME-target >/dev/null 2>&1 || true
  docker network rm $LAN >/dev/null 2>&1 || true
}
case "$1" in
up)
  [ -n "$2" ] || { echo "usage: $0 up <gateway public key>"; exit 2; }
  down
  STATE="$(dirname "$0")/.state"; mkdir -p "$STATE"
  [ -s "$STATE/fakedc.key" ] || docker run --rm vpngw:latest genkey > "$STATE/fakedc.key"
  KEY=$(cat "$STATE/fakedc.key")
  # The site's LAN, without an address on the host: only the node routes
  # into it. The bridge gateway is moved off 10.4.0.1, a target address.
  docker network create --subnet 10.4.0.0/16 --gateway 10.4.255.254 -o com.docker.network.bridge.inhibit_ipv4=true $LAN >/dev/null
  # On the default bridge first: the gateway reaches it there, and it is the
  # route to the internet.
  docker create --rm --name $NAME --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.rp_filter=2 \
    -e PORTAL_HOSTNAME=fakedc.example.com -e EMERGENCY_USER=admin -e EMERGENCY_PASS=fakedc-admin -e DATA_DIR=/tmp/data \
    -e TUNNEL_PRIVATE_KEY="$KEY" -e TUNNEL_LISTEN=0.0.0.0:5555 -e TUNNEL_TRANSPORT=udp -e TUNNEL_PSK=fakedc-psk \
    ${FAKEDC_MTU:+-e TUNNEL_MTU=$FAKEDC_MTU} \
    -e TUNNEL_PEER_VPNGW_PUBLIC_KEY="$2" -e "TUNNEL_PEER_VPNGW_ALLOW=10.4.0.0/16 0.0.0.0/0" \
    vpngw:latest >/dev/null
  docker network connect --ip 10.4.0.2 $LAN $NAME
  docker start $NAME >/dev/null
  docker run -d --rm --name $NAME-target --network $LAN --ip 10.4.0.1 --cap-add NET_ADMIN vpngw-testclient >/dev/null
  docker exec $NAME-target sh -c 'ip addr add 10.4.5.1/32 dev eth0 && ip route replace default via 10.4.0.2'
  # Bulk TCP target behind the site (MTU checks).
  STATE_ABS=$(cd "$STATE" && pwd)
  CGO_ENABLED=0 go build -C "$(dirname "$0")/fsrv" -o "$STATE_ABS/fsrv" . && docker cp "$STATE_ABS/fsrv" $NAME-target:/fsrv >/dev/null && docker exec -d $NAME-target /fsrv 10.4.0.1:8080
  echo "$KEY" | docker run --rm -i vpngw:latest pubkey
  ;;
down) down ;;
ip) docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' $NAME ;;
*) echo "usage: $0 up <pubkey>|down|ip"; exit 2 ;;
esac
