#!/bin/sh
# Starts a goproxy node in a container as a fake remote site: network
# 10.4.0.0/16 (targets 10.4.0.1 and the excluded 10.4.5.1) and an internet
# exit through the container's own NAT. The gateway connects to it as peer
# "fakedc"; its node key comes from deploy/dev/.env (TUNNEL_PRIVATE_KEY).
#   fakedc.sh up <gateway-public-key> | down | ip
set -e
NAME=vpngw-fakedc
case "$1" in
up)
  [ -n "$2" ] || { echo "usage: $0 up <gateway public key>"; exit 2; }
  docker build -q -t goproxy:dev "$(dirname "$0")/../../go-proxy" >/dev/null
  docker stop -t 1 $NAME >/dev/null 2>&1 || true
  STATE="$(dirname "$0")/.state"; mkdir -p "$STATE"
  [ -s "$STATE/fakedc.key" ] || docker run --rm goproxy:dev genkey > "$STATE/fakedc.key"
  KEY=$(cat "$STATE/fakedc.key")
  docker run -d --rm --name $NAME --cap-add NET_ADMIN --device /dev/net/tun \
    -e GOPROXY_PRIVATE_KEY="$KEY" -e GOPROXY_LISTEN=0.0.0.0:5555 -e GOPROXY_TRANSPORT=udp -e GOPROXY_PSK=fakedc-psk \
    -e GOPROXY_TUN_ADDRESS=10.4.254.1/24 -e GOPROXY_PUSH_ROUTES=true -e GOPROXY_MASQUERADE=eth0 -e GOPROXY_MASQUERADE_IPS="10.4.254.0/24 10.255.250.1/32" \
    -e GOPROXY_PEER_VPNGW_PUBLIC_KEY="$2" -e GOPROXY_PEER_VPNGW_ROUTES=10.255.250.1/32 \
    --entrypoint sh goproxy:dev -c 'ip addr add 10.4.0.1/32 dev lo; ip addr add 10.4.5.1/32 dev lo; exec goproxy node' >/dev/null
  # Bulk TCP target behind the site (MTU checks).
  STATE_ABS=$(cd "$STATE" && pwd)
  CGO_ENABLED=0 go build -C "$(dirname "$0")/fsrv" -o "$STATE_ABS/fsrv" . && docker cp "$STATE_ABS/fsrv" $NAME:/fsrv >/dev/null && docker exec -d $NAME /fsrv 10.4.0.1:8080
  echo "$KEY" | docker run --rm -i goproxy:dev pubkey
  ;;
down) docker stop -t 1 $NAME >/dev/null 2>&1 || true ;;
ip) docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $NAME ;;
*) echo "usage: $0 up <pubkey>|down|ip"; exit 2 ;;
esac
