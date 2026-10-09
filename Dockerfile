# syntax=docker/dockerfile:1
# VPN client installers for the portal (CLIENTS_DIR): "include" copies the
# clients/ directory (info.txt and the installers it lists), "none" builds
# without them and the portal shows no client downloads.
ARG CLIENTS=none

FROM scratch AS clients-none
FROM scratch AS clients-include
COPY clients /
FROM clients-${CLIENTS} AS clients

FROM golang:1.27-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY templates ./templates
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/vpngw ./cmd/vpngw

FROM debian:13-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ocserv openvpn \
      strongswan-charon strongswan-swanctl libstrongswan-standard-plugins libstrongswan-extra-plugins libcharon-extra-plugins \
      nftables iptables iproute2 tini ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ocserv/ocserv.conf \
 # ssl-cert (an ocserv dependency) generates a snakeoil key at install time:
 # unused, and it would be the same key in every copy of the image.
 && rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem
COPY --from=clients / /usr/share/vpngw/clients
COPY --from=build /out/vpngw /usr/local/bin/vpngw
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 80/tcp 443/tcp 443/udp 1194/udp 500/udp 4500/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/usr/local/bin/vpngw", "healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vpngw"]
