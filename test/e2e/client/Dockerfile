# Test client with the three VPN clients used by the e2e scenarios.
FROM debian:13-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openvpn openconnect vpnc-scripts \
      strongswan-charon strongswan-swanctl libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins \
      iproute2 iputils-ping curl ca-certificates procps dnsutils \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
