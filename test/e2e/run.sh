#!/bin/sh
# Runs the end-to-end scenarios against the dev deployment (deploy/dev).
# Requires: Docker, the image vpngw:latest (also the fake remote site),
# Python 3 with requests and playwright (chromium) — E2E_PYTHON points to that
# interpreter. Secrets: deploy/dev/.env and test/e2e/e2e.env.
set -e
cd "$(dirname "$0")/../.."
ENV=deploy/dev/.env
docker build -q -t vpngw-testclient test/e2e/client >/dev/null
# The fake site needs this gateway's tunnel public key and MTU.
GWPUB=$(grep '^TUNNEL_PRIVATE_KEY=' $ENV | cut -d= -f2- | docker run --rm -i vpngw:latest pubkey)
FAKEDC_MTU=$(grep '^TUNNEL_MTU=' $ENV | cut -d= -f2-) || true
export FAKEDC_MTU
FAKEPUB=$(./test/e2e/fakedc.sh up "$GWPUB")
FAKEIP=$(./test/e2e/fakedc.sh ip)
sed -i '/^TUNNEL_PEER_FAKEDC_/d' $ENV
cat >> $ENV <<EOT
TUNNEL_PEER_FAKEDC_PUBLIC_KEY=$FAKEPUB
TUNNEL_PEER_FAKEDC_ENDPOINT=$FAKEIP:5555
TUNNEL_PEER_FAKEDC_PSK=fakedc-psk
TUNNEL_PEER_FAKEDC_SUBNETS=10.4.0.0/16
TUNNEL_PEER_FAKEDC_EXIT=true
EOT
docker compose -f deploy/dev/docker-compose.yml up -d --force-recreate
until docker exec vpngw vpngw healthcheck >/dev/null 2>&1; do sleep 2; done
sleep 8
# Site-specific values (IdP user, host names, targets): test/e2e/e2e.env
if [ -f test/e2e/e2e.env ]; then set -a; . ./test/e2e/e2e.env; set +a; fi
rc=0
"${E2E_PYTHON:-python3}" test/e2e/e2e.py || rc=$?
./test/e2e/fakedc.sh down    # the fake site exists only for the tests
exit $rc
