#!/usr/bin/env bash
set -euo pipefail
export POSTGRES_PASSWORD=integration-test-not-secret
export ARTEX_TARGET_CIDRS=172.30.137.20/32
export ARTEX_ALLOW_DNS=0
cleanup() {
 docker rm -f artex-test-allowed artex-test-denied >/dev/null 2>&1 || true
 docker compose -p artexguardtest -f docker-compose.contained.yml down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker pull nginx:alpine
docker pull curlimages/curl:8.16.0
docker compose -p artexguardtest -f docker-compose.contained.yml up -d --build postgres network-guard
docker run -d --name artex-test-allowed --network artexguardtest_contained --ip 172.30.137.20 nginx:alpine
docker run -d --name artex-test-denied --network artexguardtest_contained --ip 172.30.137.21 nginx:alpine
GUARD_ID="$(docker compose -p artexguardtest -f docker-compose.contained.yml ps -q network-guard)"
test -n "$GUARD_ID"
for n in 1 2 3 4 5 6 7 8 9 10; do
 if docker run --rm --network "container:$GUARD_ID" --cap-drop ALL curlimages/curl:8.16.0 -fsS --connect-timeout 2 --max-time 4 http://172.30.137.20/ >/dev/null; then break; fi
 if [ "$n" -eq 10 ]; then echo "FAIL: approved target unavailable" >&2; exit 1; fi
 sleep 1
done
if docker run --rm --network "container:$GUARD_ID" --cap-drop ALL curlimages/curl:8.16.0 -fsS --connect-timeout 2 --max-time 4 http://172.30.137.21/ >/dev/null; then
 echo "FAIL: forbidden target reachable" >&2; exit 1
fi
if docker run --rm --network "container:$GUARD_ID" --cap-drop ALL curlimages/curl:8.16.0 -6fsS --connect-timeout 2 --max-time 4 'http://[2606:4700:4700::1111]/' >/dev/null; then
 echo "FAIL: unauthorized IPv6 reachable" >&2; exit 1
fi
echo "PASS: approved target reachable, forbidden IPv4/IPv6 blocked"
