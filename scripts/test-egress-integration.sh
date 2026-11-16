#!/usr/bin/env bash
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
 echo "Docker is required for the synthetic egress integration test" >&2
 exit 127
fi
export POSTGRES_USER=artex
export POSTGRES_DB=artextest
export POSTGRES_PASSWORD=integration-test-not-secret
export ARTEX_LAB_SUBNET=172.30.137.0/24
export ARTEX_PG_IP=172.30.137.10
export ARTEX_BROKER_IP=
export ARTEX_TARGET_CIDRS=172.30.137.20/32
export ARTEX_ALLOW_DNS=0

# Unique names and an internal dual-stack network keep this test self-contained.
# The IPv6 negative target is another fixture, never a real external service.
project="artexguardtest$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
allowed="${project}-allowed"
denied="${project}-denied"
network="${project}_contained"
fixture_dir="$(mktemp -d)"
fixture_compose="${fixture_dir}/compose.yml"
cleanup() {
 docker rm -f "$allowed" "$denied" >/dev/null 2>&1 || true
 docker compose -p "$project" -f docker-compose.contained.yml -f "$fixture_compose" down -v --remove-orphans >/dev/null 2>&1 || true
 rm -f "$fixture_compose"
 rmdir "$fixture_dir" || true
}
trap cleanup EXIT
cat > "$fixture_compose" <<'YAML'
networks:
  contained:
    internal: true
    enable_ipv6: true
    ipam:
      config:
        - subnet: 172.30.137.0/24
        - subnet: fd42:2f77:9c31::/64
YAML

# Verify the rendered test network still has the base IPv4 subnet as well as
# the fixture IPv6 subnet. This is not a change to the deployment Compose file.
docker compose -p "$project" -f docker-compose.contained.yml -f "$fixture_compose" config --format json | python3 -c 'import json,sys; n=json.load(sys.stdin)["networks"]["contained"]; subnets={c["subnet"] for c in n["ipam"]["config"]}; assert n.get("internal") is True and n.get("enable_ipv6") is True; assert "172.30.137.0/24" in subnets and "fd42:2f77:9c31::/64" in subnets'
docker pull nginx:alpine
docker pull curlimages/curl:8.16.0
docker compose -p "$project" -f docker-compose.contained.yml -f "$fixture_compose" up -d --build postgres network-guard
docker run -d --name "$allowed" --network "$network" --ip 172.30.137.20 nginx:alpine
docker run -d --name "$denied" --network "$network" --ip 172.30.137.21 --ip6 fd42:2f77:9c31::21 nginx:alpine
GUARD_ID="$(docker compose -p "$project" -f docker-compose.contained.yml -f "$fixture_compose" ps -q network-guard)"
test -n "$GUARD_ID"
for n in 1 2 3 4 5 6 7 8 9 10; do
 if docker run --rm --network "container:$GUARD_ID" --cap-drop ALL curlimages/curl:8.16.0 --noproxy '*' -fsS --connect-timeout 2 --max-time 4 http://172.30.137.20/ >/dev/null; then break; fi
 if [ "$n" -eq 10 ]; then echo "FAIL: approved target unavailable" >&2; exit 1; fi
 sleep 1
done
# A live unguarded control distinguishes firewall denial from an absent target.
for n in 1 2 3 4 5 6 7 8 9 10; do
 if docker run --rm --network "$network" --cap-drop ALL curlimages/curl:8.16.0 --noproxy '*' -fsS --connect-timeout 2 --max-time 4 http://172.30.137.21/ >/dev/null; then break; fi
 if [ "$n" -eq 10 ]; then echo "FAIL: synthetic IPv4 control target unavailable" >&2; exit 1; fi
 sleep 1
done
if docker run --rm --network "container:$GUARD_ID" --cap-drop ALL curlimages/curl:8.16.0 --noproxy '*' -fsS --connect-timeout 2 --max-time 4 http://172.30.137.21/ >/dev/null; then
 echo "FAIL: forbidden target reachable" >&2; exit 1
fi
# First prove the IPv6 fixture is reachable from an unguarded peer. A failed
# guarded connection is meaningful only if the target and route really exist.
for n in 1 2 3 4 5 6 7 8 9 10; do
 if docker run --rm --network "$network" --cap-drop ALL curlimages/curl:8.16.0 --noproxy '*' -6fsS --connect-timeout 2 --max-time 4 'http://[fd42:2f77:9c31::21]/' >/dev/null; then break; fi
 if [ "$n" -eq 10 ]; then echo "FAIL: synthetic IPv6 control target unavailable" >&2; exit 1; fi
 sleep 1
done
if docker run --rm --network "container:$GUARD_ID" --cap-drop ALL curlimages/curl:8.16.0 --noproxy '*' -6fsS --connect-timeout 2 --max-time 4 'http://[fd42:2f77:9c31::21]/' >/dev/null; then
 echo "FAIL: unauthorized IPv6 fixture reachable through guard" >&2; exit 1
fi
echo "PASS: approved IPv4 fixture reachable, forbidden IPv4/IPv6 fixtures blocked"
