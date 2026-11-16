#!/usr/bin/env bash
# Disposable test only. This is not the application runner or an authorization service.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" && "${ARTEX_SYNTHETIC_DOCKER_TEST:-}" != "I_UNDERSTAND_DISPOSABLE_DOCKER_HOST_ONLY" ]]; then
  echo "Use only on a disposable Docker host; set ARTEX_SYNTHETIC_DOCKER_TEST to the documented acknowledgement." >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for the synthetic team egress fixture" >&2
  exit 127
fi
suffix="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
network="artex-team-fixture-${suffix}"
image="artex-team-fixture:${suffix}"
target_a="${network}-a"
target_b="${network}-b"
guard_a="${network}-red"
guard_b="${network}-blue"
stage="image build"
cleanup() {
  result=$?
  if [[ "$result" -ne 0 ]]; then
    echo "FAIL: synthetic team egress fixture failed at $stage (exit $result)" >&2
    docker logs "$guard_a" >&2 2>/dev/null || true
    docker logs "$guard_b" >&2 2>/dev/null || true
  fi
  docker rm -f "$guard_a" "$guard_b" "$target_a" "$target_b" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker pull nginx:alpine >/dev/null
docker pull curlimages/curl:8.16.0 >/dev/null
docker build -f security/fixture-team-guard/Dockerfile -t "$image" . >/dev/null
stage="fixture targets"
docker network create --internal --ipv6 --subnet 172.30.139.0/24 --subnet fd42:2f77:9c32::/64 "$network" >/dev/null
docker run -d --name "$target_a" --network "$network" --ip 172.30.139.20 nginx:alpine >/dev/null
docker run -d --name "$target_b" --network "$network" --ip 172.30.139.21 --ip6 fd42:2f77:9c32::21 nginx:alpine >/dev/null

probe_control() {
  docker run --rm --network "$network" --cap-drop ALL curlimages/curl:8.16.0 \
    --noproxy '*' --silent --show-error --fail --connect-timeout 2 --max-time 4 "$1" >/dev/null
}
wait_control() {
  for n in 1 2 3 4 5 6 7 8 9 10; do
    if probe_control "$1"; then return 0; fi
    if [[ "$n" -eq 10 ]]; then echo "FAIL: synthetic control target unavailable" >&2; return 1; fi
    sleep 1
  done
}
wait_control 'http://172.30.139.20:80/'
wait_control 'http://172.30.139.21:80/'
# The first fixture listens on a second port so a denied-port check has a live
# positive control, rather than merely hitting an absent listener.
docker exec "$target_a" /bin/sh -c 'printf "%s\n" "server { listen 80; listen 81; listen [::]:80; location / { return 200 fixture; } }" > /etc/nginx/conf.d/default.conf; nginx -s reload'
wait_control 'http://172.30.139.20:81/'
wait_control 'http://[fd42:2f77:9c32::21]:80/'

stage="isolated guard startup"
docker run -d --name "$guard_a" --network "$network" --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true --read-only --tmpfs '/run:rw,nosuid,nodev,noexec,size=1m' \
  -e ARTEX_FIXTURE_GUARD_ACK=DISPOSABLE_NETWORK_NAMESPACE_ONLY \
  -e 'ARTEX_FIXTURE_ENDPOINTS=[{"address":"172.30.139.20","port":80}]' "$image" >/dev/null
docker run -d --name "$guard_b" --network "$network" --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true --read-only --tmpfs '/run:rw,nosuid,nodev,noexec,size=1m' \
  -e ARTEX_FIXTURE_GUARD_ACK=DISPOSABLE_NETWORK_NAMESPACE_ONLY \
  -e 'ARTEX_FIXTURE_ENDPOINTS=[{"address":"172.30.139.21","port":80}]' "$image" >/dev/null
wait_guard() {
  for n in 1 2 3 4 5 6 7 8 9 10; do
    if docker exec "$1" test -f /run/fixture-team-guard-ready 2>/dev/null; then return 0; fi
    if [[ "$n" -eq 10 ]]; then echo "FAIL: fixture guard did not become ready" >&2; return 1; fi
    sleep 1
  done
}
wait_guard "$guard_a"
wait_guard "$guard_b"

probe_guard() {
  docker run --rm --network "container:$1" --cap-drop ALL --security-opt no-new-privileges:true \
    curlimages/curl:8.16.0 --noproxy '*' --silent --show-error --fail --connect-timeout 2 --max-time 4 "$2" >/dev/null
}
expect_denied() {
  if probe_guard "$1" "$2" 2>/dev/null; then echo "FAIL: unapproved endpoint reachable" >&2; exit 1; fi
}
stage="team-specific endpoint checks"
probe_guard "$guard_a" 'http://172.30.139.20:80/'
probe_guard "$guard_b" 'http://172.30.139.21:80/'
expect_denied "$guard_a" 'http://172.30.139.21:80/'
expect_denied "$guard_b" 'http://172.30.139.20:80/'
expect_denied "$guard_a" 'http://172.30.139.20:81/'
expect_denied "$guard_a" 'http://[fd42:2f77:9c32::21]:80/'

stage="invalid endpoint rejection"
if docker run --rm --network "$network" --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true --read-only --tmpfs '/run:rw,nosuid,nodev,noexec,size=1m' \
  -e ARTEX_FIXTURE_GUARD_ACK=DISPOSABLE_NETWORK_NAMESPACE_ONLY \
  -e 'ARTEX_FIXTURE_ENDPOINTS=[{"address":"0.0.0.0/0","port":80}]' "$image" >/dev/null 2>&1; then
  echo "FAIL: broad invalid endpoint accepted" >&2
  exit 1
fi
echo "PASS: separate fixture guards enforced exact IPv4 address and TCP port; IPv6 denied"
