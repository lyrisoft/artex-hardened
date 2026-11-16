#!/usr/bin/env bash
# Synthetic Docker fixture only: it does not implement or attest a team runner.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" && "${ARTEX_SYNTHETIC_DOCKER_TEST:-}" != "I_UNDERSTAND_DISPOSABLE_DOCKER_HOST_ONLY" ]]; then
  echo "Use only on a disposable Docker host; set ARTEX_SYNTHETIC_DOCKER_TEST to the documented acknowledgement." >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for the synthetic hardening fixture" >&2
  exit 127
fi
suffix="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
network="artex-runner-test-${suffix}"
server="${network}-target"
runner="${network}-runner"
stage="fixture image"
cleanup() {
  result=$?
  if [[ "$result" -ne 0 ]]; then
    echo "FAIL: disposable Docker fixture failed at $stage (exit $result)" >&2
    docker logs "$server" >&2 2>/dev/null || true
    docker logs "$runner" >&2 2>/dev/null || true
  fi
  docker rm -f "$runner" "$server" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Resolve the public fixture image to its local content ID for all invocations.
# This tag is used only on the disposable CI host and is not a production image.
docker pull alpine:3.22 >/dev/null
image_id="$(docker image inspect --format '{{.Id}}' alpine:3.22)"
if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "FAIL: fixture image has an unexpected content ID" >&2
  exit 1
fi
stage="fixture network and target"
docker network create --internal "$network" >/dev/null
docker run -d --name "$server" --network "$network" "$image_id" /bin/sh -c \
  'mkdir -p /www; echo synthetic-fixture > /www/index.html; exec httpd -f -p 8080 -h /www' >/dev/null
target_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")"
if [[ ! "$target_ip" =~ ^[0-9.]+$ ]]; then
  echo "FAIL: synthetic target has no IPv4 address" >&2
  exit 1
fi
stage="synthetic target positive control"
# This positive control proves the target and network work independently of the
# isolated container's negative connection test.
for n in 1 2 3 4 5 6 7 8 9 10; do
  if docker run --rm --network "$network" "$image_id" wget -q -O - -T 3 "http://${target_ip}:8080/" | grep -q synthetic-fixture; then
    break
  fi
  if [[ "$n" -eq 10 ]]; then echo "FAIL: synthetic target unavailable" >&2; exit 1; fi
  sleep 1
done

stage="read-only filesystem controls"
# Prove the read-only mount is doing work: in an otherwise similar throwaway
# control, root owns / and can write there when the root filesystem is writable,
# but the same operation must fail with --read-only. These are isolated test
# controls, not the non-root runner container checked below.
docker run --rm --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges:true \
  "$image_id" /bin/sh -c 'touch /artex-rw-control'
if docker run --rm --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges:true --read-only \
  "$image_id" /bin/sh -c 'touch /artex-ro-control' 2>/dev/null; then
  echo "FAIL: read-only filesystem allowed a root write" >&2
  exit 1
fi

stage="hardened container creation"
# A host variable is a dummy canary: it must not be inherited by the container.
export ARTEX_RUNNER_TEST_SECRET='fixture-only-do-not-forward'
docker create --name "$runner" --network none --user 65532:65532 --read-only \
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,size=16m,uid=65532,gid=65532' \
  --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 32 \
  --memory 128m --cpus 0.5 "$image_id" /bin/sh -c '
    set -eu
    test "$(id -u)" = 65532
    test "$(id -g)" = 65532
    test -z "${ARTEX_RUNNER_TEST_SECRET+x}"
    test ! -S /var/run/docker.sock
    grep -Eq "^CapEff:[[:space:]]*0+$" /proc/self/status
    grep -Eq "^NoNewPrivs:[[:space:]]*1$" /proc/self/status
    grep -Eq "^Seccomp:[[:space:]]*2$" /proc/self/status
    if touch /artex-forbidden 2>/dev/null; then echo "writable root" >&2; exit 1; fi
    echo synthetic > /tmp/fixture
    test "$(cat /tmp/fixture)" = synthetic
    if wget -q -O /dev/null -T 3 "http://$1:8080/" 2>/dev/null; then
      echo "network-none container reached target" >&2; exit 1
    fi
    echo "PASS: disposable no-network container passed hardening checks"
  ' fixture "$target_ip" >/dev/null

stage="Docker configuration inspection"
docker inspect "$runner" | python3 -c '
import json, sys
container = json.load(sys.stdin)[0]
host, cfg = container["HostConfig"], container["Config"]
assert cfg["User"] == "65532:65532"
assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True
assert host["Privileged"] is False and not host.get("Binds") and not host.get("VolumesFrom")
assert "ALL" in host["CapDrop"] and "no-new-privileges:true" in host["SecurityOpt"]
assert host["PidsLimit"] == 32 and host["Memory"] == 128 * 1024 * 1024
assert host["NanoCpus"] == 500000000 and set(host["Tmpfs"]) == {"/tmp"}
'
stage="hardened container runtime"
docker start -a "$runner"
