# Lyrisoft ARTEX hardening baseline

This fork is intended for authorized lab assessments. No source-only audit can certify
an installed image or prove that a backdoor does not exist. Pin and review every deployment.

## Implemented in phase 1

- Docker Compose enables `no-new-privileges`, an init process, and a 256-PID limit.
- UI/proxy ports remain loopback-bound by default. Do not set `ARTEX_BIND_ADDR=0.0.0.0`
  unless an authenticated ingress and firewall are configured.
- The prompt-injection output boundary and *disabled* update check are explicit defaults.
- `update.sh` defaults to **not** pulling upstream code, and rejects pulling with
  local uncommitted changes. This does not block an administrator from deliberately
  pulling untrusted code or using another update mechanism.

## Deploy after review

```sh
git rev-parse HEAD
docker compose config --quiet
docker compose config --format json | python3 scripts/check-compose-security.py
docker compose build artex
docker compose up -d
docker compose ps
```

The checker inspects the rendered Compose configuration; it does not assess network
firewall enforcement or the behavior of the compiled binary.

## Verify the running instance without disclosing secrets

```sh
CID="$(docker compose ps -q artex)"
docker inspect "$CID" --format 'Image={{.Image}} Privileged={{.HostConfig.Privileged}} Network={{.HostConfig.NetworkMode}} SecurityOpt={{json .HostConfig.SecurityOpt}} CapAdd={{json .HostConfig.CapAdd}} PidsLimit={{.HostConfig.PidsLimit}}'
docker port "$CID"
git rev-parse HEAD
```

Never paste `docker compose config`, `.env`, database rows, or `docker inspect`
environment variables into public issues: they may contain API keys and passwords.

## High-priority remaining review

1. Audit default and user-defined MCP records, agent triggers, custom tools,
   skill scripts, and notification destinations stored in PostgreSQL.
2. Trace every outbound request from the Go backend, browser MCP, shell tools,
   package managers, telemetry and third-party binaries. Permit approved LLM
   endpoints and target hosts using **host/network enforced egress policy**.
   Docker bridge networking and in-application scope checks are not an egress ACL.
3. Enforce a restricted execution identity, narrow persistent directory permissions,
   read-only filesystems and explicit temporary writable paths where supported.
   Verify browser tooling, scanning tools, evidence capture and key persistence.
4. Pin OS/base images and download sources by immutable digest; generate SBOM,
   verify provenance, perform SCA and review upstream diffs before each update.
5. Review JWT query-token exposure, request authorization, setup/login flows,
   stored credentials, upload handling, and SSRF protection with regression tests.
6. Compare source revision with the **actual installed container image** and
   inspect runtime egress. A clean Git checkout does not establish image identity.

## Emergency containment

If unexpected destinations or execution are observed: stop the ARTEX service,
preserve container/log evidence, isolate its network, and rotate credentials
that the container could access. Do not automatically delete evidence.
