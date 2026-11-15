# ARTEX operating profiles — Lyrisoft

## Threat model and feature preservation

The runtime agents retain Bash, Python, Nmap, Nuclei, SQLMap, Playwright, and
other installed security utilities. No command interpreter is removed.

The new guard operates on **agent-initiated platform mutations** (installing
custom executable tools, rewriting skills, configuring MCP servers and
deleting shared asset inventory). These operations are privileged because
they change capabilities for future tasks, potentially across engagements.
Authenticated administrators can configure tools and MCP integrations through
the existing UI; a user-defined tool may still execute arbitrary commands.
Do not treat this as a comprehensive permission sandbox.

## Profiles

- `pentest` (default): all existing scanners, shell and agents continue to
  run; autonomous platform mutations are blocked; approved integrations
  configured by operators remain usable. Target-scoping, approval and request
  interception behavior remains whatever the operator configured in ARTEX.
- `research`: currently the **same backend enforcement** as `pentest`
  for platform mutations. Passive-only execution is **not yet enforced**;
  do not represent this profile as safe for arbitrary third-party websites.
- `advanced-lab`: restores agent-created MCP servers, scripts, skills and
  asset deletion. Requires the exact environment variable
  `ARTEX_ADVANCED_LAB_ACK=I_UNDERSTAND_ISOLATED_LAB_ONLY`.
  Use only against disposable and isolated systems.

These are process-level controls and can be bypassed by a compromised process
with shell access. Effective defense requires independent network isolation.

## Local isolated lab (no external internet)

```sh
export ARTEX_ADVANCED_LAB_ACK=I_UNDERSTAND_ISOLATED_LAB_ONLY
docker compose -f docker-compose.yml -f docker-compose.isolated.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.isolated.yml up -d --build
```

The `internal: true` network disconnects ARTEX and PostgreSQL from external
Docker routing; approved local target containers must join `artex_lab`
and be controlled by the operator. This **cannot** reach arbitrary external
target addresses or cloud-hosted LLM APIs. If using Ollama, deploy or connect
it on this isolated network. Confirm routing with network tests.

Docker publishes the UI/proxy on host loopback per the base Compose file.
For malicious code and exploit payloads, a dedicated disposable VM with
host-side firewall and no access to personal accounts is strongly recommended.

## External authorized penetration testing

Use `pentest` and a separately administered VM/network firewall with
destination allowlisting that includes the authorized target addresses, DNS
resolver and approved model endpoint. Enforce restrictions on ALL protocols
including scanner subprocesses. Application target gates alone do not protect
against `curl`, Bash, DNS tunnels or alternative tools. Network policy must
also allow authorized redirects and DNS changes only after scope verification.

Do not claim that the standard Compose file enforces egress restrictions.
Do not connect a production environment or your primary workstation's
cloud credentials to an untrusted agent workload.

## Verification / acceptance

1. Run `go test ./securityprofile ./server`, plus the repository's regular CI.
2. In `pentest`, verify built-in shell/scanners still run against a disposable
   target; verify the Auto agent's `create_mcp`, `create_custom_tool` and
   `update_skill_file` return policy errors without altering PostgreSQL/files.
3. Verify the UI still supports manual management of trusted MCP/tools.
4. In `advanced-lab` without acknowledgement, platform mutation remains denied.
5. With acknowledgement in a disposable network, platform mutation is possible.
6. Confirm the isolated lab has no outbound route to external internet and
   can still reach its explicitly attached test target and PostgreSQL.
7. Verify no Docker socket, host SSH keys or personal credentials are mounted.
8. Test that agent-side Bash can bypass in-process tool controls; require
   the external network isolation to block unauthorized destinations.

This phase does not implement immutable image provenance, RBAC, a full
host-enforced firewall for external engagements, or syscall-level sandboxing.
