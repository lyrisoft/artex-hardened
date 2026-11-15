# Lyrisoft ARTEX Containment — deployment and acceptance runbook

This is the **single consolidated implementation PR** for the ARTEX hardening program.
It is a security boundary **prototype** until isolated integration tests and human review pass.

## Supported execution models

| Configuration | Uses | External target network | Cloud model credentials |
| --- | --- | --- | --- |
| `docker-compose.yml` | Compatibility and upstream-style deployment | Unrestricted by baseline; NOT a secure executor | May enter application container |
| `docker-compose.isolated.yml` (with base) | Disposable local lab on Docker internal network | Not routed externally | No cloud model available without custom routing |
| `docker-compose.contained.yml` (standalone) | Scoped IP-based testing | Guard-side allowlisted IPv4 destinations only; IPv6 denied | No provider key passed by default |
| Contained + `docker-compose.cloud-llm.yml` | Scoped testing with OpenAI-compatible model provider | Same IP restriction; broker separately reaches approved model origin | Provider key resides in broker secret; ARTEX receives only a dedicated client token |

**Do not combine the contained Compose file with the upstream-style Compose file.**

## Required configuration

Use an isolated VM or dedicated Docker host rather than a personal workstation.
Do not mount `/var/run/docker.sock`, SSH key directories, cloud account profiles,
host home directories, or unrelated files into ARTEX.

Create an ignored `.env` with at least:

```dotenv
POSTGRES_PASSWORD=<unique generated password>
ARTEX_TARGET_CIDRS=192.0.2.10/32
ARTEX_SECURITY_PROFILE=pentest
ARTEX_ALLOW_DNS=0
```

Replace the documentation IP with the **actual address(es) you are explicitly authorized to test**.
Never use `0.0.0.0/0`. Scope IPs and DNS targets separately: IP-level filtering
**cannot** distinguish multiple HTTPS hostnames sharing a CDN IP.

For cloud models using OpenAI-compatible endpoints only:

```bash
mkdir -p secrets && chmod 700 secrets
umask 077
printf '%s' "$OPENAI_PROVIDER_KEY" > secrets/openai_api_key
unset OPENAI_PROVIDER_KEY
export ARTEX_BROKER_CLIENT_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(40))')"
docker compose -f docker-compose.contained.yml -f docker-compose.cloud-llm.yml config --quiet
```

Do not put the real provider key in `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
ARTEX's model profiles, or the agent container environment.
The broker intentionally uses an *unrelated* per-deployment token for client
authentication. Rotate both tokens if the instance is exposed.

The broker supports a fixed HTTPS origin with a restricted set of OpenAI-style
paths. Verify the configured provider and streaming behavior before using the
platform for time-sensitive testing. It is not a DLP filter: agent prompts still
leave the environment when an external model is used.

## Bring up the contained deployment

```bash
docker compose -f docker-compose.contained.yml config --quiet
docker compose -f docker-compose.contained.yml up -d --build
docker compose -f docker-compose.contained.yml ps
```

For a model broker, pass both Compose files in the same order for every command.
The upstream-style and contained configurations use different PostgreSQL volumes:
**do not assume existing evidence, credentials, or state has migrated**.

## Mandatory egress acceptance test

Do not deploy on a production host until the following has been verified:

1. ARTEX connects to PostgreSQL and loads its authenticated UI on 127.0.0.1:8787.
2. An authorized test fixture at an explicitly allowed IP is reachable using Bash,
   Python requests and a bundled scanner.
3. A separate fixture at a forbidden IP fails to connect using curl, Python and TCP tools.
4. IPv6 external destinations are unreachable.
5. Host gateway, Docker host management ports, internal LAN, cloud instance metadata
   addresses, and unrelated external services are not reachable unless explicitly
   included in the engagement.
6. Check that the egress guard still denies forbidden traffic following ARTEX restart
   and guard restart.
7. Confirm the relevant model still supports streamed responses through the broker,
   and ARTEX's own container has no cloud-provider key.
8. From the default pentest profile, platform-mutation tools must fail without
   modifying the DB or skill directory. In a disposable advanced-lab deployment,
   acknowledged mutation operations may succeed.
9. The existing approval API must require valid login; high-impact shell calls must
   queue a decision, time out to deny, and never execute without human approval.
10. Persist externally captured security events and inspect the application's
    approval history; verify that service restarts do not destroy necessary evidence.

The GitHub Actions policy tests check configuration shape and application code;
they **do not** simulate an actual malicious agent or prove network enforcement.

## DNS limitations

The contained deployment denies direct DNS by default. This makes domain-based
scanning unavailable unless DNS is separately configured and safely scoped.
`ARTEX_ALLOW_DNS=1` opens Docker DNS and risks DNS-based exfiltration: do not
enable it for untrusted agents without a policy-enforcing resolver.

A production engagement needs an independently administered resolver that
allowlists authorized hostnames, rejects non-approved QNAMEs, and enforces
destination IPs *after* DNS resolution. Shared CDN/IP infrastructure requires
L7 hostname-aware control; an IP allowlist alone does not meet that requirement.

## What is not completed in this PR

- Independent OS process/VM executor (today agent and API share the ARTEX process,
  filesystem namespace and database connection; the *network guard* is separate).
- Full credential brokering for ARTEX's PostgreSQL and stored test credentials.
- Mandatory classification of every high-impact operation, including encoded
  scripts, arbitrary Python code, multi-tool chains and remote script bodies.
- A built-in, securely provisioned scoped DNS service and dynamic hostname
  allowlist for CDN-backed production endpoints.
- A service that automatically forwards all application audit events to an
  external, immutable SIEM.
- Complete runtime proof against container escapes, LLM prompt injection,
  malicious skills or supply-chain compromise.

Keep the PR unmerged until its tests pass and the actual deployment has been
validated on an isolated, expendable Docker host. For threat-model questions,
see `docs/SECURITY-PROFILES.md` and `docs/LYRISOFT-HARDENING.md`.
