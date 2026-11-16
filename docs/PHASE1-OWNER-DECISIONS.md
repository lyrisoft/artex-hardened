# Issue #5: approved synthetic-only design direction

**Design direction approved:** the owner approved the three defaults below on
2026-11-16. This does not authorize deployment, access changes, agent activation,
or a pilot. The actual identity provider, host, trust roots, independent evidence
store and responsible owners still need to be identified before a separately
approved pilot. If the required infrastructure is unavailable, keep it disabled.

## 1. Identity and bootstrap

**Recommend:** reuse an existing OIDC-capable identity provider. Verify issuer,
signature, audience, expiry and subject server-side; map each verified person to
a persisted principal and issue short-lived, scoped service identities for runs.
Bootstrap two distinct humans: a workspace operator and an independent approver.
Quarantine unmapped legacy records and review customized tool bindings explicitly;
never infer identity or approval authority from the shared ARTEX password.

**Tradeoff:** reusing an existing provider avoids operating another identity
service but requires integration and managed onboarding/revocation. If none is
available, choose one before activation. OIDC does not itself enforce workspace
permissions. [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)

## 2. Execution, targets, credentials, and models

**Recommend:** start on one dedicated disposable nonproduction VM, with one run at
a time. Each team run gets its own disposable non-root container, filesystem and
network namespace, pinned image, read-only root with private writable scratch,
default seccomp, no added capabilities or host/Docker socket, and resource limits. No executor can reach or
mount the control-plane DB, keys, evidence store, or another team's credentials.
A separately administered egress boundary permits only exact operator-approved
synthetic fixture addresses and ports; deny other traffic, DNS and IPv6 until
explicitly approved and tested. An owner-operated stop must revoke queued work and
interrupt active runs.

Use only dummy credentials for disposable targets, delivered through a scoped
broker directly to tools when needed, and keep credential values out of model context. Use a fake or
local model for tests; separately approve any external pilot model's endpoint and
data handling. Preserve shell, scanner, browser, retester and graph capabilities
in fixture tests. Capability-dependent tools, including raw-packet scanners, need
a separately reviewed narrow execution path before pilot acceptance.

**Tradeoff:** this reuses the existing Compose and broker work without requiring a
new paid service, but needs VM capacity and engineering for a real runner and
independent egress. The current guard shares ARTEX's namespace and is not a
per-team or port policy; the model broker is not DLP. Rootless Docker reduces
daemon privilege, but its host, network and resource-limit behavior must be tested.
[Docker rootless](https://docs.docker.com/engine/security/rootless/),
[limitations](https://docs.docker.com/engine/security/rootless/troubleshoot/)

## 3. Evidence, sharing, and approval

**Recommend:** a separate scoped intake service preserves original evidence with
hashes, timestamps, provenance and lineage; export independently signed checkpoints
to existing, independently administered tamper-evident storage or immutable backups
that provide equivalent retention guarantees. Do not automatically
delete pilot evidence until an owner sets retention and storage limits. Deny
cross-team disclosure by default; allow explicit audited, redacted grants. Purple
may review granted evidence and propose retests, but cannot self-approve or modify
protected detections; Blue receives read-only defensive access. A distinct human
approves the exact target, methods and time window.

**Tradeoff:** reuse PostgreSQL and suitable backup storage with separate restricted
service identities, but do not give executors DB credentials. Existing DB-owner
access and triggers do not establish immutability. Row-level security is defense in
depth: privileged roles and normally table owners bypass it. If independent custody
is unavailable, keep the pilot inactive. [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

## Cost and activation gate

No budget, provider inventory, VM capacity or storage pricing has been supplied;
this direction is not a cost estimate. Name the host, security and evidence owners;
confirm the IdP and independent backup capability; and estimate VM, model, storage
and operating costs. Before activation, separately approve the specific synthetic
targets and operational change, then verify authenticated RBAC, manifest checks,
isolated execution and egress, brokers, revocation, rollback and capability parity.

Code-only work may continue with new paths inactive. The current schema, scope
records and runner contract are foundations, not team isolation or permission to
run a test. See the [implementation plan](MAIGUARD-SECURITY-OPERATIONS-PLAN.md)
and [contained Compose configuration](../docker-compose.contained.yml).
