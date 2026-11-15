# MaiGuard security operations implementation plan

Status: planning and Phase 1 work in progress. This document is not approval to
execute a test, expand scope, change live access, activate an agent, or deploy.
The program is tracked by [#4](https://github.com/lyrisoft/artex-hardened/issues/4)
and is sequenced [#5](https://github.com/lyrisoft/artex-hardened/issues/5) →
[#6](https://github.com/lyrisoft/artex-hardened/issues/6) →
[#7](https://github.com/lyrisoft/artex-hardened/issues/7) →
[#8](https://github.com/lyrisoft/artex-hardened/issues/8). Each phase uses a
separate feature branch and PR against `main`; do not merge without authorization.
The [program reference](https://docs.google.com/document/d/17cRcQhk2Bm4WOQ-SVkhJOmsyo6PZXWVmZORJmhu3B3c/edit)
is a proposal, not a grant of target access. Use disposable synthetic targets and
records for development and tests; no customer data or production credentials.
The [owner decision brief](PHASE1-OWNER-DECISIONS.md) recommends a minimal,
synthetic-only pilot direction and identifies its operational approval gates.

## Baseline and design checkpoint

At `855bccf6bdbafd3d6f1af3ed920195886290dc1e`, ARTEX has one shared password
and JWT subject (`ARTEX`); a valid signature alone passes the API middleware.
Approval attribution therefore does not distinguish people or establish independent
approval. Agent `role`, prompt, tool visibility, and the global security profile
are not principals or isolation boundaries. Default SDK tools are assembled in the
agent process; MCP, skills, shell, browser and other tools require call-time controls.

Tasks, assets, exploration graphs, findings, traffic, retests, conversations,
credentials and archives are stored in PostgreSQL or shared filesystem paths. The
API, planner and workers share process, database connection and filesystem access.
The contained Compose profile has an independently configured network guard, but
one ARTEX network namespace and its allowed CIDRs are not per-team execution,
credential or evidence isolation. It does not protect a DB secret available to a
shell in that process. The cloud model broker keeps the provider key out of ARTEX,
but is not data-loss prevention. An IP allowlist does not establish FQDN policy for
shared/CDN addresses, redirects, rebinding or DNS exfiltration. The existing
`task_scope` and `company_scope` are mutable coverage/inventory data, **not**
authorization to contact targets. The target gate is optional and shell command
matching cannot reliably classify encoded or indirect actions.

The scheduler reads global task events, and `fireToolCalls` currently includes raw
input/output in messages to matching enabled triggers. Its in-memory queue and
watermarks are not one transaction, so restart can lose or repeat work; do not
claim exactly-once delivery. Existing credentials and evidence are not team scoped. Task passwords are encrypted at rest,
but `TaskCredentials` decrypts them and `taskCredentialOverview` includes them in
agent context, which can reach the configured model provider. SDK default tools are
not automatically removed by MCP/skill visibility. The original tool resolver
also passed its input through when the catalog query failed. This branch stops the
four main agent paths and goal decomposition on a catalog failure, checks before
MCP augmentation, and rechecks the catalog at each harness call (including SDK
and deferred calls). Agent assembly also aborts if its visibility inputs or an
assigned skill cannot be loaded. The SDK can silently discard malformed skill
frontmatter, so this does not establish a reliable skill-to-MCP boundary. Unknown
legacy tools still pass the catalog check; standalone MCP discovery, per-team
authorization and independent process isolation remain incomplete. These
checks do not stop a permitted shell from accessing shared files or connections.
The program must close all of these paths before it claims isolation or enables teams.

### Phase 1 implementation checkpoint

- Migrations 0004–0006 create inactive principal/workspace and scoped-trigger
  data, specialist/product catalogs and append-only synthetic-scope records. No
  principal, agent, trigger, credential or executor is enabled by these migrations.
  A lookup maps an already verified issuer, subject and kind to an enabled
  persisted principal; it does not verify credentials or choose an identity provider.
  Legacy records are not automatically assigned or quarantined; legacy HTTP routes
  still use the shared identity and can access data outside these proposed checks.
- `AuthorizeWorkspaceAction` checks current membership and a directly assigned
  agent or task for a narrow set of CRUD actions. Scheduling/execution, evidence,
  secrets, tool/MCP calls, approval decisions and protected detection changes deny
  by default. It is not connected to the legacy API or runtime and is not sufficient
  on its own: an eventual protected operation must authenticate its caller and
  combine resource verification and authorization with the operation transaction.
- Goal decomposition now honors catalog bindings for `add_task_scope`. Newly seeded
  catalogs include the goals binding; an existing catalog is not automatically
  changed, so an operator must explicitly add that binding to retain automatic
  goal-stage scope extraction. Planner scope tools and existing graph data remain.
  Decide and test the migration of existing customized bindings before rollout.
- A synthetic scope proposal stores exact JSON bytes and their hash; a distinct
  active human approver may append an approval, and an authorized human may append
  a revocation. The read path rechecks memberships, task assignment, time and hash.
  A label does not establish that data or targets are synthetic. JSON semantics,
  approved methods, signatures, independent storage/administration and egress
  enforcement are not implemented. DB owners can bypass the append-only triggers;
  no proposal or approval authorizes a network action.
- The legacy scheduler excludes assigned tasks, agents and bound triggers from its
  global queries, retains source IDs through queue merges and rechecks before a
  legacy run. These checks are not atomic with runtime execution or data migration.
  The inactive scoped tool-event query filters by bound principal, workspace,
  membership, trigger, agent and task in PostgreSQL, returns metadata without raw
  inputs/outputs and supports a fresh pre-dispatch check. An inactive dispatch
  seam rechecks before a trusted sink, but is not wired to the executor; other
  event types and transactional queues/leases remain unfinished.
- `security/runnercontract` validates only a desired configuration (non-root,
  immutable image digest, no host mounts or environment, resource limits and
  distinct team policy references). It does not launch, attest or isolate a real
  executor, verify an egress broker, or make a target safe. All execution remains
  legacy and shared-process until an owner-approved isolated executor is implemented.

Owner decisions before operational rollout (the proposed defaults below are
engineering directions, not authorization):

1. Select and independently provision the human identity provider, service
   identity issuance/revocation, initial owner and independent approver bootstrap.
   Decide how to map or quarantine existing data and which operators may migrate it.
   Do not infer team membership or approval authority from the shared password.
2. Approve an isolation implementation and operator ownership: per-run disposable
   executor and independently managed egress/credential brokers are proposed.
   Decide its host, image provenance, network and FQDN-aware resolver/proxy policy,
   secret issuer, model provider/data handling and emergency stop. No test agent
   receives a production credential, customer data, management DB credential,
   JWT key, host socket or another team's secret.
3. Define tenant/evidence classifications, explicit Red/Blue/Purple sharing and
   blind-exercise disclosure rules, evidence retention and external audit custody.
   Purple read grants must not confer approval or detection-edit rights.
4. Asset and security owners must sign exact target manifests, allowed methods,
   time windows, ceilings, stop conditions and synthetic account scope. Review any
   production access change, containment, destructive action, scope expansion or
   deployment independently before it occurs.

## Cross-cutting implementation contracts

- Persist durable human and service principals, team types, memberships and scoped
  workspace/tenant IDs separately from agent display roles. Authenticate a unique
  principal, resolve current membership and status on each operation, deny on
  missing/error/expired/revoked state, and audit authorization decisions. Do not
  treat a JWT claim, prompt, UI filter or agent-supplied ID as authority.
- A separately administered immutable, versioned approval manifest identifies
  tenant, environment, exact targets, methods, owner, validity, limits, revocation
  and digest. Creation and changes require an authorized human. Graph discovery
  may add inventory but cannot change this manifest. Check the manifest at admission,
  after dequeue, immediately before dispatch and in the independent egress layer;
  revocation stops already queued work and interrupts active leases.
- Route every REST, SSE/download/export, scheduled/background/retest, tool and MCP
  path through the same backend authorization service. Cover list, count, search,
  nested IDs, batch actions and indirect graph/archive links; filter before loading
  or returning data. PostgreSQL constraints, narrow service identities and, where
  practical, row-level security provide defense in depth; test with the actual
  application DB role, including RLS owner/bypass behavior and connection pooling.
- Assign each run a short-lived identity and a narrowly scoped capability bound to
  principal, tenant, workspace, task, manifest revision, operation, tool and expiry.
  Recheck membership, grant, approved target and revocation at the execution boundary.
  Tool output and retrieved text are untrusted; neither may grant privileges. A
  Purple or other agent cannot approve its own action; approvers must be distinct,
  active, authorized humans and decisions bind to the exact request and scope.
- The control plane must not execute untrusted shell/browser/scanner code. Dispatch
  authorized tool calls to disposable, non-root per-run executors with separate
  filesystem and network namespaces, no host/Docker socket, no database, keys or
  shared secret mounts, dropped capabilities and resource/time limits. Preserve
  Bash, scanners, browser, proxy capture, retester and graph capabilities through
  a narrow authenticated protocol and synthetic-fixture integration tests. Give
  Red, Blue and Purple distinct network and credential policies; Blue is read-only
  and cannot invoke offensive execution. Apply egress outside the executor to every
  subprocess, including DNS, IPv4/IPv6, proxies and redirects. Deny by default.
- Broker test credentials as narrowly scoped, short-lived leases; do not copy real
  production secrets or data into an executor. Models use approved endpoints and
  bounded synthetic inputs; keep provider keys outside executor containers. Network
  rules cannot by themselves prevent sensitive prompts from leaving for a model.
- Preserve immutable source evidence, timestamps, hashes, lineage and independent
  audit storage. Mediate writes through a scoped intake service; record observations
  separately from model hypotheses and never overwrite original proof on retest.
  Cross-team disclosure needs an explicit, audited grant and redaction policy.
- Use current migrations (`db/migrations` are checksummed and forward-only), not
  edits to published migrations. Back up and rehearse restoration on synthetic
  copies. Add nullable/new objects, quarantine unmapped legacy data, validate and
  backfill via an explicit operator-reviewed process, then enforce constraints.
  Rollback means stop runs, revoke leases, preserve new evidence, and restore a
  tested backup or deploy a compatible rollback binary that still embeds every
  applied migration with new features disabled. The current migration runner rejects
  a binary missing an applied migration; an unmodified older binary cannot open the
  upgraded database. Do not delete a checksum or silently discard data. Reconcile
  writes since backup before any restore; document schema-specific recovery.

## Phase 1 — agent foundation (#5)

Current branch: a forward migration creates disabled principals, tenants, teams,
workspaces and memberships plus inert specialist and product-template catalogs.
It does not assign existing records or activate agents. A database resolver checks
current enabled/unexpired membership, but no authentication, API, tool, scheduler
or executor path calls it yet. Legacy records remain accessible through legacy
paths; they are **not yet quarantined**. No team isolation is established.

Implementation slices, in dependency order:

1. Inventory all authenticated and unauthenticated API, websocket/SSE, MCP,
   trigger, task, graph, file, secret, model and evidence entry points; enumerate
   data flows and principal/tenant ownership. Add unique principals, memberships,
   workspace/team types and resource ownership with migrations and indexes. Leave
   legacy records quarantined until mapped by an authorized human. Establish a
   documented identity bootstrap and a safe disabled-by-default transition path.
2. Implement a centralized action/resource policy with explicit deny by default,
   per-resource query scoping and independent human approval. Cover agent CRUD,
   task creation/control, schedules and background workers, evidence, credential
   access, tools/MCP and decisions; check permissions before disclosure and again
   at execution. Verify access using direct HTTP calls, guessed IDs, batches,
   streams, database errors, revoked grants, cross-tenant joins and cancellation.
3. Extract untrusted execution into the independently restricted per-run runner
   described above. Replace direct SDK tool execution and MCP spawning with the
   mediated execution path, including process children and browser traffic; isolate
   credential leases and evidence intake. Keep legacy shared-process execution
   clearly identified as insecure and unavailable to isolated team principals.
4. Define the eight specialist templates: Red Lead, API Security, Cloud Security;
   Blue Lead, Detection Analyst, Incident Analyst; Purple Coordinator and Retester.
   Templates provide descriptions/defaults only; an operator-controlled policy and
   manifest decide permissions. Add Sentinel, Verify and MaiGuard ID task templates
   without built-in live targets, secrets or implicit approvals.
5. Add scoped workspaces to existing agent, task, graph, finding, evidence and
   approval interfaces. UI uses server-filtered results and displays authorization,
   verification and missing telemetry state; it never serves as the boundary.
6. Change trigger queries to fetch only the event fields a specific recipient may
   see, redact before enqueue, persist owner/scope, disable unsafe cross-task merge,
   and reauthorize at dispatch. Until done, new team principals cannot use the
   legacy global trigger path. Do not promise exactly-once execution from watermarks.
7. Exercise Docker hardening, separate egress and safe model broker on disposable
   fixtures: allowed and denied IPv4/IPv6, DNS/redirect/rebinding/proxy cases,
   restart/revocation, no credential mounts, no host socket, resource limits,
   independently recorded audit and synthetic shell/scanner/browser evidence.
   Run existing scanner, retester and asset-graph regressions; fix rather than
   bypass tests. Document setup, migrations and rollback. No activation or deploy.

### Phase 1 migration and recovery rehearsal

`0004_team_foundation.sql` is additive: it adds disabled security records and
catalog rows, leaves existing tasks/agents untouched, and does not assign ownership.
`0005_scoped_trigger_bindings.sql` adds disabled trigger bindings and
`0006_synthetic_scope_records.sql` adds append-only synthetic proposal, approval
and revocation records. The last two add no bindings or scopes during migration.
On a disposable copy, verify the pre-migration backup, record its checksum and the
applied migration checksums, upgrade, check legacy evidence/graphs, and run the
negative membership and authorization suite before enabling any future feature.
No migration makes old shared-password sessions trustworthy.

For a rollback rehearsal, stop admission and drain/terminate isolated leases, export
and preserve all new membership/evidence/audit records, and verify backup integrity.
Use a rollback build that retains the exact embedded bytes/checksums of all applied
migrations 0004–0006 but disables the new feature; an older binary missing any
applied migration will refuse the newer migration record. Alternatively restore the verified pre-migration backup to
a separate database and reconcile all writes since the snapshot before switching.
Never remove the recorded checksum to force an older binary to start. Owner approval
and a tested change window are required for any live migration, restoration or
cutover; this branch does not perform one.

## Phase 2 — Blue monitoring (#6), after #5 acceptance

- Reuse existing telemetry and Wazuh where available. Register sources with
  least-privilege read-only identities; adapters for application audit, CloudTrail,
  GuardDuty, WAF, VPC Flow Logs and optional Wazuh ingest synthetic fixtures first.
- Version normalized UTC events with source/tenant/asset/actor/trace provenance;
  deduplicate by source identity, tolerate delays/out-of-order events and mark
  unavailable telemetry explicitly. Authenticate source registration and reject
  forged/malformed/cross-tenant records.
- Implement versioned deterministic rules for authentication, cross-tenant,
  administrative access, bulk retrieval, IAM and egress anomalies. Correlate alerts
  with event references, rule version, confidence and timestamps; LLM text can only
  explain cited evidence, never create an observed event or approve containment.
- Add scoped investigation and incident APIs/UI, triage and governed suppression.
  Migration adds versioned sources, events, rules, alerts, incidents and provenance;
  retain legacy evidence. Disable ingestion, drain/checkpoint queues, preserve source
  offsets and event evidence on rollback; restore from tested backup if needed.
- Test fixture replay, duplicates, malformed/spoofed events, disorder, missing logs,
  tenant isolation and deterministic true/false positives; monitor ingestion lag,
  failures, bounded retention, polling, storage and model cost. Owner approval is
  required for actual source identities and production access; no mutation by Blue.

## Phase 3 — Purple orchestration (#7), after #5 and #6 acceptance

- Add exercises with immutable ID, manifest revision, owners, synthetic identities,
  approvals, schedule, disclosure state, stop conditions and independently owned
  evidence links. Enforce blind-stage access and pause/stop without agent scope edits.
- Correlate independent Red actions and Blue events by test marker, trace/request ID,
  asset and UTC windows with explicit clock-skew limits. Preserve original evidence
  and rule versions; derive observed/blocked/not-observed/telemetry-unavailable from
  source records, not model summaries. Scorecards use only verified timestamps.
- Provide exercise/approval/evidence APIs and a scoped chain/coverage UI. Migrations
  add exercise, immutable scope references, evidence links, correlation results and
  disclosure grants. On rollback disable new exercise starts, stop leases, retain
  evidence and read-only exports, and restore only after backup/reconciliation.
- In staging demonstrate distinct identities, a true positive, a missed detection,
  a noisy false positive, blind access controls, tamper resistance, owner-linked
  remediation and independent retest. Exercise stop, expiry and authorization tests.

## Phase 4 — continuous assurance (#8), after #5–#7 acceptance

- Extend the existing scheduler, templates, triggers and retester. Persist owner,
  scope revision, expiry, budgets and immutable event idempotency keys; a transactional
  outbox, claim/lease, retry and deduplication design must handle crashes and
  concurrency. Recheck permissions, scope, approval and revocation before each run.
  Exactly-once external effects are not assumed; use idempotent operations and
  reconciliation. Include kill switches and resource/concurrency limits.
- Add authorized release events, recurring staging assessments, coverage sweeps and
  constrained remediation retests. Export redacted, role-scoped audit reports with
  proven/failed/inconclusive/uncovered distinctions and source links. Dashboard
  evidence completeness, spend, storage, retention, coverage and retest age.
- Migrations add schedule ownership, outbox/lease/idempotency and budget records;
  rollback disables triggers, drains/reconciles leases, retains history/evidence,
  and documents re-enable/replay. Validate duplicate/concurrent/restarted releases,
  expired or revoked scopes, out-of-scope targets, cost caps and on-call runbooks.
- Pilot exit: run the independently evidenced Red → Blue → Purple → engineering →
  retest sequence twice on distinct approved synthetic staging releases.

## Acceptance matrix

All statuses start **open**; no phase or issue is complete until its full evidence
is reviewed. A prior main-branch CI pass does not prove a new branch or runtime.

| Phase / requirement | Evidence required | Status |
| --- | --- | --- |
| #5 Red approved synthetic test | Separate executor runs Bash, scanner and browser only against approved fixtures; saved finding links preserved source evidence | Open |
| #5 Red/Blue separation | Direct API, DB, tool/MCP, process, network and credential negative tests; Blue cannot execute offensively or read Red secrets; Red cannot change telemetry | Open |
| #5 Purple separation | Explicit evidence grant succeeds; protected detection mutation and self-approval denied for every path | Open |
| #5 all entry points | Scoped REST, SSE, batch, scheduler, background and MCP checks before disclosure and rechecked at dispatch; revocation race tests | Open |
| #5 hostile content | Prompt injection and altered tool output cannot change identity, permissions, manifest or execution policy | Open |
| #5 persistence/compatibility | Migrations, legacy quarantine, backup/rollback rehearsal, setup docs and scanner/retester/asset-graph regressions | Open |
| #5 runtime gate | Disposable Docker, network-guard, credential and model-broker acceptance; independent review and no activation before success | Open |
| #6 telemetry/detection | All synthetic source fixtures, provenance, deterministic detections, malformed/replay/order/tenant isolation, no-log state, read-only Blue and failure metrics | Open |
| #7 exercise | Distinct identities, blind scope, true/missed/noisy cases, verified source/timestamps, pause/stop, remediation/retest and immutable proof | Open |
| #8 assurance | Idempotent approved release, constrained retest, revoked/expired denial, concurrency/restart, honest reports, budgets and rollback | Open |
| #4 end to end | Authorized staging chain with independently verifiable evidence and UTC timestamps; #8 pilot repeated on two releases | Open |

## Validation record

- After the visibility-error change, `go test -p 1 -count=1 -timeout 180s
  ./...` passed against a fresh synthetic PostgreSQL cluster. The first run exposed
  fixtures using a closed visibility store, missing shipped skills, and a temporary
  skill binding whose cleanup ran after its DB closed; the fixtures now use a live
  store and clean up in order. The complete `go test -race -p 1 -count=1
  -timeout 180s ./agent ./server` passed on another fresh fixture, as did
  `go vet -p 2 ./agent ./server` and a Go build. These checks do not validate malformed skill metadata or establish
  team isolation.
- On this Phase 1 branch, `go test -p 1 -count=1 ./...` passed on a fresh,
  loopback-only synthetic PostgreSQL fixture after updating the migration inventory
  and a manually constructed chat-worker test to use its own live policy store.
  `go test -race -p 1 -count=1 ./db ./agent ./server ./security/runnercontract`
  passed against a separate fresh fixture. After the final goal-prompt, nested
  deferred-call and inactive dispatch-seam edits, the complete normal suite was
  repeated on another fresh fixture and affected agent and server tests were rerun
  under `-race`. The subsequent inactive verified-identity lookup and related
  database-policy regressions also passed under `-race` on a fresh fixture.
  The new tests cover policy-store outages before/after augmentation and at calls,
  SDK/deferred tool checks, no tools in connection tests, workspace CRUD/default
  denials, scoped scheduler filtering and revocation, distinct human scope approval,
  append-only records and hash checks, and the inactive runner contract. They do not
  prove production isolation or authorize an activation. Existing skips remain.
- `go vet -p 2 ./...`, `go build -p 2 ./...`, frontend `tsc --noEmit` and
  `npm run build:static`, and the seven loopback broker tests passed locally. Docker
  is unavailable locally; the existing GitHub Docker fixture must rerun on the new
  PR head and still does not establish team isolation.
- Main `855bccf`: GitHub Actions `ci` failed in Go tests; build and vet passed,
  web and shell jobs passed, race job was skipped. Failures were
  `TestTargetOnlyGuardSkipsRules` (nil approval DB) and `TestSkillTools` (expected
  skill mutation despite default-deny). The separate contained-egress integration,
  hardened Compose and security profile workflows reported success on that commit.
- Local baseline `go test ./guard ./server -run
  '^(TestTargetOnlyGuardSkipsRules|TestSkillTools)$' -count=1` reproduced both.
  After the fixture/approval-store changes, the same targeted tests plus
  `TestTargetOnlyGuardMandatoryApprovalFailsClosed` passed. Default pentest,
  research, invalid and unacknowledged lab profiles denied skill writes; the
  existing filesystem behavior was tested only in an acknowledged temporary lab.
- A local fresh-DB `go test -p 1 -count=1 ./...` passed after repairing a test
  cleanup that leaked a fake active model profile; this run preceded the later
  membership-resolver and previously skipped graph/approval test changes. Targeted
  PostgreSQL tests for migration, resolver, scanner ingestion, retester and graph
  passed afterward. The two formerly skipped graph and approval-lifecycle tests
  were run against another fresh synthetic database and passed. The graph fixture
  now checks the deliberately compact overview and the detailed on-demand company
  scope interface. The timing-sensitive side-question usage test and SQLite FTS5
  cases remain skipped by the existing suite.
- `go build -p 2 ./...` and `go vet -p 2 ./...` passed again after the resolver
  was added. The CI package list passed `go test -race -p 1 -count=1` with a fresh
  synthetic PostgreSQL database, including the re-enabled graph and approval tests.
  After the catalog failure change, `go test -p 1 -count=1 -v ./server -run
  '^TestWireTools'`, the same command with `-race`, and `go build -p 2 ./server`
  passed: an unavailable catalog returned no resolver-input tools and a healthy
  catalog retained its normal bindings. Those earlier results predate the newer
  per-call policy checks; see subsequent validation for the current implementation.
  `npm ci --ignore-scripts --no-audit --no-fund`, `tsc --noEmit` and
  `npm run build:static` passed using Node 24 and the environment's trusted proxy;
  CI uses Node 22. Network-guard (4 tests) and model-broker (7 tests) Python suites
  passed. The broker's loopback-only TLS fixture uses generated certificates and
  dummy credentials; it checks request denial, credential substitution, untrusted
  certificate rejection, and incremental chunked/unchunked streaming. It exposed
  buffering in `read`, fixed by using `read1`; no real provider was contacted.
  Compose v5.7.1 rendered the base, isolated, contained, model-broker and dual-stack
  fixture configurations; the supplied structural checkers passed.
- GitHub Actions [run 43708361299](https://github.com/lyrisoft/artex-hardened/actions/runs/43708361299)
  failed `TestEveryAgentKindCarriesTargetScope`: a manually constructed test server
  inherited a previous test's closed database resolver. The fixture now installs its
  own live resolver; the policy-store outage behavior remains fail closed for that
  resolver's inputs. `go test -p 1 -count=1 ./server` and the same command with
  `-race` passed afterward against separate fresh synthetic databases.
- `bash -n scripts/test-egress-integration.sh` passed. Actual execution reports
  `Docker is required for the synthetic egress integration test` (exit 127): this
  environment has no Docker CLI/daemon. GitHub Actions [run 43707740351](https://github.com/lyrisoft/artex-hardened/actions/runs/43707740351)
  on draft PR #9 commit `8be7bf97` ran the revised script successfully: positive
  controls reached the synthetic targets, the allowed IPv4 target was reachable
  through the guard, and the other IPv4/IPv6 targets were blocked. This tests one
  guarded network namespace, not team isolation. No browser/scanner container,
  live model connection, team runner, per-team egress or end-to-end staged exercise
  has been verified. No deployment or agent activation is authorized by these results.
