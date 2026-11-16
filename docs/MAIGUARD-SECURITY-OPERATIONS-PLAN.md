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
The [owner decision brief](PHASE1-OWNER-DECISIONS.md) records the approved
synthetic-only design direction and its separate operational approval gates.

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
and deferred calls). Agent assembly aborts if visibility inputs are unavailable or
assigned skill metadata is malformed, and uses one validated snapshot for skill
and MCP gating. Standalone cache discovery no longer runs automatically at server
startup; explicit legacy-authenticated requests recheck catalog availability and
reload the selected MCP configuration before connecting. The shared JWT is not an
individual identity or team grant, and other legacy sync actions remain unscoped.
Unknown legacy tools still pass the catalog check; per-team authorization and
independent process isolation remain incomplete. These checks do not stop a
permitted shell from accessing shared files or connections.
The program must close all of these paths before it claims isolation or enables teams.

### Phase 1 implementation checkpoint

- Migrations 0004–0009 create inactive principal/workspace and scoped-trigger
  data, specialist/product catalogs and append-only synthetic-scope records. No
  principal, agent, trigger, credential or executor is enabled by these migrations.
  A lookup maps an already verified issuer, subject and kind to an enabled
  persisted principal; it does not verify credentials or choose an identity provider.
  Legacy records are not automatically assigned or quarantined; legacy HTTP routes
  still use the shared identity and can access data outside these proposed checks.
- An independently constructed OIDC authorization-code flow uses PKCE S256,
  one-time state and nonce, an explicit HTTPS provider-origin allowlist and
  short-lived opaque server-side sessions. It resolves only already-provisioned
  humans and rechecks their revocation generation on each request. A separate
  team handler exposes scoped workspace/task summaries and inert synthetic scope
  proposal and two-person decision routes; it has no fallback to the legacy API
  and checks membership and generation in the corresponding database operation.
  Its constructor binds authentication and scoped queries to the same identity
  store, avoiding principal-ID collisions across unrelated databases. Neither
  component is mounted by the current server. It does not provide task
  execution, secrets, evidence, executable authorization, a frontend,
  provider-side revocation, or tenant isolation from the shared legacy process.
  Sessions are in memory and do not survive restart. Per-client login rate limits,
  provider configuration, independent deployment and security review remain. The
  verifier also rejects ambiguous or case-variant reserved JWT keys before
  signature verification. No real provider has been configured or contacted.
- `AuthorizeWorkspaceAction` checks the verified identity generation, current
  membership and a directly assigned agent or task for a narrow set of CRUD actions. Scheduling/execution, evidence,
  secrets, tool/MCP calls, approval decisions and protected detection changes deny
  by default. It is not connected to the legacy API or runtime and is not sufficient
  on its own: an eventual protected operation must authenticate its caller and
  combine resource verification and authorization with the operation transaction.
- Goal decomposition now honors catalog bindings for `add_task_scope`. Newly seeded
  catalogs include the goals binding; an existing catalog is not automatically
  changed, so an operator must explicitly add that binding to retain automatic
  goal-stage scope extraction. Planner scope tools and existing graph data remain.
  Decide and test the migration of existing customized bindings before rollout.
  Reseeding does not overwrite customized descriptions, schemas, enabled flags,
  or bindings. Valid legacy skill metadata forms remain supported; malformed YAML,
  invalid MCP lists, duplicate skill names, and missing assigned skills now stop
  assembly rather than silently dropping gating metadata.
- Standalone MCP cache discovery requires an explicit legacy-authenticated HTTP
  add/refresh or status request; startup no longer contacts enabled MCPs just to
  populate the cache. An explicit refresh of a disabled legacy entry remains
  available. Existing cached tool metadata is retained; a new installation with
  no cached tools needs an explicit refresh to populate its tool list. Restored
  legacy tasks may still start MCP clients. The shared JWT cannot establish a human principal;
  direct legacy ScopeSentry sync and agent runtime MCP calls remain outside team
  isolation, and a later configuration change cannot interrupt an active client.
  No scoped team access is activated.
- A synthetic scope proposal stores exact JSON bytes and their hash; a distinct
  active human approver may append an approval, and an authorized human may append
  a revocation. The read path rechecks memberships, task assignment, time and hash.
  Proposal, approval and read paths reject duplicate JSON keys, invalid UTF-8,
  unpaired surrogate escapes and excessive nesting, without rewriting the approved
  bytes. Proposal, approval and read also require a versioned manifest with exact
  private IPv4 addresses, TCP ports and named methods; DNS, ranges, public IPs,
  IPv6, wildcards and unknown fields are denied. Existing documents outside this
  schema are preserved but cannot be newly approved or returned by that lookup.
  An inactive policy compiler checks the approval digest and every approved
  endpoint/method against a separately supplied inventory and rejects an expansion. A private address or a
  label does not establish a target is synthetic. The caller must bind inventory
  to the same tenant and workspace from an independently administered source and
  recheck approval, expiration and revocation at each operation. Signatures,
  independent storage/administration and egress enforcement are not implemented.
  DB owners can bypass the append-only triggers; no proposal, approval or compiled
  in-process policy authorizes a network action.
- Scope proposals, approvals and scoped trigger bindings now refer to the exact
  membership grant that created them. A revoked grant cannot be restored or edited;
  a new grant does not revive old approvals or bindings. Migration 0008 prevents
  ordinary reassignment of a principal identity and increments its authentication
  generation on disable; old sessions and grants do not revive on re-enable. New
  grants require an enabled principal and serialize with a concurrent disable.
  Older grants without a recorded generation remain unbound. Re-enabling a disabled
  tenant, team or workspace can still restore access if its grant was not revoked.
  The inactive membership, action, scope-decision and trigger-query helpers now
  require the authenticated principal generation and check it in their SQL;
  callers must derive it from verified authentication, never request or event data.
  Migration 0009 also prevents ordinary in-place team/workspace ownership
  changes, erasure or transfer of assignments, deletion of identity/grant
  history, and deletion or reassignment of a scoped trigger binding. Disabling a
  trigger binding remains possible; a new grant needs a new binding on a new
  trigger. No audited ownership-transfer procedure exists yet. Inserts and the
  shared legacy process still require separate role restrictions. A DB owner can
  bypass these triggers; active-run revocation and independent administration
  remain incomplete.
  Migration 0007 preserves older unbound records but does not infer their grants;
  they remain unavailable to the new lookup until handled by an approved process.
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

The owner approved the design direction on 2026-11-16: use an existing OIDC
provider, one nonproduction VM with separate per-team execution and synthetic
credentials, and independently controlled evidence with audited, redacted sharing.
This is not authorization to provision access, deploy, activate agents or run a
pilot. Concrete inputs and separate operational approvals still required:

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
and revocation records. `0007_scope_membership_bindings.sql` adds nullable grant
references and makes grant fields and revocation immutable. It leaves earlier
records unbound rather than inferring ownership; review and recreate any needed
proposals or bindings through an authorized process. `0008_immutable_principal_identity.sql`
rejects in-place identity reassignment, advances a revocation generation on
disable and leaves existing grants without an inferred generation. New grants
require an enabled principal and serialize with disablement. Old grants must be
explicitly reviewed, revoked and recreated before use.
`0009_immutable_team_ownership.sql` preserves existing ownership while rejecting
ordinary team/workspace reassignment, deletion of identity and grant history,
assignment movement, and removal or reassignment of trigger bindings. A disabled
trigger can be replaced by a separately authorized new trigger; transfers need a
future independently controlled procedure. These migrations add no live bindings
or scopes during migration.
On a disposable copy, verify the pre-migration backup, record its checksum and the
applied migration checksums, upgrade, check legacy evidence/graphs, and run the
negative membership and authorization suite before enabling any future feature.
No migration makes old shared-password sessions trustworthy. Previously stored
scope bytes are not rewritten; version-1 validation denies incompatible earlier
scope documents. An authorized operator must submit and obtain independent approval
for a new document after reviewing target ownership and fixture inventory.

The separate, unmounted team handler offers the following scoped API operations.
All POSTs require an authenticated human session and the exact configured Origin;
unauthorized and missing records use the same generic denial. These endpoints do
not dispatch work or configure a network:

| Operation | Purpose |
| --- | --- |
| `POST /team/api/workspaces/{workspace}/tasks/{task}/scope-proposals` | An operator submits `valid_from`, `valid_until` and the version-1 document. |
| `GET /team/api/workspaces/{workspace}/scope-proposals/{proposal}` | The requester or a distinct workspace approver receives the exact stored bytes and headers containing task, requester, time window, document digest and decision digest. |
| `POST /team/api/workspaces/{workspace}/scope-proposals/{proposal}/approve` | A distinct approver submits `decision_sha256`; the transaction verifies the displayed decision context before recording it. |
| `POST /team/api/workspaces/{workspace}/scope-proposals/{proposal}/revoke` | A workspace approver appends a reason and revocation. |

The domain-separated decision digest binds the proposal, workspace, task,
requester, validity window and document digest. It is a comparison value, not a
signature or independent evidence custody. A privileged database owner can bypass
the current triggers; future execution must recheck revocation and independent
inventory at the point of use. Provisioned IdP governance must ensure two subjects
represent distinct people; separate subject strings alone cannot prove that.

A version-1 fixture document has the following shape. Each method is separately
allowed per endpoint; this is not permission to run it:

```json
{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["tcp.connect","http.request"]}]}
```

The parser currently recognizes `tcp.connect`, `http.request`, and
`browser.navigate`; a scanner, DNS, UDP, IPv6, raw-packet or other capability
needs an explicit design and independent enforcement before it can be admitted.
Existing legacy execution has not been changed by this inactive schema.

For a rollback rehearsal, stop admission and drain/terminate isolated leases, export
and preserve all new membership/evidence/audit records, and verify backup integrity.
Use a rollback build that retains the exact embedded bytes/checksums of all applied
migrations 0004–0009 but disables the new feature; an older binary missing any
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

- After migration 0007, targeted PostgreSQL tests passed under `go test -race`
  for unbound-record upgrade, membership revocation/regrant, scope approval and
  scoped-trigger filtering. A 30-second parser fuzz run passed with 41,138 inputs;
  `go build -p 2 ./...` and `go vet -p 2 ./...` also passed. An initial full
  suite inherited the workspace HTTP proxy: two WebFetch dialer fixtures failed
  because the target guard denied the proxy address. A clean-environment rerun
  is required; the guard was not relaxed.
- After the strict skill and standalone-discovery changes, `go build -p 2 ./...`,
  `go vet -p 2 ./...`, and `go test -p 1 -count=1 -timeout 180s ./...` passed.
  The test suite used a fresh synthetic PostgreSQL database on loopback. The CI
  package list also passed against a separate fresh database:

  ```sh
  go test -race -p 1 -count=1 -timeout 180s ./agent ./cmd/artex ./config ./db \
    ./evidence ./guard ./intercept ./llmpool ./llmrec ./mcphttp ./notify \
    ./server ./sidequestion ./traffic
  ```

  Existing test skips remain; these results do not establish team isolation.
- Focused `go test -race -p 1 -count=1 -timeout 120s ./db ./server -run ...`
  passed on synthetic PostgreSQL and loopback-only MCP fixtures after the strict
  skill and standalone-discovery changes. Tests cover valid custom skill formats,
  malformed metadata before a connection, gated MCP unlock, explicit legacy
  creation/refresh, policy-store failure, cancellation, and preservation of custom
  catalog settings. The startup cache-discovery removal is intentional; it does
  not disable explicit refresh or existing cached metadata. These checks do not
  prove identity, credential, process or network isolation.
- After the visibility-error change, `go test -p 1 -count=1 -timeout 180s
  ./...` passed against a fresh synthetic PostgreSQL cluster. The first run exposed
  fixtures using a closed visibility store, missing shipped skills, and a temporary
  skill binding whose cleanup ran after its DB closed; the fixtures now use a live
  store and clean up in order. The complete `go test -race -p 1 -count=1
  -timeout 180s ./agent ./server` passed on another fresh fixture, as did
  `go vet -p 2 ./agent ./server` and a Go build. Those earlier checks did not
  validate malformed skill metadata or establish team isolation.
- After migration 0009, `go build -p 2 ./...`, `go vet -p 2 ./...`,
  `go test -p 1 -count=1 -timeout 240s ./...`, and
  `go test -race -p 1 -count=1 -timeout 240s ./db ./server` passed using fresh
  synthetic PostgreSQL databases. The 0008-to-0009 upgrade preserved existing
  assignments and tested denied reassignment, deletion and legacy-trigger escape;
  these triggers are not protection from a database owner.
- After adding the unmounted two-person scope routes and binding the OIDC
  resolver to the same database as the handler, `go build -p 2 ./...`,
  `go vet -p 2 ./...`, `go test -p 1 -count=1 -timeout 240s ./...`, and
  `go test -race -p 1 -count=1 -timeout 240s ./db ./server` passed on fresh
  synthetic PostgreSQL databases. A fake TLS IdP exercised two distinct users,
  exact proposal review, decision replay, wrong workspace, self-approval,
  revocation and stale-session denial. These tests do not activate an executor.
- After the exact-target and generation-check changes, `go build -p 2 ./...`,
  `go vet -p 2 ./...`, `go test -p 1 -count=1 -timeout 240s ./...`, and
  `go test -race -p 1 -count=1 -timeout 240s ./db ./server
  ./security/syntheticpolicy` passed on fresh synthetic PostgreSQL fixtures.
  A 30-second inventory-intersection fuzz run passed with 734,512 executions.
  The new disposable Docker hardening fixture passed `bash -n` and denied an
  invocation without the disposable-host acknowledgement; its real Docker run
  is recorded in CI. It is not a team runner, and does not test team egress,
  browser/scanner parity, active-run interruption, or independent custody.
- After the isolated OIDC and read-only team handler changes, `go build -p 2
  ./...`, `go vet -p 2 ./...`, `go test -p 1 -count=1 -timeout 240s ./...`,
  and the CI package list with `go test -race -p 1 -count=1 -timeout 420s`
  passed using fresh loopback-only synthetic PostgreSQL databases and a fake TLS
  identity provider. The signed-token, callback, session, cross-tenant and
  upgrade-quarantine regressions passed. A subsequent membership issuance fix was
  tested separately against PostgreSQL; its final full-suite results are recorded
  in the PR. Existing skips remain, and no real IdP or isolated executor was used.
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
