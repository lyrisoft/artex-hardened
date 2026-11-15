-- Foundation data only. These tables do not enable teams or authorize execution.
-- Existing shared-password data is deliberately not assigned to a team. Runtime
-- isolation and scoped authorization must be implemented before activation.
CREATE TABLE security_tenants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL CHECK (btrim(name) <> ''),
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE security_principals (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('human', 'service')),
    issuer TEXT NOT NULL CHECK (btrim(issuer) <> ''),
    subject TEXT NOT NULL CHECK (btrim(subject) <> ''),
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE security_teams (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES security_tenants(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('red', 'blue', 'purple')),
    name TEXT NOT NULL CHECK (btrim(name) <> ''),
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, tenant_id),
    UNIQUE (tenant_id, kind, name)
);

-- Grant history is retained; revoke an old membership before creating another
-- for the same principal/team. Authorization must also check principal, tenant,
-- team and workspace status, timestamps and the principal's human/service kind.
CREATE TABLE security_team_memberships (
    id BIGSERIAL PRIMARY KEY,
    team_id BIGINT NOT NULL REFERENCES security_teams(id) ON DELETE RESTRICT,
    principal_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'manager', 'approver')),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at IS NULL OR expires_at > valid_from)
);
CREATE UNIQUE INDEX security_team_memberships_unrevoked
    ON security_team_memberships(team_id, principal_id) WHERE revoked_at IS NULL;
CREATE INDEX security_team_memberships_principal
    ON security_team_memberships(principal_id, team_id);

CREATE TABLE security_workspaces (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    team_id BIGINT NOT NULL,
    name TEXT NOT NULL CHECK (btrim(name) <> ''),
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (team_id, tenant_id) REFERENCES security_teams(id, tenant_id) ON DELETE RESTRICT,
    UNIQUE (team_id, name)
);

-- Assignments are empty on upgrade. Do not infer ownership of existing shared
-- agents/tasks, and do not expose these as scoped views before authorization is
-- enforced on every read and execution path.
CREATE TABLE security_workspace_agents (
    workspace_id BIGINT NOT NULL REFERENCES security_workspaces(id) ON DELETE RESTRICT,
    agent_id BIGINT NOT NULL UNIQUE REFERENCES agents(id) ON DELETE RESTRICT,
    PRIMARY KEY (workspace_id, agent_id)
);
CREATE TABLE security_workspace_tasks (
    workspace_id BIGINT NOT NULL REFERENCES security_workspaces(id) ON DELETE RESTRICT,
    task_id BIGINT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE RESTRICT,
    PRIMARY KEY (workspace_id, task_id)
);

-- Catalog entries are inert descriptions. They grant no tools, access, targets,
-- credentials or approvals, and do not create or activate agents or tasks.
CREATE TABLE security_specialist_templates (
    key TEXT PRIMARY KEY,
    team_kind TEXT NOT NULL CHECK (team_kind IN ('red', 'blue', 'purple')),
    name TEXT NOT NULL,
    description TEXT NOT NULL
);
INSERT INTO security_specialist_templates(key, team_kind, name, description) VALUES
    ('red_lead', 'red', 'Red Lead', 'Coordinates authorized synthetic assessments.'),
    ('red_api_security', 'red', 'API Security', 'Examines approved API authorization and security controls.'),
    ('red_cloud_security', 'red', 'Cloud Security', 'Examines approved synthetic cloud configurations.'),
    ('blue_lead', 'blue', 'Blue Lead', 'Coordinates read-only security investigation.'),
    ('blue_detection_analyst', 'blue', 'Detection Analyst', 'Analyzes independently collected defensive observations.'),
    ('blue_incident_analyst', 'blue', 'Incident Analyst', 'Triages evidence-linked incidents without containment authority.'),
    ('purple_coordinator', 'purple', 'Purple Coordinator', 'Coordinates independently approved exercises and evidence review.'),
    ('purple_retester', 'purple', 'Retester', 'Independently verifies remediation within an approved scope.');

CREATE TABLE security_engagement_templates (
    key TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL
);
INSERT INTO security_engagement_templates(key, name, description) VALUES
    ('sentinel', 'Sentinel', 'Synthetic Sentinel assessment; an independently approved target manifest is required.'),
    ('verify', 'Verify', 'Synthetic Verify assessment; an independently approved target manifest is required.'),
    ('maiguard_id', 'MaiGuard ID', 'Synthetic MaiGuard ID assessment; an independently approved target manifest is required.');
