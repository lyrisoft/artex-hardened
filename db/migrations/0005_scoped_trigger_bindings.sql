-- A proposed owner for a scoped trigger is inert by default. The legacy global
-- scheduler must exclude every bound trigger, even while it is disabled. No
-- runtime is activated by this migration.
CREATE TABLE security_scoped_trigger_bindings (
    trigger_id BIGINT PRIMARY KEY REFERENCES agent_triggers(id) ON DELETE RESTRICT,
    workspace_id BIGINT NOT NULL REFERENCES security_workspaces(id) ON DELETE RESTRICT,
    principal_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_scoped_trigger_bindings_owner
    ON security_scoped_trigger_bindings(principal_id, workspace_id);
