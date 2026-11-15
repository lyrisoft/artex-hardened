-- Inert records for a future independently administered approval service. A
-- document being present does not authorize any target, tool or network request.
-- The application/DB owner can disable triggers; an independent role/store and
-- external audit are required before these records can be a security boundary.
CREATE TABLE security_scope_proposals (
    id BIGSERIAL PRIMARY KEY,
    workspace_id BIGINT NOT NULL REFERENCES security_workspaces(id) ON DELETE RESTRICT,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    requester_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    environment TEXT NOT NULL DEFAULT 'synthetic' CHECK (environment='synthetic'),
    document BYTEA NOT NULL CHECK (octet_length(document) BETWEEN 2 AND 65536),
    document_sha256 BYTEA NOT NULL CHECK (octet_length(document_sha256)=32),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL CHECK (valid_until > valid_from),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE security_scope_approvals (
    proposal_id BIGINT PRIMARY KEY REFERENCES security_scope_proposals(id) ON DELETE RESTRICT,
    approver_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE security_scope_revocations (
    proposal_id BIGINT PRIMARY KEY REFERENCES security_scope_proposals(id) ON DELETE RESTRICT,
    revoker_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK (btrim(reason) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE FUNCTION security_reject_scope_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'scope records are append-only'; END;
$$;
CREATE TRIGGER scope_proposals_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON security_scope_proposals
FOR EACH STATEMENT EXECUTE FUNCTION security_reject_scope_mutation();
CREATE TRIGGER scope_approvals_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON security_scope_approvals
FOR EACH STATEMENT EXECUTE FUNCTION security_reject_scope_mutation();
CREATE TRIGGER scope_revocations_no_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON security_scope_revocations
FOR EACH STATEMENT EXECUTE FUNCTION security_reject_scope_mutation();
