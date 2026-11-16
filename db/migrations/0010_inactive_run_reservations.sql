-- Inactive fixture reservation ledger only: it does not start a runner, prove
-- inventory provenance, interrupt a process, or authorize network traffic.
-- A single live row enforces one reservation on this database; an expired or
-- orphaned row remains live until an independently trusted supervisor confirms
-- that the process has stopped. DB-owner access can bypass these triggers.
CREATE TABLE security_run_reservations (
    id BIGSERIAL PRIMARY KEY,
    nonce BYTEA NOT NULL UNIQUE CHECK (octet_length(nonce)=32),
    workspace_id BIGINT NOT NULL REFERENCES security_workspaces(id) ON DELETE RESTRICT,
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    scope_proposal_id BIGINT NOT NULL REFERENCES security_scope_proposals(id) ON DELETE RESTRICT,
    requester_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    requester_membership_id BIGINT NOT NULL REFERENCES security_team_memberships(id) ON DELETE RESTRICT,
    executor_id BIGINT NOT NULL REFERENCES security_principals(id) ON DELETE RESTRICT,
    executor_membership_id BIGINT NOT NULL REFERENCES security_team_memberships(id) ON DELETE RESTRICT,
    decision_sha256 BYTEA NOT NULL CHECK (octet_length(decision_sha256)=32),
    inventory_sha256 BYTEA NOT NULL CHECK (octet_length(inventory_sha256)=32),
    valid_until TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','running','stopping','stopped')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at TIMESTAMPTZ,
    CHECK ((state='stopped') = (stopped_at IS NOT NULL)),
    CHECK (valid_until > created_at)
);
CREATE UNIQUE INDEX security_one_live_run_reservation ON security_run_reservations ((true))
    WHERE state IN ('reserved','running','stopping');

CREATE FUNCTION security_guard_run_reservation_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.state <> 'reserved' OR NEW.stopped_at IS NOT NULL THEN
        RAISE EXCEPTION 'run reservations start in reserved state';
    END IF;
    NEW.created_at := statement_timestamp();
    IF NEW.valid_until <= NEW.created_at THEN
        RAISE EXCEPTION 'run reservation is already expired';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_run_reservation_insert_guard BEFORE INSERT ON security_run_reservations
    FOR EACH ROW EXECUTE FUNCTION security_guard_run_reservation_insert();

CREATE FUNCTION security_guard_run_reservation_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.nonce, NEW.workspace_id, NEW.task_id, NEW.scope_proposal_id,
           NEW.requester_id, NEW.requester_membership_id, NEW.executor_id, NEW.executor_membership_id,
           NEW.decision_sha256, NEW.inventory_sha256, NEW.valid_until, NEW.created_at, NEW.stopped_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.nonce, OLD.workspace_id, OLD.task_id, OLD.scope_proposal_id,
           OLD.requester_id, OLD.requester_membership_id, OLD.executor_id, OLD.executor_membership_id,
           OLD.decision_sha256, OLD.inventory_sha256, OLD.valid_until, OLD.created_at, OLD.stopped_at) THEN
        RAISE EXCEPTION 'run reservation context cannot be changed';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT ((OLD.state='reserved' AND NEW.state IN ('running','stopping')) OR
                (OLD.state='running' AND NEW.state='stopping') OR
                (OLD.state='stopping' AND NEW.state='stopped')) THEN
            RAISE EXCEPTION 'invalid run reservation state transition';
        END IF;
        IF NEW.state='running' THEN
            IF OLD.valid_until <= statement_timestamp() OR NOT EXISTS (
                SELECT 1 FROM security_scope_proposals proposal
                JOIN security_scope_approvals approval ON approval.proposal_id=proposal.id AND approval.approver_id<>proposal.requester_id
                JOIN security_workspaces w ON w.id=proposal.workspace_id AND w.enabled
                JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.kind='red' AND team.enabled
                JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
                JOIN security_workspace_tasks assigned ON assigned.workspace_id=w.id AND assigned.task_id=proposal.task_id
                JOIN tasks task ON task.id=assigned.task_id AND task.deleted_at IS NULL
                JOIN security_principals requester ON requester.id=proposal.requester_id AND requester.kind='human' AND requester.enabled
                JOIN security_team_memberships requester_m ON requester_m.id=proposal.requester_membership_id AND requester_m.principal_id=requester.id
                 AND requester_m.team_id=team.id AND requester_m.principal_auth_epoch=requester.auth_epoch AND requester_m.role IN ('operator','manager')
                 AND requester_m.revoked_at IS NULL AND requester_m.valid_from<=statement_timestamp() AND (requester_m.expires_at IS NULL OR requester_m.expires_at>statement_timestamp())
                JOIN security_principals approver ON approver.id=approval.approver_id AND approver.kind='human' AND approver.enabled
                JOIN security_team_memberships approver_m ON approver_m.id=approval.approver_membership_id AND approver_m.principal_id=approver.id
                 AND approver_m.team_id=team.id AND approver_m.principal_auth_epoch=approver.auth_epoch AND approver_m.role='approver'
                 AND approver_m.revoked_at IS NULL AND approver_m.valid_from<=statement_timestamp() AND (approver_m.expires_at IS NULL OR approver_m.expires_at>statement_timestamp())
                JOIN security_principals executor ON executor.id=OLD.executor_id AND executor.kind='service' AND executor.enabled
                JOIN security_team_memberships executor_m ON executor_m.id=OLD.executor_membership_id AND executor_m.principal_id=executor.id
                 AND executor_m.team_id=team.id AND executor_m.principal_auth_epoch=executor.auth_epoch AND executor_m.role IN ('operator','manager')
                 AND executor_m.revoked_at IS NULL AND executor_m.valid_from<=statement_timestamp() AND (executor_m.expires_at IS NULL OR executor_m.expires_at>statement_timestamp())
                WHERE proposal.id=OLD.scope_proposal_id AND w.id=OLD.workspace_id AND task.id=OLD.task_id
                 AND requester.id=OLD.requester_id AND requester_m.id=OLD.requester_membership_id
                 AND proposal.environment='synthetic' AND proposal.valid_from<=statement_timestamp()
                 AND proposal.valid_until=OLD.valid_until AND proposal.valid_until>statement_timestamp()
                 AND NOT EXISTS (SELECT 1 FROM security_scope_revocations rev WHERE rev.proposal_id=proposal.id)
            ) THEN
                RAISE EXCEPTION 'run reservation is no longer eligible to start';
            END IF;
        END IF;
        IF NEW.state='stopped' THEN
            NEW.stopped_at := statement_timestamp();
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_run_reservation_update_guard BEFORE UPDATE ON security_run_reservations
    FOR EACH ROW EXECUTE FUNCTION security_guard_run_reservation_update();
CREATE TRIGGER security_run_reservation_no_delete BEFORE DELETE OR TRUNCATE ON security_run_reservations
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
