-- Inactive serialization for the reservation state machine. This is not an
-- executor, a stop mechanism, or an authorization to access a target. Every
-- security-sensitive database role must be restricted independently; the DB
-- owner can disable these triggers or otherwise bypass their protection.
--
-- An admission and any mutation that can invalidate its eligibility update the
-- same row in the same transaction. At READ COMMITTED the eligibility check in
-- the following trigger sees a preceding committed invalidation. At REPEATABLE
-- READ / SERIALIZABLE a stale transaction fails with a serialization error.
-- A start that wins the row lock can commit before a later revocation; an
-- independent supervisor must stop already-running work when that happens.
CREATE TABLE security_admission_epoch (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0)
);
INSERT INTO security_admission_epoch(singleton) VALUES (true);

CREATE FUNCTION security_guard_admission_epoch_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.generation <> OLD.generation + 1 THEN
        RAISE EXCEPTION 'admission generation may only advance by one';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_admission_epoch_update_guard BEFORE UPDATE ON security_admission_epoch
    FOR EACH ROW EXECUTE FUNCTION security_guard_admission_epoch_update();
CREATE TRIGGER security_admission_epoch_no_delete BEFORE DELETE OR TRUNCATE ON security_admission_epoch
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();

CREATE FUNCTION security_advance_admission_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE security_admission_epoch SET generation=generation+1 WHERE singleton=true;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'admission serialization unavailable';
    END IF;
    RETURN NEW;
END;
$$;

-- PostgreSQL runs same-kind triggers alphabetically, so this barrier precedes
-- security_run_reservation_update_guard and its eligibility query.
CREATE TRIGGER security_admission_barrier_reservation BEFORE UPDATE OF state ON security_run_reservations
    FOR EACH ROW WHEN (OLD.state='reserved' AND NEW.state='running')
    EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_scope_revocation BEFORE INSERT ON security_scope_revocations
    FOR EACH ROW EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_membership BEFORE UPDATE OF revoked_at ON security_team_memberships
    FOR EACH ROW WHEN (OLD.revoked_at IS DISTINCT FROM NEW.revoked_at)
    EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_principal BEFORE UPDATE OF enabled ON security_principals
    FOR EACH ROW WHEN (OLD.enabled IS DISTINCT FROM NEW.enabled)
    EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_workspace BEFORE UPDATE OF enabled ON security_workspaces
    FOR EACH ROW WHEN (OLD.enabled IS DISTINCT FROM NEW.enabled)
    EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_team BEFORE UPDATE OF enabled ON security_teams
    FOR EACH ROW WHEN (OLD.enabled IS DISTINCT FROM NEW.enabled)
    EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_tenant BEFORE UPDATE OF enabled ON security_tenants
    FOR EACH ROW WHEN (OLD.enabled IS DISTINCT FROM NEW.enabled)
    EXECUTE FUNCTION security_advance_admission_epoch();
CREATE TRIGGER security_admission_barrier_task BEFORE UPDATE OF deleted_at ON tasks
    FOR EACH ROW WHEN (OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
    EXECUTE FUNCTION security_advance_admission_epoch();

-- This guard runs after the serialization barrier. Capture fresh database
-- wall-clock time after any lock wait; statement_timestamp() would refer
-- to the beginning of the waiting statement and could admit expired scope
-- or memberships. A future executor must still recheck at launch.
CREATE OR REPLACE FUNCTION security_guard_run_reservation_update() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admission_at TIMESTAMPTZ;
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
            admission_at := clock_timestamp();
            IF OLD.valid_until <= admission_at OR NOT EXISTS (
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
                 AND requester_m.revoked_at IS NULL AND requester_m.valid_from<=admission_at AND (requester_m.expires_at IS NULL OR requester_m.expires_at>admission_at)
                JOIN security_principals approver ON approver.id=approval.approver_id AND approver.kind='human' AND approver.enabled
                JOIN security_team_memberships approver_m ON approver_m.id=approval.approver_membership_id AND approver_m.principal_id=approver.id
                 AND approver_m.team_id=team.id AND approver_m.principal_auth_epoch=approver.auth_epoch AND approver_m.role='approver'
                 AND approver_m.revoked_at IS NULL AND approver_m.valid_from<=admission_at AND (approver_m.expires_at IS NULL OR approver_m.expires_at>admission_at)
                JOIN security_principals executor ON executor.id=OLD.executor_id AND executor.kind='service' AND executor.enabled
                JOIN security_team_memberships executor_m ON executor_m.id=OLD.executor_membership_id AND executor_m.principal_id=executor.id
                 AND executor_m.team_id=team.id AND executor_m.principal_auth_epoch=executor.auth_epoch AND executor_m.role IN ('operator','manager')
                 AND executor_m.revoked_at IS NULL AND executor_m.valid_from<=admission_at AND (executor_m.expires_at IS NULL OR executor_m.expires_at>admission_at)
                WHERE proposal.id=OLD.scope_proposal_id AND w.id=OLD.workspace_id AND task.id=OLD.task_id
                 AND requester.id=OLD.requester_id AND requester_m.id=OLD.requester_membership_id
                 AND proposal.environment='synthetic' AND proposal.valid_from<=admission_at
                 AND proposal.valid_until=OLD.valid_until AND proposal.valid_until>admission_at
                 AND NOT EXISTS (SELECT 1 FROM security_scope_revocations rev WHERE rev.proposal_id=proposal.id)
            ) THEN
                RAISE EXCEPTION 'run reservation is no longer eligible to start';
            END IF;
        END IF;
        IF NEW.state='stopped' THEN
            NEW.stopped_at := clock_timestamp();
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
