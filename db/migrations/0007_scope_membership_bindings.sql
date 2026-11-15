-- Inactive foundations only. Existing proposals, approvals and trigger bindings
-- have no trustworthy recorded membership grant; preserve them unchanged and
-- leave their new bindings NULL so they cannot become authorized automatically.
ALTER TABLE security_scope_proposals
    ADD COLUMN requester_membership_id BIGINT REFERENCES security_team_memberships(id) ON DELETE RESTRICT;
ALTER TABLE security_scope_approvals
    ADD COLUMN approver_membership_id BIGINT REFERENCES security_team_memberships(id) ON DELETE RESTRICT;
ALTER TABLE security_scoped_trigger_bindings
    ADD COLUMN owner_membership_id BIGINT REFERENCES security_team_memberships(id) ON DELETE RESTRICT;

-- Grant changes require revoking this row and creating a new grant. A later
-- grant cannot make an approval or trigger bound to a revoked grant valid again.
-- This is not protection against a DB owner who can disable the trigger.
CREATE FUNCTION security_guard_membership_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.team_id, NEW.principal_id, NEW.role, NEW.valid_from, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.team_id, OLD.principal_id, OLD.role, OLD.valid_from, OLD.expires_at) THEN
        RAISE EXCEPTION 'membership grants cannot be changed; revoke and create a new grant';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'membership revocation cannot be undone or changed';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_membership_update_guard BEFORE UPDATE ON security_team_memberships
    FOR EACH ROW EXECUTE FUNCTION security_guard_membership_update();
