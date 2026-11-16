-- Preserve the identity and ownership of inactive security records. The shared
-- legacy process and a DB owner can bypass triggers; independently restricted
-- roles and a reviewed transfer process are still required before activation.
CREATE FUNCTION security_guard_tenant_identity_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.created_at) IS DISTINCT FROM ROW(OLD.id, OLD.created_at) THEN
        RAISE EXCEPTION 'tenant identity cannot be reassigned';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_tenant_identity_update_guard BEFORE UPDATE ON security_tenants
    FOR EACH ROW EXECUTE FUNCTION security_guard_tenant_identity_update();

CREATE FUNCTION security_guard_team_identity_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.tenant_id, NEW.kind, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id, OLD.tenant_id, OLD.kind, OLD.created_at) THEN
        RAISE EXCEPTION 'team identity and tenant cannot be reassigned';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_team_identity_update_guard BEFORE UPDATE ON security_teams
    FOR EACH ROW EXECUTE FUNCTION security_guard_team_identity_update();

CREATE FUNCTION security_guard_workspace_identity_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.tenant_id, NEW.team_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id, OLD.tenant_id, OLD.team_id, OLD.created_at) THEN
        RAISE EXCEPTION 'workspace identity and team cannot be reassigned';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_workspace_identity_update_guard BEFORE UPDATE ON security_workspaces
    FOR EACH ROW EXECUTE FUNCTION security_guard_workspace_identity_update();

-- Disabling a binding is allowed; changing its trigger, workspace, owner or
-- grant could reactivate legacy dispatch or transfer ownership. Create a new
-- trigger and binding after explicit authorization instead of rewriting it.
CREATE FUNCTION security_guard_trigger_binding_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.trigger_id, NEW.workspace_id, NEW.principal_id, NEW.owner_membership_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.trigger_id, OLD.workspace_id, OLD.principal_id, OLD.owner_membership_id, OLD.created_at) THEN
        RAISE EXCEPTION 'trigger ownership cannot be reassigned';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_trigger_binding_update_guard BEFORE UPDATE ON security_scoped_trigger_bindings
    FOR EACH ROW EXECUTE FUNCTION security_guard_trigger_binding_update();

-- Removing a principal or grant can erase the durable revocation history;
-- removing an assignment can silently transfer a resource to another team;
-- removing a trigger binding can put it back in the global legacy scheduler.
-- Disable/revoke in place and retain ownership. Future transfer/deletion needs
-- a separately controlled, audited design rather than DELETE+INSERT.
CREATE FUNCTION security_reject_foundation_deletion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'security ownership and history cannot be deleted';
END;
$$;
CREATE TRIGGER security_tenants_no_delete BEFORE DELETE OR TRUNCATE ON security_tenants
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_principals_no_delete BEFORE DELETE OR TRUNCATE ON security_principals
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_teams_no_delete BEFORE DELETE OR TRUNCATE ON security_teams
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_memberships_no_delete BEFORE DELETE OR TRUNCATE ON security_team_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_workspaces_no_delete BEFORE DELETE OR TRUNCATE ON security_workspaces
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_workspace_agents_no_reassign BEFORE UPDATE OR DELETE OR TRUNCATE ON security_workspace_agents
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_workspace_tasks_no_reassign BEFORE UPDATE OR DELETE OR TRUNCATE ON security_workspace_tasks
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
CREATE TRIGGER security_scoped_trigger_bindings_no_delete BEFORE DELETE OR TRUNCATE ON security_scoped_trigger_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION security_reject_foundation_deletion();
