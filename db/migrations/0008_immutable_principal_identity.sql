-- Existing memberships have no recorded principal generation. Leave them
-- unbound rather than assuming whether a disabled identity had been revoked.
ALTER TABLE security_principals ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0);
ALTER TABLE security_team_memberships ADD COLUMN principal_auth_epoch BIGINT;

-- Principal identifiers are identity bindings, not editable display fields.
-- Replacing issuer, subject or kind on an existing principal could transfer its
-- memberships and approvals to a different verified identity. Create a distinct
-- principal and explicitly grant access instead. A database owner can bypass
-- this trigger; independent administration remains necessary before activation.
CREATE FUNCTION security_guard_principal_identity_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.kind, NEW.issuer, NEW.subject, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.kind, OLD.issuer, OLD.subject, OLD.created_at) THEN
        RAISE EXCEPTION 'principal identity cannot be reassigned';
    END IF;
    IF NEW.auth_epoch IS DISTINCT FROM OLD.auth_epoch THEN
        RAISE EXCEPTION 'principal authentication generation is managed by the database';
    END IF;
    IF OLD.enabled AND NOT NEW.enabled THEN
        NEW.auth_epoch := OLD.auth_epoch + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_principal_identity_update_guard BEFORE UPDATE ON security_principals
    FOR EACH ROW EXECUTE FUNCTION security_guard_principal_identity_update();

-- New grants bind to an enabled principal under a row lock. This serializes
-- issuance with disable: a concurrent disable either invalidates the new grant
-- or wins first and causes issuance to fail. Re-enable never revives old grants.
CREATE FUNCTION security_bind_membership_principal_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_epoch BIGINT;
BEGIN
    SELECT auth_epoch INTO current_epoch FROM security_principals
        WHERE id=NEW.principal_id AND enabled FOR SHARE;
    IF current_epoch IS NULL OR (NEW.principal_auth_epoch IS NOT NULL AND NEW.principal_auth_epoch <> current_epoch) THEN
        RAISE EXCEPTION 'membership principal generation mismatch';
    END IF;
    NEW.principal_auth_epoch := current_epoch;
    RETURN NEW;
END;
$$;
CREATE TRIGGER security_membership_principal_epoch BEFORE INSERT ON security_team_memberships
    FOR EACH ROW EXECUTE FUNCTION security_bind_membership_principal_epoch();

CREATE OR REPLACE FUNCTION security_guard_membership_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id, NEW.team_id, NEW.principal_id, NEW.role, NEW.valid_from, NEW.expires_at, NEW.principal_auth_epoch)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.team_id, OLD.principal_id, OLD.role, OLD.valid_from, OLD.expires_at, OLD.principal_auth_epoch) THEN
        RAISE EXCEPTION 'membership grants cannot be changed; revoke and create a new grant';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'membership revocation cannot be undone or changed';
    END IF;
    RETURN NEW;
END;
$$;
