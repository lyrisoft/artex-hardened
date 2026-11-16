-- Trigger functions must resolve their own tables in the schema where this
-- migration is installed. A session with TEMP privilege can otherwise shadow
-- unqualified table names and bypass the inactive admission barrier or the
-- principal-generation check. pg_temp is explicitly last: if it is omitted,
-- PostgreSQL implicitly searches the session's temporary schema first.
--
-- This does not restrict direct SQL, schema creation, DB-owner bypass, or the
-- unmounted Go queries. Separate, least-privilege database roles remain required.
DO $$
DECLARE
    target_schema TEXT;
    function_name TEXT;
BEGIN
    SELECT namespace.nspname INTO target_schema
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace
    WHERE relation.oid=pg_catalog.to_regclass('security_run_reservations');
    IF target_schema IS NULL OR target_schema LIKE 'pg_temp_%' THEN
        RAISE EXCEPTION 'security schema unavailable';
    END IF;
    FOREACH function_name IN ARRAY ARRAY[
        'security_reject_scope_mutation',
        'security_guard_membership_update',
        'security_guard_principal_identity_update',
        'security_bind_membership_principal_epoch',
        'security_guard_tenant_identity_update',
        'security_guard_team_identity_update',
        'security_guard_workspace_identity_update',
        'security_guard_trigger_binding_update',
        'security_reject_foundation_deletion',
        'security_guard_run_reservation_insert',
        'security_guard_run_reservation_update',
        'security_guard_admission_epoch_update',
        'security_advance_admission_epoch'
    ] LOOP
        IF pg_catalog.to_regprocedure(pg_catalog.format('%I.%I()', target_schema,function_name)) IS NULL THEN
            RAISE EXCEPTION 'required security trigger function unavailable';
        END IF;
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%I() SET search_path TO pg_catalog, %I, pg_temp',
            target_schema,function_name,target_schema
        );
    END LOOP;
END;
$$;
