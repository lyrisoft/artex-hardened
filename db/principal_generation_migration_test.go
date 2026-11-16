package db

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPrincipalGenerationMigrationQuarantinesExistingGrants(t *testing.T) {
	dsn := scratchDSN(t, "principal_generation_upgrade")
	old := fstest.MapFS{}
	for _, name := range []string{
		llmRecordsMigration, llmUsageMigration, "0003_task_scope_icp_index.sql", "0004_team_foundation.sql",
		"0005_scoped_trigger_bindings.sql", "0006_synthetic_scope_records.sql", "0007_scope_membership_bindings.sql",
	} {
		content, err := fs.ReadFile(migrationsFS(), name)
		if err != nil {
			t.Fatal(err)
		}
		old[name] = &fstest.MapFile{Data: content}
	}
	d, err := openWithMigrations(dsn, old)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id := func(query string, args ...any) int64 {
		t.Helper()
		var value int64
		if err := d.QueryRow(query, args...).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	tenant := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture',true) RETURNING id`)
	team := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','fixture',true) RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'fixture',true) RETURNING id`, tenant, team)
	principal := id(`INSERT INTO security_principals(issuer,subject,kind,enabled) VALUES ('fixture','alice','human',true) RETURNING id`)
	grant := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, team, principal)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var epoch sql.NullInt64
	if err := d.QueryRow(`SELECT principal_auth_epoch FROM security_team_memberships WHERE id=$1`, grant).Scan(&epoch); err != nil || epoch.Valid {
		t.Fatalf("prior grant generation was inferred: epoch=%+v err=%v", epoch, err)
	}
	if got, err := d.ResolveWorkspaceMembership(context.Background(), principal, 1, workspace); got != nil || !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("old grant was authorized: %+v err=%v", got, err)
	}
	if _, err := d.Exec(`UPDATE security_team_memberships SET principal_auth_epoch=1 WHERE id=$1`, grant); err == nil {
		t.Fatal("old grant was rebound by update")
	}
	if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, grant); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, team, principal); err != nil {
		t.Fatal(err)
	}
	if got, err := d.ResolveWorkspaceMembership(context.Background(), principal, 1, workspace); got == nil || err != nil {
		t.Fatalf("explicit new grant unavailable: %+v err=%v", got, err)
	}
}

// A grant and a disable cannot pass each other and accidentally produce a
// membership bound to the post-disable generation while the principal is off.
func TestMembershipIssuanceSerializesWithPrincipalDisable(t *testing.T) {
	d, err := Open(scratchDSN(t, "membership_disable_lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var tenant, team, workspace, principal int64
	if err := d.QueryRow(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture',true) RETURNING id`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','fixture',true) RETURNING id`, tenant).Scan(&team); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'fixture',true) RETURNING id`, tenant, team).Scan(&workspace); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO security_principals(issuer,subject,kind,enabled) VALUES ('fixture','alice','human',true) RETURNING id`).Scan(&principal); err != nil {
		t.Fatal(err)
	}

	grantTx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer grantTx.Rollback()
	if _, err := grantTx.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, team, principal); err != nil {
		t.Fatal(err)
	}
	disableTx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer disableTx.Rollback()
	if _, err := disableTx.Exec(`SET LOCAL lock_timeout='250ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = disableTx.Exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, principal)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
		t.Fatalf("disable did not wait for in-flight grant: %v", err)
	}
	if err := disableTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := grantTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE team_id=$1 AND principal_id=$2`, team, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, team, principal); err == nil {
		t.Fatal("grant issued while principal disabled")
	}
	if _, err := d.Exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, principal); err != nil {
		t.Fatal(err)
	}
	if got, err := d.ResolveWorkspaceMembership(context.Background(), principal, 2, workspace); got != nil || !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("disable/re-enable restored a grant: %+v err=%v", got, err)
	}
}
