package db

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

// The migration is inert: old tasks and agents remain unassigned and no team or
// principal is automatically enabled. The API and runtime do not yet enforce
// these tables; they must not be presented as an isolation boundary.
func TestTeamFoundationMigration(t *testing.T) {
	dsn := scratchDSN(t, "team_foundation")
	old := fstest.MapFS{}
	for _, name := range []string{llmRecordsMigration, llmUsageMigration, "0003_task_scope_icp_index.sql"} {
		content, err := fs.ReadFile(migrationsFS(), name)
		if err != nil {
			t.Fatal(err)
		}
		old[name] = &fstest.MapFile{Data: content}
	}
	d, err := openWithMigrations(dsn, old)
	if err != nil {
		t.Fatalf("open pre-foundation database: %v", err)
	}
	legacy, err := d.CreateTask("synthetic legacy task", "preserve evidence", nil, 0, 300)
	if err != nil {
		t.Fatalf("create legacy task: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d, err = Open(dsn)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer d.Close()
	kept, err := d.GetTask(legacy.ID)
	if err != nil || kept == nil || kept.Description != legacy.Description || kept.ExplorationID != legacy.ExplorationID {
		t.Fatalf("legacy task changed: got=%+v err=%v", kept, err)
	}
	for _, table := range []string{"security_tenants", "security_principals", "security_teams", "security_team_memberships", "security_workspaces", "security_workspace_tasks", "security_workspace_agents"} {
		var count int
		if err := d.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s must be empty after upgrade: count=%d err=%v", table, count, err)
		}
	}

	wantSpecialists := map[string]string{
		"red_lead": "red", "red_api_security": "red", "red_cloud_security": "red",
		"blue_lead": "blue", "blue_detection_analyst": "blue", "blue_incident_analyst": "blue",
		"purple_coordinator": "purple", "purple_retester": "purple",
	}
	rows, err := d.Query(`SELECT key, team_kind FROM security_specialist_templates`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key, kind string
		if err := rows.Scan(&key, &kind); err != nil {
			t.Fatal(err)
		}
		if wantSpecialists[key] != kind {
			t.Errorf("unexpected specialist %q team %q", key, kind)
		}
		delete(wantSpecialists, key)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if len(wantSpecialists) != 0 {
		t.Errorf("missing specialists: %v", wantSpecialists)
	}
	var productCount int
	if err := d.QueryRow(`SELECT count(*) FROM security_engagement_templates WHERE key IN ('sentinel','verify','maiguard_id')`).Scan(&productCount); err != nil || productCount != 3 {
		t.Fatalf("product templates = %d, err=%v", productCount, err)
	}

	var tenantA, tenantB, principal, red, workspace int64
	var enabled bool
	if err := d.QueryRow(`INSERT INTO security_tenants(name) VALUES ('fixture A') RETURNING id, enabled`).Scan(&tenantA, &enabled); err != nil || enabled {
		t.Fatalf("new tenant must be disabled: enabled=%v err=%v", enabled, err)
	}
	if err := d.QueryRow(`INSERT INTO security_tenants(name) VALUES ('fixture B') RETURNING id`).Scan(&tenantB); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`INSERT INTO security_principals(kind,issuer,subject) VALUES ('human','fixture','person') RETURNING id, enabled`).Scan(&principal, &enabled); err != nil || enabled {
		t.Fatalf("new principal must be disabled: enabled=%v err=%v", enabled, err)
	}
	if err := d.QueryRow(`INSERT INTO security_teams(tenant_id,kind,name) VALUES ($1,'red','fixture red') RETURNING id, enabled`, tenantA).Scan(&red, &enabled); err != nil || enabled {
		t.Fatalf("new team must be disabled: enabled=%v err=%v", enabled, err)
	}
	if _, err := d.Exec(`INSERT INTO security_workspaces(tenant_id,team_id,name) VALUES ($1,$2,'wrong tenant')`, tenantB, red); err == nil {
		t.Fatal("workspace accepted a team from another tenant")
	}
	if err := d.QueryRow(`INSERT INTO security_workspaces(tenant_id,team_id,name) VALUES ($1,$2,'fixture') RETURNING id, enabled`, tenantA, red).Scan(&workspace, &enabled); err != nil || enabled {
		t.Fatalf("new workspace must be disabled: enabled=%v err=%v", enabled, err)
	}
	if _, err := d.Exec(`INSERT INTO security_teams(tenant_id,kind,name) VALUES ($1,'unknown','bad')`, tenantA); err == nil {
		t.Fatal("unknown team kind accepted")
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'viewer')`, red, principal); err == nil {
		t.Fatal("grant issued to a disabled principal")
	}
	if _, err := d.Exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'superuser')`, red, principal); err == nil {
		t.Fatal("unknown membership role accepted")
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role,valid_from) VALUES ($1,$2,'viewer', now() + interval '1 day')`, red, principal); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, red, principal); err == nil {
		t.Fatal("duplicate unrevoked membership accepted")
	}
	if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE team_id=$1 AND principal_id=$2`, red, principal); err != nil {
		t.Fatalf("future membership must be revocable immediately: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, red, principal); err != nil {
		t.Fatalf("regrant after revocation: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, workspace, legacy.ID); err != nil {
		t.Fatalf("assign synthetic task: %v", err)
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dsn)
	if err != nil {
		t.Fatalf("reopen after migration: %v", err)
	}
	defer d.Close()
	var memberships, assignments int
	if err := d.QueryRow(`SELECT count(*) FROM security_team_memberships WHERE team_id=$1`, red).Scan(&memberships); err != nil || memberships != 2 {
		t.Fatalf("membership history after reopen = %d, err=%v", memberships, err)
	}
	if err := d.QueryRow(`SELECT count(*) FROM security_workspace_tasks WHERE workspace_id=$1 AND task_id=$2`, workspace, legacy.ID).Scan(&assignments); err != nil || assignments != 1 {
		t.Fatalf("task assignment after reopen = %d, err=%v", assignments, err)
	}
}
