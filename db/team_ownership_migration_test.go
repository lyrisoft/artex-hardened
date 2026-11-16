package db

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
)

// Existing ownership is retained, but ordinary SQL cannot transfer it or erase
// the binding which keeps a scoped trigger out of the legacy global scheduler.
func TestTeamOwnershipMigrationPreservesAndLocksBindings(t *testing.T) {
	dsn := scratchDSN(t, "team_ownership_upgrade")
	old := fstest.MapFS{}
	for _, name := range []string{
		llmRecordsMigration, llmUsageMigration, "0003_task_scope_icp_index.sql", "0004_team_foundation.sql",
		"0005_scoped_trigger_bindings.sql", "0006_synthetic_scope_records.sql", "0007_scope_membership_bindings.sql",
		"0008_immutable_principal_identity.sql",
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
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	tenant := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture',true) RETURNING id`)
	emptyTenant := id(`INSERT INTO security_tenants(name) VALUES ('empty fixture') RETURNING id`)
	red := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','fixture-red',true) RETURNING id`, tenant)
	blue := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','fixture-blue',true) RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'red',true) RETURNING id`, tenant, red)
	other := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'blue',true) RETURNING id`, tenant, blue)
	emptyWorkspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name) VALUES ($1,$2,'empty') RETURNING id`, tenant, red)
	principal := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ('service','fixture','worker',true) RETURNING id`)
	emptyPrincipal := id(`INSERT INTO security_principals(kind,issuer,subject) VALUES ('human','fixture','unused') RETURNING id`)
	grant := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, red, principal)
	agent := id(`INSERT INTO agents(key,name,role,builtin,enabled) VALUES ('ownership_fixture','fixture','assistant',false,true) RETURNING id`)
	task, err := d.CreateTask("synthetic ownership", "fixture", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_agents(workspace_id,agent_id) VALUES ($1,$2)`, workspace, agent)
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, workspace, task.ID)
	trigger, err := d.CreateTrigger(&AgentTrigger{AgentKey: "ownership_fixture", Enabled: true, OnToolCall: true, ToolNames: []string{"scan"}})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_scoped_trigger_bindings(trigger_id,workspace_id,principal_id,owner_membership_id,enabled) VALUES ($1,$2,$3,$4,true)`, trigger.ID, workspace, principal, grant)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if got, err := d.ResolveWorkspaceMembership(context.Background(), principal, 1, workspace); got == nil || err != nil {
		t.Fatalf("existing membership was changed by upgrade: %+v err=%v", got, err)
	}
	for _, tc := range []struct {
		query string
		args  []any
	}{
		{`UPDATE security_tenants SET created_at=created_at+interval '1 second' WHERE id=$1`, []any{tenant}},
		{`UPDATE security_teams SET kind='purple' WHERE id=$1`, []any{red}},
		{`UPDATE security_teams SET tenant_id=$2 WHERE id=$1`, []any{red, emptyTenant}},
		{`UPDATE security_workspaces SET team_id=$2 WHERE id=$1`, []any{workspace, blue}},
		{`UPDATE security_workspace_tasks SET workspace_id=$2 WHERE workspace_id=$1`, []any{workspace, other}},
		{`UPDATE security_workspace_agents SET workspace_id=$2 WHERE workspace_id=$1`, []any{workspace, other}},
		{`DELETE FROM security_workspace_tasks WHERE workspace_id=$1`, []any{workspace}},
		{`DELETE FROM security_workspace_agents WHERE workspace_id=$1`, []any{workspace}},
		{`DELETE FROM security_team_memberships WHERE id=$1`, []any{grant}},
		{`DELETE FROM security_principals WHERE id=$1`, []any{emptyPrincipal}},
		{`DELETE FROM security_tenants WHERE id=$1`, []any{emptyTenant}},
		{`DELETE FROM security_workspaces WHERE id=$1`, []any{emptyWorkspace}},
		{`DELETE FROM security_scoped_trigger_bindings WHERE trigger_id=$1`, []any{trigger.ID}},
		{`UPDATE security_scoped_trigger_bindings SET workspace_id=$2 WHERE trigger_id=$1`, []any{trigger.ID, other}},
		{`TRUNCATE security_workspace_tasks`, nil},
	} {
		if _, err := d.Exec(tc.query, tc.args...); err == nil {
			t.Fatalf("ownership mutation allowed: %s", tc.query)
		}
	}
	// Routine disable and revocation retain history and still work.
	exec(`UPDATE security_scoped_trigger_bindings SET enabled=false WHERE trigger_id=$1`, trigger.ID)
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, grant)
	exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, principal)
	if got, err := d.ResolveWorkspaceMembership(context.Background(), principal, 1, workspace); got != nil || !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("disabled or revoked membership authorized: %+v err=%v", got, err)
	}
	legacy, err := d.ListEnabledTriggers()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range legacy {
		if item.ID == trigger.ID {
			t.Fatal("retained scoped trigger escaped to the legacy scheduler")
		}
	}
	var taskWorkspace, agentWorkspace, boundWorkspace int64
	if err := d.QueryRow(`SELECT workspace_id FROM security_workspace_tasks WHERE task_id=$1`, task.ID).Scan(&taskWorkspace); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT workspace_id FROM security_workspace_agents WHERE agent_id=$1`, agent).Scan(&agentWorkspace); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT workspace_id FROM security_scoped_trigger_bindings WHERE trigger_id=$1`, trigger.ID).Scan(&boundWorkspace); err != nil {
		t.Fatal(err)
	}
	if taskWorkspace != workspace || agentWorkspace != workspace || boundWorkspace != workspace {
		t.Fatal("upgrade or attempted mutations changed stored ownership")
	}
}
