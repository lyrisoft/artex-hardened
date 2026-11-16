package db

import (
	"context"
	"testing"
)

func TestHumanWorkspaceReadsFilterBeforeDisclosureAndRecheckEpoch(t *testing.T) {
	d, err := Open(scratchDSN(t, "human_workspace_reads"))
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
	tenantA := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture-a',true) RETURNING id`)
	tenantB := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture-b',true) RETURNING id`)
	red := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','red',true) RETURNING id`, tenantA)
	blue := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','blue',true) RETURNING id`, tenantB)
	rw := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'red',true) RETURNING id`, tenantA, red)
	bw := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'blue',true) RETURNING id`, tenantB, blue)
	human := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ('human','fixture','alice',true) RETURNING id`)
	service := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ('service','fixture','service',true) RETURNING id`)
	grant := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'viewer') RETURNING id`, red, human)
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, red, service)
	redTask, err := d.CreateTaskWithOptions("synthetic red", "fixture", TaskCreateOptions{Name: "red-task"})
	if err != nil {
		t.Fatal(err)
	}
	blueTask, err := d.CreateTaskWithOptions("synthetic blue", "fixture", TaskCreateOptions{Name: "blue-task"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateTaskWithOptions("synthetic legacy", "fixture", TaskCreateOptions{Name: "unassigned-task"}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2),($3,$4)`, rw, redTask.ID, bw, blueTask.ID)
	ctx := context.Background()
	workspaces, err := d.HumanWorkspaces(ctx, human, 1, 0, 100)
	if err != nil || len(workspaces) != 1 || workspaces[0].ID != rw || workspaces[0].TenantID != tenantA {
		t.Fatalf("workspaces=%+v err=%v", workspaces, err)
	}
	tasks, err := d.HumanWorkspaceTasks(ctx, human, 1, rw, 0, 100)
	if err != nil || len(tasks) != 1 || tasks[0].ID != redTask.ID || tasks[0].Name != "red-task" {
		t.Fatalf("tasks=%+v err=%v", tasks, err)
	}
	if tasks, err := d.HumanWorkspaceTasks(ctx, human, 1, bw, 0, 100); err != nil || len(tasks) != 0 {
		t.Fatalf("other tenant tasks=%+v err=%v", tasks, err)
	}
	if workspaces, err := d.HumanWorkspaces(ctx, service, 1, 0, 100); err != nil || len(workspaces) != 0 {
		t.Fatalf("service principal saw human workspaces: %+v err=%v", workspaces, err)
	}
	if tasks, err := d.HumanWorkspaceTasks(ctx, human, 1, rw, redTask.ID, 100); err != nil || len(tasks) != 0 {
		t.Fatalf("task cursor=%+v err=%v", tasks, err)
	}
	// The same verified session must not gain a newly issued grant if disable,
	// re-enable and regrant happen after authentication but before this query.
	exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, human)
	exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, human)
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, grant)
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'viewer')`, red, human)
	if tasks, err := d.HumanWorkspaceTasks(ctx, human, 1, rw, 0, 100); err != nil || len(tasks) != 0 {
		t.Fatalf("stale session saw new grant: %+v err=%v", tasks, err)
	}
	if tasks, err := d.HumanWorkspaceTasks(ctx, human, 2, rw, 0, 100); err != nil || len(tasks) != 1 || tasks[0].ID != redTask.ID {
		t.Fatalf("new session did not see new grant: %+v err=%v", tasks, err)
	}
	if _, err := d.HumanWorkspaces(ctx, human, 2, 0, 101); err == nil {
		t.Fatal("unbounded page accepted")
	}
}
