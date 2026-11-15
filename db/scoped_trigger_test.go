package db

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScopedTriggerFiltersBeforeDisclosureAndRechecks(t *testing.T) {
	d, err := Open(scratchDSN(t, "scoped_trigger"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id := func(query string, args ...any) int64 {
		t.Helper()
		var v int64
		if err := d.QueryRow(query, args...).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	tenant := id(`INSERT INTO security_tenants(name,enabled) VALUES ('synthetic',true) RETURNING id`)
	red := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','red',true) RETURNING id`, tenant)
	blue := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','blue',true) RETURNING id`, tenant)
	rw := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'r',true) RETURNING id`, tenant, red)
	bw := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'b',true) RETURNING id`, tenant, blue)
	principal := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ('service','synthetic','red',true) RETURNING id`)
	other := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ('service','synthetic','blue',true) RETURNING id`)
	member := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, red, principal)
	otherMember := id(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator') RETURNING id`, blue, other)
	agentID := id(`INSERT INTO agents(key,name,role,builtin,enabled) VALUES ('scoped_red_fixture','red','assistant',false,true) RETURNING id`)
	exec(`INSERT INTO security_workspace_agents(workspace_id,agent_id) VALUES ($1,$2)`, rw, agentID)
	redTask, err := d.CreateTask("red secret description", "red secret goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	blueTask, err := d.CreateTask("blue secret description", "blue secret goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	legacyTask, err := d.CreateTask("legacy fixture", "legacy goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2),($3,$4)`, rw, redTask.ID, bw, blueTask.ID)
	insertActivity := func(task *Task, content string) int64 {
		return id(`INSERT INTO activity(exploration_id,kind,tool,tool_use_id,detail) VALUES ($1,'tool_result','scan','fixture',$2) RETURNING id`, task.ExplorationID, content)
	}
	redEvent := insertActivity(redTask, "red private output")
	_ = insertActivity(blueTask, "blue private output")
	legacyEvent := insertActivity(legacyTask, "legacy output")
	tr, err := d.CreateTrigger(&AgentTrigger{AgentKey: "scoped_red_fixture", Enabled: true, OnToolCall: true, ToolNames: []string{"scan"}})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_scoped_trigger_bindings(trigger_id,workspace_id,principal_id,owner_membership_id) VALUES ($1,$2,$3,$4)`, tr.ID, rw, principal, member)
	ctx := context.Background()
	list := func(p, w int64) []ScopedToolEvent {
		t.Helper()
		got, err := d.ScopedToolEvents(ctx, p, w, tr.ID, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if len(list(principal, rw)) != 0 {
		t.Fatal("disabled scoped binding emitted events")
	}
	legacyTriggers, err := d.ListEnabledTriggers()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range legacyTriggers {
		if e.ID == tr.ID {
			t.Fatal("bound trigger entered legacy scheduler")
		}
	}
	exec(`UPDATE security_scoped_trigger_bindings SET enabled=true WHERE trigger_id=$1`, tr.ID)
	events := list(principal, rw)
	if len(events) != 1 || events[0].TaskID != redTask.ID || events[0].ActivityID != redEvent || events[0].Tool != "scan" {
		t.Fatalf("scoped events=%+v", events)
	}
	if len(list(other, rw)) != 0 || len(list(principal, bw)) != 0 {
		t.Fatal("cross-principal or cross-team event disclosed")
	}
	exec(`UPDATE security_scoped_trigger_bindings SET owner_membership_id=$2 WHERE trigger_id=$1`, tr.ID, otherMember)
	if len(list(principal, rw)) != 0 {
		t.Fatal("a membership belonging to another principal and team disclosed events")
	}
	exec(`UPDATE security_scoped_trigger_bindings SET owner_membership_id=$2 WHERE trigger_id=$1`, tr.ID, member)
	legacyEvents, err := d.NewToolCallsSince(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range legacyEvents {
		if e.NodeID == redEvent || strings.Contains(e.ToolOutput, "blue private") {
			t.Fatalf("assigned task leaked to legacy scheduler: %+v", e)
		}
	}
	foundLegacy := false
	for _, e := range legacyEvents {
		if e.NodeID == legacyEvent {
			foundLegacy = true
		}
	}
	if !foundLegacy {
		t.Fatal("unassigned legacy tool event was lost")
	}
	if _, err := d.ScopedToolEventForDispatch(ctx, principal, rw, tr.ID, redEvent); err != nil {
		t.Fatalf("dispatch recheck: %v", err)
	}
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, member)
	if len(list(principal, rw)) != 0 {
		t.Fatal("revoked owner can still list")
	}
	if _, err := d.ScopedToolEventForDispatch(ctx, principal, rw, tr.ID, redEvent); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("revoked dispatch err=%v", err)
	}
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, red, principal)
	if len(list(principal, rw)) != 0 {
		t.Fatal("new membership revived an old trigger binding")
	}
	if _, err := d.ScopedToolEventForDispatch(ctx, principal, rw, tr.ID, redEvent); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("regranted principal dispatched an old trigger: %v", err)
	}
	allowed, err := d.LegacyTriggerPermitted(ctx, "scoped_red_fixture", nil, nil)
	if err != nil || allowed {
		t.Fatalf("assigned agent legacy permission=%v, %v", allowed, err)
	}
	allowed, err = d.LegacyTriggerPermitted(ctx, "legacy", []int64{legacyTask.ID}, nil)
	if err != nil || !allowed {
		t.Fatalf("legacy permission=%v, %v", allowed, err)
	}
	legacyTrigger, err := d.CreateTrigger(&AgentTrigger{AgentKey: "legacy", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = d.LegacyTriggerPermitted(ctx, "legacy", []int64{legacyTask.ID}, []int64{legacyTrigger.ID})
	if err != nil || !allowed {
		t.Fatalf("unassigned trigger denied: %v %v", allowed, err)
	}
	exec(`INSERT INTO security_scoped_trigger_bindings(trigger_id,workspace_id,principal_id) VALUES ($1,$2,$3)`, legacyTrigger.ID, rw, principal)
	allowed, err = d.LegacyTriggerPermitted(ctx, "legacy", []int64{legacyTask.ID}, []int64{legacyTrigger.ID})
	if err != nil || allowed {
		t.Fatalf("newly bound trigger permitted: %v %v", allowed, err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, rw, legacyTask.ID)
	allowed, err = d.LegacyTriggerPermitted(ctx, "legacy", []int64{legacyTask.ID}, nil)
	if err != nil || allowed {
		t.Fatalf("reassigned task permitted=%v, %v", allowed, err)
	}
	allowed, err = d.LegacyTriggerPermitted(ctx, "legacy", []int64{999999999}, nil)
	if err != nil || allowed {
		t.Fatalf("missing task permitted=%v, %v", allowed, err)
	}
}
