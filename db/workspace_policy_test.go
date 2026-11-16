package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestWorkspaceActionPolicy(t *testing.T) {
	d, err := Open(scratchDSN(t, "workspace_policy"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id := func(q string, a ...any) int64 {
		t.Helper()
		var v int64
		if err := d.QueryRow(q, a...).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := d.Exec(q, a...); err != nil {
			t.Fatal(err)
		}
	}
	tenant := id(`INSERT INTO security_tenants(name,enabled) VALUES ('policy fixture',true) RETURNING id`)
	red := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','red',true) RETURNING id`, tenant)
	blue := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','blue',true) RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'red',true) RETURNING id`, tenant, red)
	otherWorkspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'blue',true) RETURNING id`, tenant, blue)
	identities := map[string]int64{}
	for _, person := range []struct{ name, kind, role string }{
		{"viewer", "human", "viewer"}, {"operator", "human", "operator"}, {"manager", "human", "manager"},
		{"approver", "human", "approver"}, {"service_manager", "service", "manager"},
	} {
		p := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ($1,'fixture',$2,true) RETURNING id`, person.kind, person.name)
		exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,$3)`, red, p, person.role)
		identities[person.name] = p
	}
	agentID := id(`INSERT INTO agents(key,name,role,builtin) VALUES ('workspace_policy_fixture','fixture','assistant',false) RETURNING id`)
	otherAgent := id(`INSERT INTO agents(key,name,role,builtin) VALUES ('other_policy_fixture','fixture','assistant',false) RETURNING id`)
	exec(`INSERT INTO security_workspace_agents(workspace_id,agent_id) VALUES ($1,$2),($3,$4)`, workspace, agentID, otherWorkspace, otherAgent)
	task, err := d.CreateTask("policy task", "synthetic", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, workspace, task.ID)
	cases := []struct {
		name    string
		action  WorkspaceAction
		r       WorkspaceResource
		allowed bool
	}{
		{"viewer", ActionAgentRead, WorkspaceResource{AgentID: agentID}, true},
		{"viewer", ActionTaskRead, WorkspaceResource{TaskID: task.ID}, true},
		{"viewer", ActionTaskCreate, WorkspaceResource{}, false},
		{"operator", ActionTaskCreate, WorkspaceResource{}, true},
		{"operator", ActionTaskUpdate, WorkspaceResource{TaskID: task.ID}, true},
		{"operator", ActionTaskDelete, WorkspaceResource{TaskID: task.ID}, false},
		{"manager", ActionAgentCreate, WorkspaceResource{}, true},
		{"manager", ActionAgentUpdate, WorkspaceResource{AgentID: agentID}, true},
		{"manager", ActionTaskDelete, WorkspaceResource{TaskID: task.ID}, true},
		{"service_manager", ActionAgentUpdate, WorkspaceResource{AgentID: agentID}, false},
		{"approver", ActionApprovalDecide, WorkspaceResource{}, false},
		{"manager", ActionAgentRead, WorkspaceResource{AgentID: otherAgent}, false},
		{"manager", ActionAgentRead, WorkspaceResource{}, false},
		{"manager", ActionTaskRead, WorkspaceResource{TaskID: task.ID, AgentID: agentID}, false},
	}
	for _, action := range []WorkspaceAction{ActionTaskSchedule, ActionTaskExecute, ActionEvidenceRead, ActionEvidenceWrite, ActionSecretRead, ActionSecretLease, ActionToolInvoke, ActionMCPInvoke, ActionProtectedDetectionModify, "future.unknown"} {
		cases = append(cases, struct {
			name    string
			action  WorkspaceAction
			r       WorkspaceResource
			allowed bool
		}{"manager", action, WorkspaceResource{}, false})
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d_%s_%s", i, tc.name, tc.action), func(t *testing.T) {
			err := d.AuthorizeWorkspaceAction(context.Background(), identities[tc.name], 1, workspace, tc.action, tc.r)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v err=%v", tc.allowed, err)
			}
			if !tc.allowed && !errors.Is(err, ErrWorkspaceAccessDenied) {
				t.Fatalf("expected generic denial: %v", err)
			}
		})
	}
	if err := d.AuthorizeWorkspaceAction(context.Background(), identities["manager"], 2, workspace, ActionAgentRead, WorkspaceResource{AgentID: agentID}); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("wrong authentication generation authorized: %v", err)
	}
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE team_id=$1 AND principal_id=$2`, red, identities["manager"])
	if err := d.AuthorizeWorkspaceAction(context.Background(), identities["manager"], 1, workspace, ActionAgentRead, WorkspaceResource{AgentID: agentID}); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("revoked principal: %v", err)
	}
	if err := (*DB)(nil).AuthorizeWorkspaceAction(context.Background(), 1, 1, 1, ActionTaskRead, WorkspaceResource{TaskID: 1}); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("nil store: %v", err)
	}
}
