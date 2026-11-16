package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
)

// Unbound records created before migration 0007 are retained for audit, but
// must not be treated as authorized merely because a current grant exists.
func TestScopeMembershipMigrationQuarantinesUnboundRecords(t *testing.T) {
	dsn := scratchDSN(t, "scope_membership_upgrade")
	old := fstest.MapFS{}
	for _, name := range []string{
		llmRecordsMigration, llmUsageMigration, "0003_task_scope_icp_index.sql",
		"0004_team_foundation.sql", "0005_scoped_trigger_bindings.sql", "0006_synthetic_scope_records.sql",
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
		var result int64
		if err := d.QueryRow(query, args...).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	tenant := id(`INSERT INTO security_tenants(name,enabled) VALUES ('fixture',true) RETURNING id`)
	team := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','fixture',true) RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'fixture',true) RETURNING id`, tenant, team)
	person := func(subject, kind, role string) int64 {
		p := id(`INSERT INTO security_principals(issuer,subject,kind,enabled) VALUES ('fixture',$1,$2,true) RETURNING id`, subject, kind)
		exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,$3)`, team, p, role)
		return p
	}
	requester := person("requester", "human", "operator")
	approver := person("approver", "human", "approver")
	owner := person("owner", "service", "operator")
	agentID := id(`INSERT INTO agents(key,name,role,builtin,enabled) VALUES ('upgrade_scope_fixture','fixture','assistant',false,true) RETURNING id`)
	exec(`INSERT INTO security_workspace_agents(workspace_id,agent_id) VALUES ($1,$2)`, workspace, agentID)
	task, err := d.CreateTask("synthetic upgrade", "fixture", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, workspace, task.ID)
	activity := id(`INSERT INTO activity(exploration_id,kind,tool,tool_use_id,detail) VALUES ($1,'tool_result','scan','fixture','private') RETURNING id`, task.ExplorationID)
	trigger, err := d.CreateTrigger(&AgentTrigger{AgentKey: "upgrade_scope_fixture", Enabled: true, OnToolCall: true, ToolNames: []string{"scan"}})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_scoped_trigger_bindings(trigger_id,workspace_id,principal_id,enabled) VALUES ($1,$2,$3,true)`, trigger.ID, workspace, owner)
	document := []byte(`{"targets":["synthetic.invalid"]}`)
	hash := sha256.Sum256(document)
	proposal := id(`INSERT INTO security_scope_proposals(workspace_id,task_id,requester_id,document,document_sha256,valid_from,valid_until) VALUES ($1,$2,$3,$4,$5,now()-interval '1 minute',now()+interval '1 hour') RETURNING id`, workspace, task.ID, requester, document, hash[:])
	exec(`INSERT INTO security_scope_approvals(proposal_id,approver_id) VALUES ($1,$2)`, proposal, approver)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var gotDocument, gotHash []byte
	var requesterGrant, approverGrant, ownerGrant sql.NullInt64
	if err := d.QueryRow(`SELECT p.document,p.document_sha256,p.requester_membership_id,a.approver_membership_id,b.owner_membership_id FROM security_scope_proposals p JOIN security_scope_approvals a ON a.proposal_id=p.id JOIN security_scoped_trigger_bindings b ON b.trigger_id=$2 WHERE p.id=$1`, proposal, trigger.ID).
		Scan(&gotDocument, &gotHash, &requesterGrant, &approverGrant, &ownerGrant); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDocument, document) || !bytes.Equal(gotHash, hash[:]) || requesterGrant.Valid || approverGrant.Valid || ownerGrant.Valid {
		t.Fatal("migration changed prior evidence or inferred a membership grant")
	}
	var unbound int
	if err := d.QueryRow(`SELECT count(*) FROM security_team_memberships WHERE team_id=$1 AND principal_auth_epoch IS NULL`, team).Scan(&unbound); err != nil || unbound != 3 {
		t.Fatalf("prior principal generations inferred: count=%d err=%v", unbound, err)
	}
	if _, err := d.ApprovedSyntheticScope(context.Background(), requester, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("unbound approval became readable: %v", err)
	}
	if _, err := d.ScopedToolEventForDispatch(context.Background(), owner, workspace, trigger.ID, activity); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("unbound trigger became dispatchable: %v", err)
	}
	triggers, err := d.ListEnabledTriggers()
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range triggers {
		if tr.ID == trigger.ID {
			t.Fatal("unbound trigger escaped into the legacy scheduler")
		}
	}
}
