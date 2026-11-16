package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Autumn-27/artex/security/syntheticpolicy"
)

func TestSyntheticScopeApprovalIsAppendOnlyAndRevocable(t *testing.T) {
	d, err := Open(scratchDSN(t, "synthetic_scope"))
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
	tenant := id(`INSERT INTO security_tenants(name,enabled) VALUES ('synthetic',true) RETURNING id`)
	team := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'purple','fixture',true) RETURNING id`, tenant)
	otherTeam := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','other',true) RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'synthetic',true) RETURNING id`, tenant, team)
	mkPerson := func(kind, subject, role string, teamID int64) int64 {
		p := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ($1,'fixture',$2,true) RETURNING id`, kind, subject)
		exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,$3)`, teamID, p, role)
		return p
	}
	requester := mkPerson("human", "requester", "operator", team)
	approver := mkPerson("human", "approver", "approver", team)
	requesterMembership := id(`SELECT id FROM security_team_memberships WHERE team_id=$1 AND principal_id=$2`, team, requester)
	approverMembership := id(`SELECT id FROM security_team_memberships WHERE team_id=$1 AND principal_id=$2`, team, approver)
	service := mkPerson("service", "service", "approver", team)
	outsider := mkPerson("human", "outsider", "approver", otherTeam)
	viewer := mkPerson("human", "viewer", "viewer", team)
	task, err := d.CreateTask("synthetic scope fixture", "synthetic goal", nil, 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, workspace, task.ID)
	ctx := context.Background()
	requesterEpoch, approverEpoch := int64(1), int64(1)
	now := time.Now().UTC()
	doc := []byte(`{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["tcp.connect","http.request"]}]}`)
	for _, invalid := range [][]byte{[]byte(`[]`), []byte(`{}`), []byte(`{`), []byte(`{"targets":[],"targets":["other"]}`), []byte(`{"note":"\ud800"}`), []byte(`{"version":1,"targets":[{"address":"8.8.8.8","port":443,"methods":["tcp.connect"]}]}`), []byte(`{"version":1,"targets":[{"address":"172.30.137.20","port":443,"methods":["unknown"]}]}`)} {
		if _, err := d.ProposeSyntheticScope(ctx, requester, requesterEpoch, workspace, task.ID, invalid, now.Add(-time.Minute), now.Add(time.Hour)); !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("invalid proposal %q: %v", invalid, err)
		}
	}
	if _, err := d.ProposeSyntheticScope(ctx, requester, 2, workspace, task.ID, doc, now.Add(-time.Minute), now.Add(time.Hour)); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("wrong requester generation proposed a scope: %v", err)
	}
	if _, err := d.ProposeSyntheticScope(ctx, service, 1, workspace, task.ID, doc, now.Add(-time.Minute), now.Add(time.Hour)); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("service proposed: %v", err)
	}
	proposal, err := d.ProposeSyntheticScope(ctx, requester, requesterEpoch, workspace, task.ID, doc, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("unapproved readable: %v", err)
	}
	for _, p := range []int64{requester, service, outsider} {
		if err := d.ApproveSyntheticScope(ctx, p, 1, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("principal %d approved: %v", p, err)
		}
	}
	if err := d.ApproveSyntheticScope(ctx, approver, approverEpoch, proposal); err != nil {
		t.Fatal(err)
	}
	scope, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scope.Document, doc) || scope.SHA256 != sha256.Sum256(doc) || scope.ApproverID != approver || scope.RequesterID != requester {
		t.Fatalf("scope altered: %+v", scope)
	}
	// The exact approved bytes can be compared to an independent fixture
	// inventory, but this does not authorize execution or prove isolation.
	policy, err := syntheticpolicy.Compile(scope.Document, scope.SHA256, doc)
	if err != nil || !policy.Allows(netip.MustParseAddr("172.30.137.20"), 443, "http.request") || policy.Allows(netip.MustParseAddr("172.30.137.21"), 443, "http.request") {
		t.Fatalf("approved scope inventory intersection failed: %v", err)
	}
	if _, err := syntheticpolicy.Compile(scope.Document, scope.SHA256, []byte(`{"version":1,"targets":[{"address":"172.30.137.21","port":443,"methods":["tcp.connect","http.request"]}]}`)); err == nil {
		t.Fatal("scope outside independent fixture inventory was accepted")
	}
	// Even a matching digest cannot make ambiguous or out-of-policy bytes
	// safe if a record was inserted outside the proposal method.
	for _, invalid := range [][]byte{
		[]byte(`{"targets":[],"targets":["other"]}`),
		[]byte(`{"version":1,"targets":[{"address":"8.8.8.8","port":443,"methods":["tcp.connect"]}]}`),
	} {
		invalidHash := sha256.Sum256(invalid)
		invalidID := id(`INSERT INTO security_scope_proposals(workspace_id,task_id,requester_id,document,document_sha256,valid_from,valid_until,requester_membership_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, workspace, task.ID, requester, invalid, invalidHash[:], now.Add(-time.Minute), now.Add(time.Hour), requesterMembership)
		if err := d.ApproveSyntheticScope(ctx, approver, approverEpoch, invalidID); !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("invalid persisted scope approved: %v", err)
		}
		var decisions int
		if err := d.QueryRow(`SELECT count(*) FROM security_scope_approvals WHERE proposal_id=$1`, invalidID).Scan(&decisions); err != nil || decisions != 0 {
			t.Fatalf("rejected approval persisted: count=%d err=%v", decisions, err)
		}
		exec(`INSERT INTO security_scope_approvals(proposal_id,approver_id,approver_membership_id) VALUES ($1,$2,$3)`, invalidID, approver, approverMembership)
		if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, invalidID); !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("invalid persisted scope was returned: %v", err)
		}
	}
	if _, err := d.ApprovedSyntheticScope(ctx, viewer, 1, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("unrelated member read scope: %v", err)
	}
	if _, err := d.ApprovedSyntheticScope(ctx, service, 1, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("service read scope: %v", err)
	}
	for _, q := range []string{`UPDATE security_scope_proposals SET document='{}'::bytea WHERE id=$1`, `DELETE FROM security_scope_proposals WHERE id=$1`, `UPDATE security_scope_approvals SET approver_id=approver_id WHERE proposal_id=$1`, `DELETE FROM security_scope_approvals WHERE proposal_id=$1`} {
		if _, err := d.Exec(q, proposal); err == nil {
			t.Fatalf("mutation allowed: %s", q)
		}
	}
	exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, approver)
	exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, approver)
	approverEpoch = 2
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("re-enabled approver revived old approval: %v", err)
	}
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE team_id=$1 AND principal_id=$2`, team, approver)
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("revoked approver: %v", err)
	}
	if _, err := d.Exec(`UPDATE security_team_memberships SET revoked_at=NULL WHERE id=$1`, approverMembership); err == nil {
		t.Fatal("approver membership revocation was undone")
	}
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'approver')`, team, approver)
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("regranted approver revived old approval: %v", err)
	}
	newProposal, err := d.ProposeSyntheticScope(ctx, requester, requesterEpoch, workspace, task.ID, doc, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ApproveSyntheticScope(ctx, approver, 1, newProposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("stale approver session authorized a new grant: %v", err)
	}
	if err := d.ApproveSyntheticScope(ctx, approver, approverEpoch, newProposal); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApprovedSyntheticScope(ctx, requester, 2, workspace, newProposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("wrong reader generation authorized: %v", err)
	}
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, newProposal); err != nil {
		t.Fatalf("newly approved scope unavailable: %v", err)
	}
	pending, err := d.ProposeSyntheticScope(ctx, requester, requesterEpoch, workspace, task.ID, doc, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE id=$1`, requesterMembership)
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, team, requester)
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, newProposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("regranted requester revived old scope: %v", err)
	}
	if err := d.ApproveSyntheticScope(ctx, approver, approverEpoch, pending); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("approved a proposal made under a revoked requester grant: %v", err)
	}
	if err := d.RevokeSyntheticScope(ctx, service, 1, proposal, "synthetic test"); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("service revoked: %v", err)
	}
	if err := d.RevokeSyntheticScope(ctx, approver, 1, proposal, "synthetic test"); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("stale approver session revoked scope: %v", err)
	}
	if err := d.RevokeSyntheticScope(ctx, approver, approverEpoch, proposal, "synthetic test"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ApprovedSyntheticScope(ctx, requester, requesterEpoch, workspace, proposal); !errors.Is(err, ErrWorkspaceAccessDenied) {
		t.Fatalf("revoked scope: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM security_scope_revocations WHERE proposal_id=$1`, proposal); err == nil {
		t.Fatal("revocation was removed")
	}
}
