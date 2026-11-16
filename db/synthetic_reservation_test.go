package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestInactiveFixtureReservationIsSingleAndFailsClosed(t *testing.T) {
	d, err := Open(scratchDSN(t, "fixture_reservation"))
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
	red := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'red','red',true) RETURNING id`, tenant)
	blue := id(`INSERT INTO security_teams(tenant_id,kind,name,enabled) VALUES ($1,'blue','blue',true) RETURNING id`, tenant)
	workspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'red',true) RETURNING id`, tenant, red)
	blueWorkspace := id(`INSERT INTO security_workspaces(tenant_id,team_id,name,enabled) VALUES ($1,$2,'blue',true) RETURNING id`, tenant, blue)
	person := func(team int64, kind, subject, role string) int64 {
		p := id(`INSERT INTO security_principals(kind,issuer,subject,enabled) VALUES ($1,'fixture',$2,true) RETURNING id`, kind, subject)
		exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,$3)`, team, p, role)
		return p
	}
	requester := person(red, "human", "requester", "operator")
	approver := person(red, "human", "approver", "approver")
	executor := person(red, "service", "executor", "operator")
	blueRequester := person(blue, "human", "blue-requester", "operator")
	blueApprover := person(blue, "human", "blue-approver", "approver")
	blueExecutor := person(blue, "service", "blue-executor", "operator")
	ctx := context.Background()
	now := time.Now().UTC()
	document := []byte(`{"version":1,"targets":[{"address":"172.30.139.20","port":80,"methods":["tcp.connect","http.request"]}]}`)
	makeScope := func(workspaceID, requesterID, approverID int64, approve bool) (int64, [32]byte) {
		t.Helper()
		task, err := d.CreateTask("synthetic reservation", "fixture", nil, 0, 300)
		if err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO security_workspace_tasks(workspace_id,task_id) VALUES ($1,$2)`, workspaceID, task.ID)
		proposal, err := d.ProposeSyntheticScope(ctx, requesterID, 1, workspaceID, task.ID, document, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		view, err := d.ProposedSyntheticScope(ctx, approverID, 1, workspaceID, proposal)
		if err != nil {
			t.Fatal(err)
		}
		if approve {
			if err := d.ApproveSyntheticScope(ctx, approverID, 1, workspaceID, proposal, view.DecisionSHA256); err != nil {
				t.Fatal(err)
			}
		}
		return proposal, view.DecisionSHA256
	}
	proposal, decision := makeScope(workspace, requester, approver, true)
	pending, pendingDecision := makeScope(workspace, requester, approver, false)
	blueProposal, blueDecision := makeScope(blueWorkspace, blueRequester, blueApprover, true)
	deny := func(req, reqEpoch, ws, scope, runner, runnerEpoch int64, digest [32]byte, inventory []byte) {
		t.Helper()
		got, err := d.ReserveSyntheticFixtureRun(ctx, req, reqEpoch, ws, scope, runner, runnerEpoch, digest, inventory)
		if got != nil || !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("unsafe reservation: %+v err=%v", got, err)
		}
	}
	deny(requester, 1, workspace, pending, executor, 1, pendingDecision, document)
	deny(requester, 2, workspace, proposal, executor, 1, decision, document)
	deny(requester, 1, workspace, proposal, executor, 2, decision, document)
	deny(requester, 1, workspace, proposal, requester, 1, decision, document)
	deny(requester, 1, blueWorkspace, proposal, executor, 1, decision, document)
	deny(blueRequester, 1, blueWorkspace, blueProposal, blueExecutor, 1, blueDecision, document)
	deny(requester, 1, workspace, proposal, executor, 1, sha256.Sum256([]byte("wrong decision")), document)
	deny(requester, 1, workspace, proposal, executor, 1, decision, []byte(`{"version":1,"targets":[{"address":"172.30.139.21","port":80,"methods":["tcp.connect"]}]}`))
	if count := id(`SELECT count(*) FROM security_run_reservations`); count != 0 {
		t.Fatalf("rejected reservation persisted: %d", count)
	}

	const callers = 12
	results := make(chan *SyntheticRunReservation, callers)
	errorsOut := make(chan error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reservation, err := d.ReserveSyntheticFixtureRun(ctx, requester, 1, workspace, proposal, executor, 1, decision, document)
			if err != nil {
				errorsOut <- err
				return
			}
			results <- reservation
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsOut)
	var won *SyntheticRunReservation
	for reservation := range results {
		if won != nil {
			t.Fatal("more than one live reservation succeeded")
		}
		won = reservation
	}
	if won == nil {
		t.Fatal("no reservation succeeded")
	}
	var denied int
	for err := range errorsOut {
		if !errors.Is(err, ErrWorkspaceAccessDenied) {
			t.Fatalf("unexpected concurrency error: %v", err)
		}
		denied++
	}
	if denied != callers-1 {
		t.Fatalf("denials=%d, want %d", denied, callers-1)
	}
	var storedNonce, storedDecision, storedInventory []byte
	var state string
	if err := d.QueryRow(`SELECT nonce,decision_sha256,inventory_sha256,state FROM security_run_reservations WHERE id=$1`, won.ID).Scan(&storedNonce, &storedDecision, &storedInventory, &state); err != nil {
		t.Fatal(err)
	}
	inventoryHash := sha256.Sum256(document)
	if state != "reserved" || !bytes.Equal(storedNonce, won.Nonce[:]) || !bytes.Equal(storedDecision, decision[:]) || !bytes.Equal(storedInventory, inventoryHash[:]) {
		t.Fatal("reservation context changed")
	}
	for _, query := range []string{
		`UPDATE security_run_reservations SET state='stopped' WHERE id=$1`,
		`UPDATE security_run_reservations SET workspace_id=workspace_id+1 WHERE id=$1`,
		`UPDATE security_run_reservations SET valid_until=valid_until+interval '1 hour' WHERE id=$1`,
		`DELETE FROM security_run_reservations WHERE id=$1`,
	} {
		if _, err := d.Exec(query, won.ID); err == nil {
			t.Fatalf("invalid reservation mutation allowed: %s", query)
		}
	}
	// Only a future independently trusted supervisor may perform these direct
	// state transitions after proving the actual process state. No app path does.
	exec(`UPDATE security_run_reservations SET state='running' WHERE id=$1`, won.ID)
	if _, err := d.Exec(`UPDATE security_run_reservations SET state='reserved' WHERE id=$1`, won.ID); err == nil {
		t.Fatal("reservation state moved backwards")
	}
	exec(`UPDATE security_run_reservations SET state='stopping' WHERE id=$1`, won.ID)
	exec(`UPDATE security_run_reservations SET state='stopped' WHERE id=$1`, won.ID)
	if _, err := d.Exec(`UPDATE security_run_reservations SET stopped_at=NULL WHERE id=$1`, won.ID); err == nil {
		t.Fatal("stopped record was changed")
	}

	// An expired reservation still occupies the slot. This direct insert is only
	// a synthetic fixture; expiry is deliberately not a termination attestation.
	shortNonce := bytes.Repeat([]byte{0x5a}, 32)
	short := id(`INSERT INTO security_run_reservations(nonce,workspace_id,task_id,scope_proposal_id,requester_id,requester_membership_id,executor_id,executor_membership_id,decision_sha256,inventory_sha256,valid_until,created_at)
SELECT $2,workspace_id,task_id,scope_proposal_id,requester_id,requester_membership_id,executor_id,executor_membership_id,decision_sha256,inventory_sha256,statement_timestamp()+interval '1 second',TIMESTAMPTZ '2000-01-01 00:00:00Z'
FROM security_run_reservations WHERE id=$1 RETURNING id`, won.ID, shortNonce)
	var createdAt time.Time
	if err := d.QueryRow(`SELECT created_at FROM security_run_reservations WHERE id=$1`, short).Scan(&createdAt); err != nil || createdAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("reservation creation time was caller-controlled: %v err=%v", createdAt, err)
	}
	if _, err := d.Exec(`SELECT pg_sleep(1.1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE security_run_reservations SET state='running' WHERE id=$1`, short); err == nil {
		t.Fatal("expired reservation was marked running")
	}
	deny(requester, 1, workspace, proposal, executor, 1, decision, document)
	exec(`UPDATE security_run_reservations SET state='stopping' WHERE id=$1`, short)
	exec(`UPDATE security_run_reservations SET state='stopped' WHERE id=$1`, short)
	last, err := d.ReserveSyntheticFixtureRun(ctx, requester, 1, workspace, proposal, executor, 1, decision, document)
	if err != nil {
		t.Fatalf("new reservation after trusted stopped transition: %v", err)
	}
	if _, err := d.Exec(`TRUNCATE security_run_reservations`); err == nil {
		t.Fatal("reservation history was truncated")
	}
	exec(`UPDATE security_principals SET enabled=false WHERE id=$1`, executor)
	exec(`UPDATE security_principals SET enabled=true WHERE id=$1`, executor)
	exec(`UPDATE security_team_memberships SET revoked_at=now() WHERE team_id=$1 AND principal_id=$2`, red, executor)
	exec(`INSERT INTO security_team_memberships(team_id,principal_id,role) VALUES ($1,$2,'operator')`, red, executor)
	if _, err := d.Exec(`UPDATE security_run_reservations SET state='running' WHERE id=$1`, last.ID); err == nil {
		t.Fatal("stale executor grant was allowed to start")
	}
	exec(`UPDATE security_run_reservations SET state='stopping' WHERE id=$1`, last.ID)
	exec(`UPDATE security_run_reservations SET state='stopped' WHERE id=$1`, last.ID)
	deny(requester, 1, workspace, proposal, executor, 1, decision, document)
	fresh, err := d.ReserveSyntheticFixtureRun(ctx, requester, 1, workspace, proposal, executor, 2, decision, document)
	if err != nil {
		t.Fatalf("fresh executor generation with a new grant was denied: %v", err)
	}
	if err := d.RevokeSyntheticScope(ctx, approver, 1, workspace, proposal, "fixture revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE security_run_reservations SET state='running' WHERE id=$1`, fresh.ID); err == nil {
		t.Fatal("revoked scope was allowed to start")
	}
	exec(`UPDATE security_run_reservations SET state='stopping' WHERE id=$1`, fresh.ID)
	exec(`UPDATE security_run_reservations SET state='stopped' WHERE id=$1`, fresh.ID)
	deny(requester, 1, workspace, proposal, executor, 2, decision, document)
}
