package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Autumn-27/artex/security/syntheticpolicy"
)

// SyntheticRunReservation is an inactive reservation record, not an execution
// capability or proof that an executor is isolated. Nothing in the current
// application starts work from it or automatically frees it on timeout.
type SyntheticRunReservation struct {
	ID, WorkspaceID, TaskID, ScopeProposalID, ExecutorID int64
	Nonce                                                [32]byte
	ValidUntil                                           time.Time
}

// ReserveSyntheticFixtureRun atomically occupies the single database slot for
// an already approved Red fixture scope and an active service membership. Both
// actor IDs and generations must come from separately verified credentials.
// inventory must be supplied by an independently administered source, not an
// agent or the requester. This function cannot authenticate that source, prove
// that any target is synthetic, attest a host or authorize a network request.
// It is not wired to an API, scheduler or executor. A future trusted supervisor
// must verify process termination before recording the stopped transition; no
// caller may treat expiry or a missing heartbeat as proof of termination.
func (d *DB) ReserveSyntheticFixtureRun(ctx context.Context, requesterID, requesterEpoch, workspaceID, proposalID, executorID, executorEpoch int64, decision [sha256.Size]byte, inventory []byte) (*SyntheticRunReservation, error) {
	if ctx == nil || d == nil || d.DB == nil || requesterID <= 0 || requesterEpoch <= 0 || workspaceID <= 0 || proposalID <= 0 || executorID <= 0 || executorEpoch <= 0 || len(inventory) == 0 || len(inventory) > 65536 {
		return nil, ErrWorkspaceAccessDenied
	}
	inventory = bytes.Clone(inventory)
	if syntheticpolicy.Validate(inventory) != nil {
		return nil, ErrWorkspaceAccessDenied
	}
	inventoryHash := sha256.Sum256(inventory)
	var reservation SyntheticRunReservation
	if _, err := rand.Read(reservation.Nonce[:]); err != nil {
		return nil, errors.New("reservation unavailable")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("reserve synthetic fixture: %w", err)
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `
INSERT INTO security_run_reservations(nonce,workspace_id,task_id,scope_proposal_id,requester_id,requester_membership_id,executor_id,executor_membership_id,decision_sha256,inventory_sha256,valid_until)
SELECT $7,w.id,task.id,proposal.id,requester.id,requester_m.id,executor.id,executor_m.id,$8,$9,proposal.valid_until
FROM security_scope_proposals proposal
JOIN security_scope_approvals approval ON approval.proposal_id=proposal.id AND approval.approver_id<>proposal.requester_id
JOIN security_workspaces w ON w.id=proposal.workspace_id AND w.enabled
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.kind='red' AND team.enabled
JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
JOIN security_workspace_tasks assigned ON assigned.workspace_id=w.id AND assigned.task_id=proposal.task_id
JOIN tasks task ON task.id=assigned.task_id AND task.deleted_at IS NULL
JOIN security_principals requester ON requester.id=proposal.requester_id AND requester.kind='human' AND requester.enabled AND requester.auth_epoch=$2
JOIN security_team_memberships requester_m ON requester_m.id=proposal.requester_membership_id AND requester_m.principal_id=requester.id
 AND requester_m.team_id=team.id AND requester_m.principal_auth_epoch=requester.auth_epoch AND requester_m.role IN ('operator','manager')
 AND requester_m.revoked_at IS NULL AND requester_m.valid_from<=statement_timestamp() AND (requester_m.expires_at IS NULL OR requester_m.expires_at>statement_timestamp())
JOIN security_principals approver ON approver.id=approval.approver_id AND approver.kind='human' AND approver.enabled
JOIN security_team_memberships approver_m ON approver_m.id=approval.approver_membership_id AND approver_m.principal_id=approver.id
 AND approver_m.team_id=team.id AND approver_m.principal_auth_epoch=approver.auth_epoch AND approver_m.role='approver'
 AND approver_m.revoked_at IS NULL AND approver_m.valid_from<=statement_timestamp() AND (approver_m.expires_at IS NULL OR approver_m.expires_at>statement_timestamp())
JOIN security_principals executor ON executor.id=$5 AND executor.kind='service' AND executor.enabled AND executor.auth_epoch=$6
JOIN security_team_memberships executor_m ON executor_m.principal_id=executor.id AND executor_m.team_id=team.id
 AND executor_m.principal_auth_epoch=executor.auth_epoch AND executor_m.role IN ('operator','manager')
 AND executor_m.revoked_at IS NULL AND executor_m.valid_from<=statement_timestamp() AND (executor_m.expires_at IS NULL OR executor_m.expires_at>statement_timestamp())
WHERE requester.id=$1 AND w.id=$3 AND proposal.id=$4 AND proposal.environment='synthetic'
 AND proposal.valid_from<=statement_timestamp() AND proposal.valid_until>statement_timestamp()
 AND NOT EXISTS (SELECT 1 FROM security_scope_revocations rev WHERE rev.proposal_id=proposal.id)
RETURNING id,workspace_id,task_id,scope_proposal_id,executor_id,valid_until`, requesterID, requesterEpoch, workspaceID, proposalID, executorID, executorEpoch, reservation.Nonce[:], decision[:], inventoryHash[:]).
		Scan(&reservation.ID, &reservation.WorkspaceID, &reservation.TaskID, &reservation.ScopeProposalID, &reservation.ExecutorID, &reservation.ValidUntil)
	if errors.Is(err, sql.ErrNoRows) || isScopeConflict(err) {
		return nil, ErrWorkspaceAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("reserve synthetic fixture: %w", err)
	}
	var scope SyntheticScope
	var hash []byte
	if err := tx.QueryRowContext(ctx, `SELECT id,workspace_id,task_id,requester_id,document,document_sha256,valid_from,valid_until FROM security_scope_proposals WHERE id=$1 FOR SHARE`, proposalID).
		Scan(&scope.ID, &scope.WorkspaceID, &scope.TaskID, &scope.RequesterID, &scope.Document, &hash, &scope.ValidFrom, &scope.ValidUntil); err != nil {
		return nil, fmt.Errorf("reserve synthetic fixture: load scope: %w", err)
	}
	scope.SHA256 = sha256.Sum256(scope.Document)
	if len(hash) != sha256.Size || subtle.ConstantTimeCompare(hash, scope.SHA256[:]) != 1 {
		return nil, ErrWorkspaceAccessDenied
	}
	if computed := scopeDecisionDigest(scope); subtle.ConstantTimeCompare(computed[:], decision[:]) != 1 {
		return nil, ErrWorkspaceAccessDenied
	}
	if _, err := syntheticpolicy.Compile(scope.Document, scope.SHA256, inventory); err != nil {
		return nil, ErrWorkspaceAccessDenied
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("reserve synthetic fixture: commit: %w", err)
	}
	return &reservation, nil
}
