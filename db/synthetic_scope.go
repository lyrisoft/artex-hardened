package db

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SyntheticScope is an inert record, not permission to contact a target. Its
// document must still be interpreted by a separately administered authorization
// service and enforced by an isolated executor and independent egress broker.
type SyntheticScope struct {
	ID, WorkspaceID, TaskID, RequesterID, ApproverID int64
	Document                                         []byte
	SHA256                                           [sha256.Size]byte
	ValidFrom, ValidUntil                            time.Time
}

// ProposeSyntheticScope stores exact JSON bytes and their hash. The caller must
// derive requesterID from a verified human session, never from request content.
// "synthetic" is only a classification asserted by the author; this storage
// method does not prove that an address, account or data source is synthetic.
func (d *DB) ProposeSyntheticScope(ctx context.Context, requesterID, workspaceID, taskID int64, document []byte, from, until time.Time) (int64, error) {
	if d == nil || d.DB == nil || requesterID <= 0 || workspaceID <= 0 || taskID <= 0 || len(document) < 2 || len(document) > 65536 || !until.After(from) || !json.Valid(document) {
		return 0, ErrWorkspaceAccessDenied
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(document, &object); err != nil || object == nil || len(object) == 0 {
		return 0, ErrWorkspaceAccessDenied
	}
	digest := sha256.Sum256(document)
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO security_scope_proposals(workspace_id,task_id,requester_id,document,document_sha256,valid_from,valid_until)
SELECT w.id,t.id,p.id,$4,$5,$6,$7
FROM security_workspaces w
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
JOIN security_team_memberships m ON m.team_id=team.id AND m.role IN ('operator','manager') AND m.revoked_at IS NULL
 AND m.valid_from <= statement_timestamp() AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
JOIN security_principals p ON p.id=m.principal_id AND p.kind='human' AND p.enabled
JOIN security_workspace_tasks wt ON wt.workspace_id=w.id
JOIN tasks t ON t.id=wt.task_id AND t.deleted_at IS NULL
WHERE w.enabled AND w.id=$2 AND p.id=$1 AND t.id=$3 AND $7 > statement_timestamp()
RETURNING id`, requesterID, workspaceID, taskID, document, digest[:], from, until).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrWorkspaceAccessDenied
	}
	if err != nil {
		return 0, fmt.Errorf("propose synthetic scope: %w", err)
	}
	return id, nil
}

// ApproveSyntheticScope records the decision of a distinct, currently authorized
// human approver. approverID must come from that person's verified session. It
// cannot safely be called using an agent-supplied ID or the legacy shared login.
func (d *DB) ApproveSyntheticScope(ctx context.Context, approverID, proposalID int64) error {
	if d == nil || d.DB == nil || approverID <= 0 || proposalID <= 0 {
		return ErrWorkspaceAccessDenied
	}
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO security_scope_approvals(proposal_id,approver_id)
SELECT proposal.id,p.id
FROM security_scope_proposals proposal
JOIN security_workspaces w ON w.id=proposal.workspace_id AND w.enabled
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
JOIN security_team_memberships m ON m.team_id=team.id AND m.role='approver' AND m.revoked_at IS NULL
 AND m.valid_from <= statement_timestamp() AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
JOIN security_principals p ON p.id=m.principal_id AND p.kind='human' AND p.enabled
JOIN security_workspace_tasks wt ON wt.workspace_id=w.id AND wt.task_id=proposal.task_id
JOIN tasks t ON t.id=wt.task_id AND t.deleted_at IS NULL
WHERE proposal.id=$2 AND p.id=$1 AND proposal.requester_id<>p.id AND proposal.valid_until > statement_timestamp()
 AND NOT EXISTS(SELECT 1 FROM security_scope_revocations r WHERE r.proposal_id=proposal.id)
RETURNING proposal_id`, approverID, proposalID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWorkspaceAccessDenied
	}
	if err != nil {
		return fmt.Errorf("approve synthetic scope: %w", err)
	}
	return nil
}

// RevokeSyntheticScope appends a revocation. A currently authorized human
// approver must initiate it. Active executor interruption is not implemented.
func (d *DB) RevokeSyntheticScope(ctx context.Context, revokerID, proposalID int64, reason string) error {
	if d == nil || d.DB == nil || revokerID <= 0 || proposalID <= 0 || len(reason) == 0 || len(reason) > 4096 {
		return ErrWorkspaceAccessDenied
	}
	var id int64
	err := d.QueryRowContext(ctx, `
INSERT INTO security_scope_revocations(proposal_id,revoker_id,reason)
SELECT proposal.id,p.id,$3 FROM security_scope_proposals proposal
JOIN security_workspaces w ON w.id=proposal.workspace_id AND w.enabled
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
JOIN security_team_memberships m ON m.team_id=team.id AND m.role='approver' AND m.revoked_at IS NULL
 AND m.valid_from <= statement_timestamp() AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
JOIN security_principals p ON p.id=m.principal_id AND p.kind='human' AND p.enabled
WHERE proposal.id=$2 AND p.id=$1 RETURNING proposal_id`, revokerID, proposalID, reason).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWorkspaceAccessDenied
	}
	if err != nil {
		return fmt.Errorf("revoke synthetic scope: %w", err)
	}
	return nil
}

// ApprovedSyntheticScope rechecks owner, approver, reader, assignment, validity,
// revocation and document hash. A successful lookup is deliberately NOT an
// execution authorization or an egress check.
func (d *DB) ApprovedSyntheticScope(ctx context.Context, readerID, workspaceID, proposalID int64) (*SyntheticScope, error) {
	if d == nil || d.DB == nil || readerID <= 0 || workspaceID <= 0 || proposalID <= 0 {
		return nil, ErrWorkspaceAccessDenied
	}
	var s SyntheticScope
	var hash []byte
	err := d.QueryRowContext(ctx, `
SELECT proposal.id,w.id,proposal.task_id,proposal.requester_id,approval.approver_id,proposal.document,proposal.document_sha256,proposal.valid_from,proposal.valid_until
FROM security_scope_proposals proposal
JOIN security_scope_approvals approval ON approval.proposal_id=proposal.id AND approval.approver_id<>proposal.requester_id
JOIN security_workspaces w ON w.id=proposal.workspace_id AND w.enabled
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
JOIN security_workspace_tasks wt ON wt.workspace_id=w.id AND wt.task_id=proposal.task_id
JOIN tasks t ON t.id=wt.task_id AND t.deleted_at IS NULL
JOIN security_principals requester ON requester.id=proposal.requester_id AND requester.enabled AND requester.kind='human'
JOIN security_team_memberships requester_m ON requester_m.team_id=team.id AND requester_m.principal_id=requester.id
 AND requester_m.role IN ('operator','manager') AND requester_m.revoked_at IS NULL
 AND requester_m.valid_from<=statement_timestamp() AND (requester_m.expires_at IS NULL OR requester_m.expires_at>statement_timestamp())
JOIN security_principals approver ON approver.id=approval.approver_id AND approver.enabled AND approver.kind='human'
JOIN security_team_memberships approver_m ON approver_m.team_id=team.id AND approver_m.principal_id=approver.id
 AND approver_m.role='approver' AND approver_m.revoked_at IS NULL
 AND approver_m.valid_from<=statement_timestamp() AND (approver_m.expires_at IS NULL OR approver_m.expires_at>statement_timestamp())
JOIN security_principals reader ON reader.id=$1 AND reader.enabled AND reader.kind='human'
 AND (reader.id=proposal.requester_id OR reader.id=approval.approver_id)
JOIN security_team_memberships reader_m ON reader_m.team_id=team.id AND reader_m.principal_id=reader.id
 AND reader_m.role IN ('viewer','operator','manager','approver') AND reader_m.revoked_at IS NULL
 AND reader_m.valid_from<=statement_timestamp() AND (reader_m.expires_at IS NULL OR reader_m.expires_at>statement_timestamp())
WHERE w.id=$2 AND proposal.id=$3 AND proposal.environment='synthetic'
 AND proposal.valid_from<=statement_timestamp() AND proposal.valid_until>statement_timestamp()
 AND NOT EXISTS (SELECT 1 FROM security_scope_revocations rev WHERE rev.proposal_id=proposal.id)`, readerID, workspaceID, proposalID).
		Scan(&s.ID, &s.WorkspaceID, &s.TaskID, &s.RequesterID, &s.ApproverID, &s.Document, &hash, &s.ValidFrom, &s.ValidUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWorkspaceAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("read approved synthetic scope: %w", err)
	}
	digest := sha256.Sum256(s.Document)
	if len(hash) != sha256.Size || subtle.ConstantTimeCompare(hash, digest[:]) != 1 {
		return nil, ErrWorkspaceAccessDenied
	}
	s.SHA256 = digest
	return &s, nil
}
