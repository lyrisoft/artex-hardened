package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrWorkspaceAccessDenied is deliberately identical for absent, disabled,
// expired, revoked and unrelated membership, so callers do not disclose which
// part of an untrusted workspace/principal lookup exists.
var ErrWorkspaceAccessDenied = errors.New("workspace access denied")

// WorkspaceMembership contains only facts loaded from the security tables. It
// is not an authorization decision for a task, tool, secret or other resource.
// Action-specific policy, target approval and executor isolation must also be
// enforced. None of the existing HTTP or runtime paths use this resolver yet.
type WorkspaceMembership struct {
	PrincipalID   int64
	PrincipalKind string
	Role          string
	TenantID      int64
	TeamID        int64
	TeamKind      string
	WorkspaceID   int64
}

// ResolveWorkspaceMembership checks current membership against the database at
// the time of the call. principalID and authEpoch must come from a verified human
// or service identity, never a request parameter, prompt or tool output. The
// caller must deny on every error, recheck at execution, and enforce an action-
// and resource-specific policy. A prior result is not a lease or authorization.
func (d *DB) ResolveWorkspaceMembership(ctx context.Context, principalID, authEpoch, workspaceID int64) (*WorkspaceMembership, error) {
	if ctx == nil || principalID <= 0 || authEpoch <= 0 || workspaceID <= 0 {
		return nil, ErrWorkspaceAccessDenied
	}
	if d == nil || d.DB == nil {
		return nil, errors.New("workspace membership store unavailable")
	}
	var m WorkspaceMembership
	err := d.QueryRowContext(ctx, `
SELECT p.id, p.kind, m.role, tenant.id, team.id, team.kind, w.id
FROM security_workspaces w
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id
JOIN security_tenants tenant ON tenant.id=w.tenant_id
JOIN security_team_memberships m ON m.team_id=team.id
JOIN security_principals p ON p.id=m.principal_id AND m.principal_auth_epoch=p.auth_epoch
WHERE w.id=$1 AND p.id=$2 AND p.auth_epoch=$3
  AND w.enabled AND team.enabled AND tenant.enabled AND p.enabled
  AND m.revoked_at IS NULL AND m.valid_from <= statement_timestamp()
  AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())`, workspaceID, principalID, authEpoch).
		Scan(&m.PrincipalID, &m.PrincipalKind, &m.Role, &m.TenantID, &m.TeamID, &m.TeamKind, &m.WorkspaceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWorkspaceAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("resolve workspace membership: %w", err)
	}
	return &m, nil
}
