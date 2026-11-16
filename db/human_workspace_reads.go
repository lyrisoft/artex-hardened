package db

import (
	"context"
	"fmt"
)

// HumanWorkspaceSummary and HumanWorkspaceTask are deliberately small scoped
// views. They do not include credentials, evidence, raw tool output or graphs.
type HumanWorkspaceSummary struct {
	ID       int64  `json:"id"`
	TenantID int64  `json:"tenant_id"`
	Name     string `json:"name"`
	TeamKind string `json:"team_kind"`
	Role     string `json:"role"`
}

type HumanWorkspaceTask struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// HumanWorkspaces filters inside PostgreSQL before returning any workspace
// fields. principalID and authEpoch must come from a verified human session,
// never from the request. A stale generation produces no rows.
func (d *DB) HumanWorkspaces(ctx context.Context, principalID, authEpoch, afterID int64, limit int) ([]HumanWorkspaceSummary, error) {
	if ctx == nil || d == nil || d.DB == nil || principalID <= 0 || authEpoch <= 0 || afterID < 0 || limit < 1 || limit > 100 {
		return nil, ErrWorkspaceAccessDenied
	}
	rows, err := d.QueryContext(ctx, `
SELECT w.id,w.tenant_id,w.name,team.kind,m.role
FROM security_principals p
JOIN security_team_memberships m ON m.principal_id=p.id AND m.principal_auth_epoch=p.auth_epoch
JOIN security_teams team ON team.id=m.team_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=team.tenant_id AND tenant.enabled
JOIN security_workspaces w ON w.team_id=team.id AND w.tenant_id=tenant.id AND w.enabled
WHERE p.id=$1 AND p.auth_epoch=$2 AND p.kind='human' AND p.enabled
 AND m.role IN ('viewer','operator','manager','approver') AND m.revoked_at IS NULL
 AND m.valid_from<=statement_timestamp() AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
 AND w.id>$3 ORDER BY w.id LIMIT $4`, principalID, authEpoch, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list human workspaces: %w", err)
	}
	defer rows.Close()
	out := []HumanWorkspaceSummary{}
	for rows.Next() {
		var item HumanWorkspaceSummary
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.TeamKind, &item.Role); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// HumanWorkspaceTasks checks the session generation, membership and task
// assignment in the same query as the read. Missing or unauthorized workspaces
// return an empty list; legacy unassigned tasks are never included.
func (d *DB) HumanWorkspaceTasks(ctx context.Context, principalID, authEpoch, workspaceID, afterID int64, limit int) ([]HumanWorkspaceTask, error) {
	if ctx == nil || d == nil || d.DB == nil || principalID <= 0 || authEpoch <= 0 || workspaceID <= 0 || afterID < 0 || limit < 1 || limit > 100 {
		return nil, ErrWorkspaceAccessDenied
	}
	rows, err := d.QueryContext(ctx, `
SELECT task.id,COALESCE(task.name,''),task.status
FROM security_principals p
JOIN security_team_memberships m ON m.principal_id=p.id AND m.principal_auth_epoch=p.auth_epoch
JOIN security_teams team ON team.id=m.team_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=team.tenant_id AND tenant.enabled
JOIN security_workspaces w ON w.team_id=team.id AND w.tenant_id=tenant.id AND w.enabled
JOIN security_workspace_tasks assigned ON assigned.workspace_id=w.id
JOIN tasks task ON task.id=assigned.task_id AND task.deleted_at IS NULL
WHERE p.id=$1 AND p.auth_epoch=$2 AND p.kind='human' AND p.enabled AND w.id=$3
 AND m.role IN ('viewer','operator','manager','approver') AND m.revoked_at IS NULL
 AND m.valid_from<=statement_timestamp() AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
 AND task.id>$4 ORDER BY task.id LIMIT $5`, principalID, authEpoch, workspaceID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list human workspace tasks: %w", err)
	}
	defer rows.Close()
	out := []HumanWorkspaceTask{}
	for rows.Next() {
		var item HumanWorkspaceTask
		if err := rows.Scan(&item.ID, &item.Name, &item.Status); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
