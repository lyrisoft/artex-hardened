package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ScopedToolEvent deliberately contains neither task descriptions nor tool
// input/output. The owner and workspace are bound by a disabled-by-default
// record, not inferred from a request or event. There is no running dispatcher
// for this path yet: an isolated executor is required before activation.
type ScopedToolEvent struct {
	TriggerID   int64
	WorkspaceID int64
	TaskID      int64
	ActivityID  int64
	AgentKey    string
	Tool        string
	IsError     bool
}

// scopedToolEventsSQL does not load descriptions, credentials, raw arguments or
// output. Every event is filtered by its stored owner, membership, agent and task
// assignments before any event data leaves PostgreSQL. A broken tool_names JSON
// value causes an error (deny), not a broader match.
const scopedToolEventsSQL = `
SELECT tr.id, w.id, t.id, r.id, a.key, r.tool, r.is_error
FROM security_scoped_trigger_bindings b
JOIN agent_triggers tr ON tr.id=b.trigger_id AND tr.enabled AND tr.on_tool_call
JOIN security_workspaces w ON w.id=b.workspace_id AND w.enabled
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id AND team.enabled
JOIN security_tenants tenant ON tenant.id=w.tenant_id AND tenant.enabled
JOIN security_principals p ON p.id=b.principal_id AND p.enabled
JOIN security_team_memberships m ON m.id=b.owner_membership_id AND m.principal_id=p.id AND m.team_id=team.id AND m.principal_auth_epoch=p.auth_epoch
JOIN agents a ON a.key=tr.agent_key AND a.enabled
JOIN security_workspace_agents wa ON wa.agent_id=a.id AND wa.workspace_id=w.id
JOIN security_workspace_tasks wt ON wt.workspace_id=w.id
JOIN tasks t ON t.id=wt.task_id AND t.deleted_at IS NULL
JOIN activity r ON r.exploration_id=t.exploration_id AND r.kind='tool_result' AND r.tool <> ''
WHERE b.enabled AND b.trigger_id=$1 AND b.workspace_id=$2 AND b.principal_id=$3
  AND m.role IN ('operator','manager') AND m.revoked_at IS NULL
  AND m.valid_from <= statement_timestamp() AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())
  AND r.id > $4 AND ($5::bigint = 0 OR r.id=$5)
  AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(COALESCE(NULLIF(tr.tool_names,''),'[]')::jsonb) AS selected(name)
              WHERE lower(selected.name)=lower(r.tool))
ORDER BY r.id LIMIT $6`

// ScopedToolEvents lists only metadata belonging to the bound workspace and
// principal. principalID MUST come from a verified service/human identity, never
// user data, a JWT claim without verification, an agent prompt or tool output.
// A caller must recheck with ScopedToolEventForDispatch immediately before any
// delivery. Queue persistence, leases and interrupt-on-revocation remain required.
func (d *DB) ScopedToolEvents(ctx context.Context, principalID, workspaceID, triggerID, afterID int64, limit int) ([]ScopedToolEvent, error) {
	if d == nil || d.DB == nil || principalID <= 0 || workspaceID <= 0 || triggerID <= 0 || afterID < 0 || limit < 1 || limit > 1000 {
		return nil, ErrWorkspaceAccessDenied
	}
	rows, err := d.QueryContext(ctx, scopedToolEventsSQL, triggerID, workspaceID, principalID, afterID, int64(0), limit)
	if err != nil {
		return nil, fmt.Errorf("query scoped trigger events: %w", err)
	}
	defer rows.Close()
	out := []ScopedToolEvent{}
	for rows.Next() {
		var e ScopedToolEvent
		if err := rows.Scan(&e.TriggerID, &e.WorkspaceID, &e.TaskID, &e.ActivityID, &e.AgentKey, &e.Tool, &e.IsError); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ScopedToolEventForDispatch fetches the event again under current membership,
// trigger and workspace state. A previously listed event is not a capability.
func (d *DB) ScopedToolEventForDispatch(ctx context.Context, principalID, workspaceID, triggerID, activityID int64) (*ScopedToolEvent, error) {
	if d == nil || d.DB == nil || principalID <= 0 || workspaceID <= 0 || triggerID <= 0 || activityID <= 0 {
		return nil, ErrWorkspaceAccessDenied
	}
	var e ScopedToolEvent
	err := d.QueryRowContext(ctx, scopedToolEventsSQL, triggerID, workspaceID, principalID, activityID-1, activityID, 1).
		Scan(&e.TriggerID, &e.WorkspaceID, &e.TaskID, &e.ActivityID, &e.AgentKey, &e.Tool, &e.IsError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrWorkspaceAccessDenied
	}
	if err != nil {
		return nil, fmt.Errorf("reauthorize scoped trigger event: %w", err)
	}
	return &e, nil
}
