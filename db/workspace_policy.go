package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// WorkspaceAction is an action-specific eligibility check, never a bearer
// capability. This foundation is inactive and is not wired into existing HTTP
// routes or the shared-process runtime. The caller must authenticate the actor,
// check the resource in the same transaction as the operation and enforce all
// executor, target, evidence and approval requirements before activation.
type WorkspaceAction string

const (
	ActionAgentRead                WorkspaceAction = "agent.read"
	ActionAgentCreate              WorkspaceAction = "agent.create"
	ActionAgentUpdate              WorkspaceAction = "agent.update"
	ActionAgentDelete              WorkspaceAction = "agent.delete"
	ActionTaskRead                 WorkspaceAction = "task.read"
	ActionTaskCreate               WorkspaceAction = "task.create"
	ActionTaskUpdate               WorkspaceAction = "task.update"
	ActionTaskDelete               WorkspaceAction = "task.delete"
	ActionTaskSchedule             WorkspaceAction = "task.schedule"
	ActionTaskExecute              WorkspaceAction = "task.execute"
	ActionEvidenceRead             WorkspaceAction = "evidence.read"
	ActionEvidenceWrite            WorkspaceAction = "evidence.write"
	ActionSecretRead               WorkspaceAction = "secret.read"
	ActionSecretLease              WorkspaceAction = "secret.lease"
	ActionToolInvoke               WorkspaceAction = "tool.invoke"
	ActionMCPInvoke                WorkspaceAction = "mcp.invoke"
	ActionApprovalDecide           WorkspaceAction = "approval.decide"
	ActionProtectedDetectionModify WorkspaceAction = "detection.protected.modify"
)

type WorkspaceResource struct {
	AgentID int64
	TaskID  int64
}

// AuthorizeWorkspaceAction resolves the actor's current membership and the
// specific agent/task assignment together, using data from the database rather
// than supplied roles or team labels. principalID must come from an independently
// verified identity. A successful result is preliminary only: this function must
// not be used to expose child evidence, issue credentials, dispatch a tool, make
// an approval decision, or start work. Those operations deny until their resource
// ownership, authorization, target policy and isolated execution gates exist.
func (d *DB) AuthorizeWorkspaceAction(ctx context.Context, principalID, workspaceID int64, action WorkspaceAction, resource WorkspaceResource) error {
	if d == nil || d.DB == nil || principalID <= 0 || workspaceID <= 0 || resource.AgentID < 0 || resource.TaskID < 0 {
		return ErrWorkspaceAccessDenied
	}
	needAgent, needTask := false, false
	switch action {
	case ActionAgentRead, ActionAgentUpdate, ActionAgentDelete:
		needAgent = true
	case ActionTaskRead, ActionTaskUpdate, ActionTaskDelete:
		needTask = true
	case ActionAgentCreate, ActionTaskCreate:
		// New resources have no assigned ID yet.
	default:
		// Includes scheduling, execution, evidence, secrets, tool/MCP calls,
		// protected detections, approvals and all unknown future actions.
		return ErrWorkspaceAccessDenied
	}
	if (needAgent != (resource.AgentID > 0)) || (needTask != (resource.TaskID > 0)) {
		return ErrWorkspaceAccessDenied
	}
	var kind, role string
	var agentOK, taskOK bool
	err := d.QueryRowContext(ctx, `
SELECT p.kind, m.role,
 EXISTS(SELECT 1 FROM security_workspace_agents wa JOIN agents a ON a.id=wa.agent_id WHERE wa.workspace_id=w.id AND a.id=$3),
 EXISTS(SELECT 1 FROM security_workspace_tasks wt JOIN tasks t ON t.id=wt.task_id AND t.deleted_at IS NULL WHERE wt.workspace_id=w.id AND t.id=$4)
FROM security_workspaces w
JOIN security_teams team ON team.id=w.team_id AND team.tenant_id=w.tenant_id
JOIN security_tenants tenant ON tenant.id=w.tenant_id
JOIN security_team_memberships m ON m.team_id=team.id
JOIN security_principals p ON p.id=m.principal_id AND m.principal_auth_epoch=p.auth_epoch
WHERE w.id=$1 AND p.id=$2 AND w.enabled AND team.enabled AND tenant.enabled AND p.enabled
 AND m.revoked_at IS NULL AND m.valid_from <= statement_timestamp()
 AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())`, workspaceID, principalID, resource.AgentID, resource.TaskID).
		Scan(&kind, &role, &agentOK, &taskOK)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrWorkspaceAccessDenied
	}
	if err != nil {
		return fmt.Errorf("authorize workspace action: %w", err)
	}
	if (needAgent && !agentOK) || (needTask && !taskOK) {
		return ErrWorkspaceAccessDenied
	}
	switch action {
	case ActionAgentRead, ActionTaskRead:
		if role == "viewer" || role == "operator" || role == "manager" || role == "approver" {
			return nil
		}
	case ActionAgentCreate, ActionAgentUpdate, ActionAgentDelete, ActionTaskDelete:
		if kind == "human" && role == "manager" {
			return nil
		}
	case ActionTaskCreate, ActionTaskUpdate:
		if role == "operator" || role == "manager" {
			return nil
		}
	}
	return ErrWorkspaceAccessDenied
}
