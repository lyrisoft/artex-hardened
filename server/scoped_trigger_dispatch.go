package server

import (
	"context"
	"errors"

	"github.com/Autumn-27/artex/db"
)

// scopedToolEventLookup is implemented by the database's principal-scoped,
// metadata-only query. The dispatcher is intentionally not wired to the legacy
// shared-process runner: an independently isolated executor is still required.
type scopedToolEventLookup interface {
	ScopedToolEventForDispatch(context.Context, int64, int64, int64, int64) (*db.ScopedToolEvent, error)
}

// dispatchScopedToolEvent re-fetches and reauthorizes immediately before calling
// a trusted sink. It does not implement a durable queue, exactly-once delivery,
// active-lease interruption, target authorization, or an isolated executor. The
// principal ID must come from verified server-side authentication, not an event.
func dispatchScopedToolEvent(ctx context.Context, lookup scopedToolEventLookup, principalID, workspaceID, triggerID, activityID int64, sink func(context.Context, db.ScopedToolEvent) error) error {
	if lookup == nil || sink == nil || ctx == nil || principalID <= 0 || workspaceID <= 0 || triggerID <= 0 || activityID <= 0 {
		return db.ErrWorkspaceAccessDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	event, err := lookup.ScopedToolEventForDispatch(ctx, principalID, workspaceID, triggerID, activityID)
	if err != nil {
		return err
	}
	if event == nil || event.WorkspaceID != workspaceID || event.TriggerID != triggerID || event.ActivityID != activityID || event.TaskID <= 0 || event.AgentKey == "" || event.Tool == "" {
		return errors.New("invalid scoped trigger event")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return sink(ctx, *event)
}
