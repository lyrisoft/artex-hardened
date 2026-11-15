package server

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
)

type fakeScopedLookup struct {
	event       *db.ScopedToolEvent
	err         error
	calls       int
	afterLookup func()
}

func (f *fakeScopedLookup) ScopedToolEventForDispatch(context.Context, int64, int64, int64, int64) (*db.ScopedToolEvent, error) {
	f.calls++
	if f.afterLookup != nil {
		f.afterLookup()
	}
	return f.event, f.err
}

func TestScopedTriggerDispatchReauthorizesAndDeniesRevocation(t *testing.T) {
	event := &db.ScopedToolEvent{TriggerID: 3, WorkspaceID: 2, ActivityID: 4, TaskID: 5, AgentKey: "synthetic", Tool: "scan"}
	lookup := &fakeScopedLookup{event: event}
	delivered := 0
	sink := func(_ context.Context, e db.ScopedToolEvent) error {
		delivered++
		if e != *event {
			t.Fatalf("event=%+v", e)
		}
		return nil
	}
	if err := dispatchScopedToolEvent(context.Background(), lookup, 1, 2, 3, 4, sink); err != nil || delivered != 1 || lookup.calls != 1 {
		t.Fatalf("delivery=%d lookup=%d err=%v", delivered, lookup.calls, err)
	}
	lookup.err = db.ErrWorkspaceAccessDenied
	if err := dispatchScopedToolEvent(context.Background(), lookup, 1, 2, 3, 4, sink); !errors.Is(err, db.ErrWorkspaceAccessDenied) || delivered != 1 {
		t.Fatalf("revoked delivered=%d err=%v", delivered, err)
	}
	lookup.err = nil
	lookup.event = &db.ScopedToolEvent{TriggerID: 3, WorkspaceID: 99, ActivityID: 4, TaskID: 5, AgentKey: "synthetic", Tool: "scan"}
	if err := dispatchScopedToolEvent(context.Background(), lookup, 1, 2, 3, 4, sink); err == nil || delivered != 1 {
		t.Fatal("mismatched event delivered")
	}
	ctx, cancel := context.WithCancel(context.Background())
	lookup.event = event
	lookup.afterLookup = cancel
	if err := dispatchScopedToolEvent(ctx, lookup, 1, 2, 3, 4, sink); !errors.Is(err, context.Canceled) || delivered != 1 {
		t.Fatalf("cancelled delivered=%d err=%v", delivered, err)
	}
}
