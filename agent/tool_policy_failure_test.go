package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

func TestToolPolicyFailureBeforeAndAfterAugment(t *testing.T) {
	oldAugment, oldResolve := ToolAugment(), ToolResolve()
	t.Cleanup(func() { SetToolAugment(oldAugment); SetToolResolve(oldResolve) })
	unavailable := errors.New("synthetic policy outage")
	for _, failAt := range []int{1, 2} {
		calls, starts, closes := 0, 0, 0
		SetToolResolve(func(context.Context, string, []actool.CoreTool) ([]actool.CoreTool, error) {
			calls++
			if calls == failAt {
				return nil, unavailable
			}
			return nil, nil
		})
		SetToolAugment(func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func(), error) {
			starts++
			return actool.DefaultTools(), DeferredInfo{}, func() { closes++ }, nil
		})
		got, _, cleanup, err := AugmentTools(context.Background(), "worker", actool.DefaultTools())
		cleanup()
		if !errors.Is(err, unavailable) || len(got) != 0 {
			t.Fatalf("failure %d: tools=%d err=%v", failAt, len(got), err)
		}
		wantStarted := failAt - 1
		if starts != wantStarted || closes != wantStarted {
			t.Fatalf("failure %d: started=%d closed=%d", failAt, starts, closes)
		}
	}
}

func TestToolPolicyFailureStopsModelAndSDKInjection(t *testing.T) {
	oldAugment, oldResolve := ToolAugment(), ToolResolve()
	t.Cleanup(func() { SetToolAugment(oldAugment); SetToolResolve(oldResolve) })
	SetToolAugment(nil)
	unavailable := errors.New("synthetic policy outage")
	SetToolResolve(func(context.Context, string, []actool.CoreTool) ([]actool.CoreTool, error) { return nil, unavailable })
	invoked := false
	provider := captureUsageProvider{stream: func(_ context.Context, _ func(llm.StreamEvent, error) bool) { invoked = true }}
	chat := NewChatAgent(provider, "fixture", t.TempDir(), nil, 0)
	chat.SetWebSearch(WebSearchOpts{Enabled: true})
	if _, err := chat.Chat(context.Background(), "worker", "fixture", "test", 1, 0, true, nil); !errors.Is(err, unavailable) {
		t.Fatalf("chat error=%v", err)
	}
	if got := DecomposeGoalsWithProvider(context.Background(), provider, t.TempDir(), "synthetic goal", "", nil, nil, 0, false, 0, nil); got != nil {
		t.Fatalf("goals=%v, want no result", got)
	}
	if invoked {
		t.Fatal("model was invoked despite unavailable policy")
	}
}

func TestEmptyResolvedToolsDoNotRestoreSDKDefaults(t *testing.T) {
	oldAugment, oldResolve := ToolAugment(), ToolResolve()
	t.Cleanup(func() { SetToolAugment(oldAugment); SetToolResolve(oldResolve) })
	SetToolAugment(nil)
	SetToolResolve(func(context.Context, string, []actool.CoreTool) ([]actool.CoreTool, error) { return nil, nil })
	tools, _, cleanup, err := AugmentTools(context.Background(), "worker", actool.DefaultTools())
	defer cleanup()
	if err != nil || tools == nil || len(tools) != 0 {
		t.Fatalf("tools=%v err=%v", tools, err)
	}
}

func TestVisibilityFailureStopsChatAndCleansUp(t *testing.T) {
	oldAugment, oldResolve := ToolAugment(), ToolResolve()
	t.Cleanup(func() { SetToolAugment(oldAugment); SetToolResolve(oldResolve) })
	unavailable := errors.New("synthetic visibility outage")
	SetToolResolve(func(_ context.Context, _ string, in []actool.CoreTool) ([]actool.CoreTool, error) { return in, nil })
	cleaned, invoked := false, false
	SetToolAugment(func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func(), error) {
		return actool.DefaultTools(), DeferredInfo{}, func() { cleaned = true }, unavailable
	})
	provider := captureUsageProvider{stream: func(_ context.Context, _ func(llm.StreamEvent, error) bool) { invoked = true }}
	chat := NewChatAgent(provider, "fixture", t.TempDir(), nil, 0)
	_, err := chat.Chat(context.Background(), "worker", "fixture", "test", 1, 0, false, nil)
	if !errors.Is(err, unavailable) || !cleaned || invoked {
		t.Fatalf("err=%v cleaned=%v invoked=%v", err, cleaned, invoked)
	}
}
