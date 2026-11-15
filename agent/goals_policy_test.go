package agent

import (
	"context"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type goalPolicyProvider struct{ request llm.CompletionRequest }

func (p *goalPolicyProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.request = req
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "done"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
	}
}
func (p *goalPolicyProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	panic("streaming fixture only")
}

func TestGoalScopePromptTracksResolvedTools(t *testing.T) {
	old := ToolResolve()
	t.Cleanup(func() { SetToolResolve(old) })
	for _, allow := range []bool{false, true} {
		SetToolResolve(func(_ context.Context, _ string, tools []actool.CoreTool) ([]actool.CoreTool, error) {
			out := make([]actool.CoreTool, 0, len(tools))
			for _, tool := range tools {
				if allow || tool.Name() != "add_task_scope" {
					out = append(out, tool)
				}
			}
			return out, nil
		})
		p := &goalPolicyProvider{}
		DecomposeGoalsWithProvider(context.Background(), p, t.TempDir(), "synthetic.invalid", "", &db.AssetStore{}, nil, 1, false, 0, nil)
		hasTool := false
		for _, tool := range p.request.Tools {
			if tool.Name == "add_task_scope" {
				hasTool = true
			}
		}
		hasTail := strings.Contains(strings.Join(p.request.System, "\n"), goalsScopeTail)
		if hasTool != allow || hasTail != allow {
			t.Fatalf("allow=%v tool=%v scope prompt=%v", allow, hasTool, hasTail)
		}
	}
}
