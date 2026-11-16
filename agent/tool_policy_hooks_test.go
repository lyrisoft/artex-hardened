package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

func TestToolPolicyHookCoversDynamicAndDeferredCalls(t *testing.T) {
	denied := map[string]bool{"WebFetch": true, "Monitor": true, "mcp__fixture__scan": true}
	unavailable := false
	resolve := func(_ context.Context, _ string, in []actool.CoreTool) ([]actool.CoreTool, error) {
		if unavailable {
			return nil, errors.New("offline")
		}
		out := []actool.CoreTool{}
		for _, tool := range in {
			if !denied[tool.Name()] {
				out = append(out, tool)
			}
		}
		return out, nil
	}
	h := withToolPolicyHooks("worker", resolve, nil)
	for _, tc := range []struct {
		name, input string
		blocked     bool
	}{
		{"WebFetch", `{}`, true}, {"Monitor", `{}`, true}, {"web_search", `{}`, false},
		{"ExecuteExtraTool", `{"tool_name":"mcp__fixture__scan","params":{}}`, true},
		{"ExecuteExtraTool", `{"tool_name":"permitted","params":{}}`, false},
		{"ExecuteExtraTool", `{"tool_name":"ExecuteExtraTool","params":{"tool_name":"mcp__fixture__scan","params":{}}}`, true},
		{"ExecuteExtraTool", `{"tool_name":"ExecuteExtraTool","params":{"tool_name":"permitted","params":{}}}`, false},
		{"ExecuteExtraTool", `{}`, true}, {"ExecuteExtraTool", `invalid`, true},
	} {
		blocked, _, _ := h.PreToolUse(context.Background(), tc.name, []byte(tc.input))
		if blocked != tc.blocked {
			t.Fatalf("%s %s blocked=%v", tc.name, tc.input, blocked)
		}
	}
	unavailable = true
	if blocked, _, _ := h.PreToolUse(context.Background(), "web_search", []byte(`{}`)); !blocked {
		t.Fatal("store outage permitted SDK tool")
	}
}

func TestToolPolicyRechecksAfterModelRequest(t *testing.T) {
	available := true
	resolve := func(_ context.Context, _ string, in []actool.CoreTool) ([]actool.CoreTool, error) {
		if !available {
			return nil, errors.New("policy store went away")
		}
		return in, nil
	}
	turns, executed := 0, 0
	provider := captureUsageProvider{stream: func(_ context.Context, yield func(llm.StreamEvent, error) bool) {
		turns++
		events := []llm.StreamEvent{{Type: llm.SETextDelta, Text: "done"}, {Type: llm.SEMessageDelta, StopReason: "end_turn"}}
		if turns == 1 {
			available = false
			events = []llm.StreamEvent{{Type: llm.SEToolUseStart, ToolID: "probe", ToolName: "fixture_probe"}, {Type: llm.SEToolInputJSON, Text: `{}`}, {Type: llm.SEMessageDelta, StopReason: "tool_use"}}
		}
		for _, event := range events {
			if !yield(event, nil) {
				return
			}
		}
	}}
	probe := actool.Build(actool.Spec{Name: "fixture_probe", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		executed++
		return actool.Text("should not run"), nil
	}})
	_, _, err := captureRun(context.Background(), agentcore.Options{Provider: provider, Tools: []actool.CoreTool{probe}, Hooks: withToolPolicyHooks("worker", resolve, nil), PermissionMode: permission.ModeBypass, DisableBackgroundTasks: true, MaxTurns: 2}, "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	if executed != 0 {
		t.Fatal("tool ran after policy outage")
	}
	if turns < 2 {
		t.Fatal("fixture did not process a blocked tool result")
	}
}
