package agent

import (
	"context"
	"encoding/json"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// withToolPolicyHooks rechecks the current catalog on every harness tool call,
// including WebFetch, SDK-added WebSearch/background tools and deferred calls.
// Unknown tools retain legacy behavior; this is NOT team RBAC or a sandbox.
// The resolver is captured for the session so a later hook swap cannot bypass it.
func withToolPolicyHooks(agentKey string, resolve ToolResolveFunc, downstream harness.HookRunner) harness.HookRunner {
	if resolve == nil {
		return downstream
	}
	return &toolPolicyHooks{agentKey: agentKey, resolve: resolve, downstream: downstream}
}

type toolPolicyHooks struct {
	agentKey   string
	resolve    ToolResolveFunc
	downstream harness.HookRunner
}

func (h *toolPolicyHooks) allowed(ctx context.Context, name string) bool {
	if name == "" {
		return false
	}
	probe := actool.Build(actool.Spec{Name: name})
	resolved, err := h.resolve(WithNoDomainToolInjection(ctx), h.agentKey, []actool.CoreTool{probe})
	if err != nil {
		return false
	}
	for _, tool := range resolved {
		if tool.Name() == name {
			return true
		}
	}
	return false
}
func (h *toolPolicyHooks) allowedCall(ctx context.Context, name string, input []byte) bool {
	// A deferred invoker can itself be named as the deferred tool. Check every
	// nested name, not just the first one, and bound parsing work.
	for depth := 0; depth < 8; depth++ {
		if !h.allowed(ctx, name) {
			return false
		}
		if name != actool.ExecuteExtraToolName {
			return true
		}
		var inner struct {
			ToolName string          `json:"tool_name"`
			Params   json.RawMessage `json:"params"`
		}
		if json.Unmarshal(input, &inner) != nil || inner.ToolName == "" {
			return false
		}
		name, input = inner.ToolName, inner.Params
	}
	return false
}
func (h *toolPolicyHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if !h.allowedCall(ctx, name, input) {
		return true, "tool policy denied or unavailable", nil
	}
	if h.downstream == nil {
		return false, "", nil
	}
	block, msg, updated := h.downstream.PreToolUse(ctx, name, input)
	if !block && len(updated) > 0 && !h.allowedCall(ctx, name, updated) {
		return true, "tool policy denied or unavailable", nil
	}
	return block, msg, updated
}
func (h *toolPolicyHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.downstream != nil {
		h.downstream.PostToolUse(ctx, name, input, result, isErr)
	}
}
func (h *toolPolicyHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.downstream != nil {
		return h.downstream.Stop(ctx, messages)
	}
	return false, nil, ""
}
