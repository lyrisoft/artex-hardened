package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"sync"

	actool "github.com/Autumn-27/norma/tool"
)

// DeferredInfo carries the deferred-tools wiring an agent needs to build its
// Options: the MCP tool names whose schemas are withheld, the subset listed in the
// global system-prompt block (non-skill-gated), and the shared session unlock set.
// UnlockSkill unlocks a named skill's MCPs — hosts call it to rebuild the unlock set
// from history on a resumed session (design doc C2).
type DeferredInfo struct {
	toolResolve     ToolResolveFunc   // same snapshot used for assembly and per-call rechecks
	FindingGuidance string            // derived from the final permitted tools, including DB overrides
	Deferred        []string          // all MCP tool names (schema withheld)
	GlobalNames     []string          // MCP names to list in the system-prompt block
	Unlock          *actool.UnlockSet // shared call-gate; nil when no MCP tools
	UnlockSkill     func(skillName string)
}

// ToolAugmentFunc is the ToolAugment hook. If set, it returns the EXTRA tools
// an agent should see beyond its built-in base set — the agent's visible skills (packed into one Skill meta-tool)
// and visible MCP servers (expanded to mcp__server__tool). It also returns the
// DeferredInfo describing how those MCP tools are deferred/gated. The server wires
// it to the PG agent_visibility table. cleanup releases any spawned MCP clients;
// a visibility error stops assembly and invokes cleanup before returning.
//
// When nil, agents run with only their built-in tools — behavior is unchanged
// until a user assigns a skill/MCP to the agent in the UI.
type ToolAugmentFunc func(ctx context.Context, agentKey string) (extra []actool.CoreTool, def DeferredInfo, cleanup func(), err error)

// The hook is set by server wiring while restored tasks may already be
// assembling tools on other goroutines, so every access goes through the lock.
var (
	toolAugmentMu sync.RWMutex
	toolAugment   ToolAugmentFunc
)

// SetToolAugment installs (or, with nil, removes) the ToolAugment hook.
func SetToolAugment(f ToolAugmentFunc) {
	toolAugmentMu.Lock()
	toolAugment = f
	toolAugmentMu.Unlock()
}

// ToolAugment returns the current ToolAugment hook, or nil when none is set.
func ToolAugment() ToolAugmentFunc {
	toolAugmentMu.RLock()
	defer toolAugmentMu.RUnlock()
	return toolAugment
}

// AugmentTools returns base plus the agent's visible skill/MCP tools, the
// DeferredInfo, a cleanup func the caller must defer (closes MCP clients),
// and an error. The configured resolver filters known tools and decorates them.
func AugmentTools(ctx context.Context, agentKey string, base []actool.CoreTool) ([]actool.CoreTool, DeferredInfo, func(), error) {
	var (
		def     DeferredInfo
		cleanup = func() {}
		out     = base
	)
	// Check the catalog before augmenting: augment may start MCP subprocesses.
	// Keep this resolver for the full assembly so a hook swap cannot skip the
	// second check. A failure after augmentation releases any clients.
	resolve := ToolResolve()
	if resolve != nil {
		if _, err := resolve(ctx, agentKey, nil); err != nil {
			return nil, def, cleanup, fmt.Errorf("preflight tool policy: %w", err)
		}
	}
	// Copy each hook once under its lock, then call it outside the lock.
	if augment := ToolAugment(); augment != nil {
		var extra []actool.CoreTool
		var cl func()
		var err error
		extra, def, cl, err = augment(ctx, agentKey)
		if cl != nil {
			cleanup = cl
		}
		if err != nil {
			cleanup()
			return nil, DeferredInfo{}, func() {}, fmt.Errorf("augment tool visibility: %w", err)
		}
		if len(extra) > 0 {
			out = append(append([]actool.CoreTool{}, base...), extra...)
		}
	}
	// DB tools table has the final say on the built-in tools: drop the ones this
	// agent isn't bound to (or that are disabled) and swap in overridden
	// descriptions/schemas + default injection. MCP/skill/host tools have no row
	// and pass through untouched, so deferred/unlock wiring stays consistent.
	if resolve != nil {
		var err error
		out, err = resolve(ctx, agentKey, out)
		if err != nil {
			cleanup()
			return nil, DeferredInfo{}, func() {}, fmt.Errorf("resolve tool policy: %w", err)
		}
	}
	// Tool RAG (off by default): lexical projection of the bound list; only removes.
	out = applyToolRAG(ctx, agentKey, out, def.Deferred, bm25Score)
	out, def.FindingGuidance = findingWorkflowTools(agentKey, out)
	def.toolResolve = resolve
	// An explicit empty list must not become the SDK default tool set, even if
	// a projection above returned nil for its empty input.
	if out == nil {
		out = []actool.CoreTool{}
	}
	for i, t := range out {
		out[i] = guardPanic(t)
	}
	return out, def, cleanup, nil
}

// guardPanic turns a panicking tool handler into an ordinary tool error. The
// harness runs each tool on its own goroutine, so a panic inside a handler can't
// be recovered by the caller that started the run — it takes the whole process
// down, and on restart the agent replays the same call and crashes again. Applied
// last, so it covers every tool the agent can reach: domain, SDK, MCP and skill.
func guardPanic(t actool.CoreTool) actool.CoreTool { return &guardedTool{CoreTool: t} }

type guardedTool struct{ actool.CoreTool }

func (g *guardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] %s panic: %v\n%s", g.Name(), r, debug.Stack())
			res, err = actool.Errorf(fmt.Sprintf("internal error in tool %s: %v (this call has failed; try different arguments or another tool)", g.Name(), r)), nil
		}
	}()
	return g.CoreTool.Call(ctx, in, tc)
}
