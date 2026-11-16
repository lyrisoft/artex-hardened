package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func TestGoalScopePreservesCustomizedCatalogBindings(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config: %v", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("open synthetic database: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	oldResolve, oldPolicy := agent.ToolResolve(), agent.FindingTrafficBindingEnabled()
	t.Cleanup(func() { agent.SetToolResolve(oldResolve); agent.SetFindingTrafficBindingEnabled(oldPolicy) })
	wireTools(pg, nil)
	original, err := pg.GetTool("add_task_scope")
	if err != nil || original == nil {
		t.Fatalf("scope catalog: %v", err)
	}
	oldAgents, _ := json.Marshal(original.Agents)
	var customSchema map[string]any
	if err := json.Unmarshal(original.Schema, &customSchema); err != nil {
		t.Fatal(err)
	}
	customSchema["x-operator-note"] = "fixture-customization"
	customSchemaJSON, _ := json.Marshal(customSchema)
	t.Cleanup(func() {
		if err := pg.UpdateTool(original.Key, original.Description, original.Schema, oldAgents, original.Enabled); err != nil {
			t.Errorf("restore catalog: %v", err)
		}
	})
	var base []actool.CoreTool
	for _, tool := range agent.NewToolSet(nil, "").PlannerTools() {
		if tool.Name() == original.Key {
			base = append(base, tool)
		}
	}
	if len(base) != 1 {
		t.Fatal("scope tool missing from fixture")
	}
	set := func(agents []string, enabled bool) {
		t.Helper()
		b, _ := json.Marshal(agents)
		if err := pg.UpdateTool(original.Key, "custom operator description", customSchemaJSON, b, enabled); err != nil {
			t.Fatal(err)
		}
		wireTools(pg, nil)
	}
	has := func(agentKey string) bool {
		t.Helper()
		tools, err := agent.ToolResolve()(agent.WithNoDomainToolInjection(context.Background()), agentKey, base)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range tools {
			if tool.Name() == original.Key {
				if tool.Description() != "custom operator description" {
					t.Fatalf("operator description changed: %q", tool.Description())
				}
				if tool.InputSchema()["x-operator-note"] != "fixture-customization" {
					t.Fatal("operator schema customization changed")
				}
				return true
			}
		}
		return false
	}
	set([]string{"planner"}, true)
	row, err := pg.GetTool(original.Key)
	if err != nil || row.Description != "custom operator description" || !row.Enabled || len(row.Agents) != 1 || row.Agents[0] != "planner" {
		t.Fatalf("custom binding overwritten: %+v err=%v", row, err)
	}
	if !has("planner") || has("goals") {
		t.Fatal("existing customized binding was broadened")
	}
	set([]string{"goals"}, false)
	if has("goals") {
		t.Fatal("disabled customized tool was enabled")
	}
	set([]string{"goals"}, true)
	if !has("goals") {
		t.Fatal("explicit goal binding was not honored")
	}
}
