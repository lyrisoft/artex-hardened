package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// A malformed assigned skill must not turn a directly-visible, skill-gated MCP
// into a global tool or even contact it. Valid metadata keeps the existing
// deferred/unlock behavior. The MCP and all records are synthetic fixtures.
func TestMalformedSkillStopsMCPBeforeConnection(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	ag, err := pg.GetAgentByKey("planner")
	if err != nil || ag == nil {
		t.Fatalf("planner=%v err=%v", ag, err)
	}
	original, err := pg.AgentSkillNames(ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.SetAgentSkillVisibility(ag.ID, original); err != nil {
			t.Errorf("restore skill visibility: %v", err)
		}
	})
	if err := pg.SetAgentSkillVisibility(ag.ID, []string{"fixture_skill"}); err != nil {
		t.Fatal(err)
	}
	fake, hits := newSyntheticMCPServer(t)
	id, err := pg.SaveMCP(&db.MCPServer{Name: "fixture_policy", Transport: "http", URL: fake.URL, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pg.DeleteMCP(id); err != nil {
			t.Errorf("remove fixture MCP: %v", err)
		}
	})
	if err := pg.ToggleVisibility(ag.ID, "mcp", id, true); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "fixture_skill")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(file, []byte("---\nname: fixture\ndescription: broken: value\nmcps: fixture_policy\n---\nbody"), 0600); err != nil {
		t.Fatal(err)
	}
	old := agent.ToolAugment()
	t.Cleanup(func() { agent.SetToolAugment(old) })
	wireAgentAugment(pg, root, nil)
	tools, _, cleanup, err := agent.AugmentTools(context.Background(), "planner", nil)
	cleanup()
	if err == nil || len(tools) != 0 || hits.Load() != 0 {
		t.Fatalf("malformed metadata: tools=%d hits=%d err=%v", len(tools), hits.Load(), err)
	}
	if err := os.WriteFile(file, []byte("---\nname: fixture\ndescription: valid\nmcps: [fixture_policy]\n---\nbody"), 0600); err != nil {
		t.Fatal(err)
	}
	tools, def, cleanup, err := agent.AugmentTools(context.Background(), "planner", nil)
	defer cleanup()
	if err != nil || hits.Load() == 0 {
		t.Fatalf("valid metadata: hits=%d err=%v", hits.Load(), err)
	}
	const name = "mcp__fixture_policy__synthetic_probe"
	found := false
	for _, tool := range tools {
		if tool.Name() == name {
			found = true
		}
	}
	if !found || def.Unlock == nil || def.Unlock.Has(name) {
		t.Fatal("skill-gated MCP not present and locked")
	}
	def.UnlockSkill("fixture")
	if !def.Unlock.Has(name) {
		t.Fatal("valid skill did not unlock its MCP")
	}
}
