package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSkillTools functionally exercises create_skill + update_skill_file against a
// temp skill dir (no DB needed — these tools only touch the filesystem).
func TestSkillTools(t *testing.T) {
	dir := t.TempDir()
	s := &Server{skillDir: dir}

	// create_skill writes a spec-compliant SKILL.md.
	in, _ := json.Marshal(map[string]any{
		"name": "my-skill", "description": "does X", "instructions": "## do\n1. a",
	})
	// Default and unacknowledged profiles must deny both creation and mutation
	// without changing the filesystem. Acknowledged advanced-lab mode is used
	// only below to exercise the legacy filesystem behavior in this temp dir.
	existing := filepath.Join(dir, "existing")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	existingFile := filepath.Join(existing, "SKILL.md")
	if err := os.WriteFile(existingFile, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	updateExisting, _ := json.Marshal(map[string]any{"name": "existing", "file": "SKILL.md", "content": "modified"})
	for _, profile := range []string{"", "pentest", "research", "advanced-lab", "invalid"} {
		t.Setenv("ARTEX_SECURITY_PROFILE", profile)
		t.Setenv("ARTEX_ADVANCED_LAB_ACK", "")
		if r, err := s.toolCreateSkill().Call(context.Background(), in, nil); err != nil || !r.IsError {
			t.Fatalf("%s: create_skill must be denied: err=%v result=%+v", profile, err, r)
		}
		if r, err := s.toolUpdateSkillFile().Call(context.Background(), updateExisting, nil); err != nil || !r.IsError {
			t.Fatalf("%s: update_skill_file must be denied: err=%v result=%+v", profile, err, r)
		}
		if _, err := os.Stat(filepath.Join(dir, "my-skill")); !os.IsNotExist(err) {
			t.Fatalf("%s: denied creation changed filesystem: %v", profile, err)
		}
		got, err := os.ReadFile(existingFile)
		if err != nil || string(got) != "original" {
			t.Fatalf("%s: denied update changed filesystem: %v %q", profile, err, got)
		}
	}
	t.Setenv("ARTEX_SECURITY_PROFILE", "advanced-lab")
	t.Setenv("ARTEX_ADVANCED_LAB_ACK", "I_UNDERSTAND_ISOLATED_LAB_ONLY")
	res, err := s.toolCreateSkill().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("create_skill: err=%v result=%+v", err, res)
	}
	md, err := os.ReadFile(filepath.Join(dir, "my-skill", "SKILL.md"))
	if err != nil {
		t.Fatalf("SKILL.md not written: %v", err)
	}
	if !strings.Contains(string(md), "name: my-skill") || !strings.Contains(string(md), "description: does X") || !strings.Contains(string(md), "1. a") {
		t.Fatalf("SKILL.md content:\n%s", md)
	}

	// creating the same skill again fails.
	if r, _ := s.toolCreateSkill().Call(context.Background(), in, nil); !r.IsError {
		t.Fatal("duplicate create should error")
	}

	// invalid name rejected.
	bad, _ := json.Marshal(map[string]any{"name": "Bad Name", "description": "x"})
	if r, _ := s.toolCreateSkill().Call(context.Background(), bad, nil); !r.IsError {
		t.Fatal("invalid skill name should error")
	}

	// update_skill_file writes a nested script; path traversal is rejected.
	up, _ := json.Marshal(map[string]any{"name": "my-skill", "file": "scripts/run.py", "content": "print(1)"})
	if r, err := s.toolUpdateSkillFile().Call(context.Background(), up, nil); err != nil || r.IsError {
		t.Fatalf("update_skill_file: err=%v result=%+v", err, r)
	}
	got, err := os.ReadFile(filepath.Join(dir, "my-skill", "scripts", "run.py"))
	if err != nil || string(got) != "print(1)" {
		t.Fatalf("nested file not written: %v %q", err, got)
	}
	evil, _ := json.Marshal(map[string]any{"name": "my-skill", "file": "../escape.txt", "content": "x"})
	if r, _ := s.toolUpdateSkillFile().Call(context.Background(), evil, nil); !r.IsError {
		t.Fatal("path traversal should be rejected")
	}
}
