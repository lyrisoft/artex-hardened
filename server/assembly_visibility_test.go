package server

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Autumn-27/artex/db"
)

type visibilityFixture struct {
	fail  string
	calls []string
}

func (v *visibilityFixture) step(name string) error {
	v.calls = append(v.calls, name)
	if v.fail == name {
		return errors.New("synthetic " + name + " failure")
	}
	return nil
}
func (v *visibilityFixture) GetAgentByKey(string) (*db.Agent, error) {
	if err := v.step("agent"); err != nil {
		return nil, err
	}
	return &db.Agent{ID: 1}, nil
}
func (v *visibilityFixture) AgentSkillNames(int64) ([]string, error) {
	if err := v.step("skills"); err != nil {
		return nil, err
	}
	return []string{"fixture"}, nil
}
func (v *visibilityFixture) AgentVisible(int64, string) ([]int64, error) {
	if err := v.step("visibility"); err != nil {
		return nil, err
	}
	return []int64{7}, nil
}
func (v *visibilityFixture) ListMCP() ([]*db.MCPServer, error) {
	if err := v.step("mcps"); err != nil {
		return nil, err
	}
	return []*db.MCPServer{{ID: 7, Name: "fixture"}}, nil
}

func TestVisibilityInputsFailClosedBeforeMCPAssembly(t *testing.T) {
	for _, tc := range []struct {
		failure string
		calls   []string
	}{
		{"agent", []string{"agent"}},
		{"skills", []string{"agent", "skills"}},
		{"visibility", []string{"agent", "skills", "visibility"}},
		{"mcps", []string{"agent", "skills", "visibility", "mcps"}},
	} {
		t.Run(tc.failure, func(t *testing.T) {
			fixture := &visibilityFixture{fail: tc.failure}
			a, skills, ids, servers, err := loadAgentVisibility(fixture, "fixture")
			if err == nil || a != nil || skills != nil || ids != nil || servers != nil {
				t.Fatalf("partial visibility escaped: agent=%v skills=%v ids=%v servers=%v err=%v", a, skills, ids, servers, err)
			}
			if !reflect.DeepEqual(fixture.calls, tc.calls) {
				t.Fatalf("calls=%v want %v", fixture.calls, tc.calls)
			}
		})
	}
	fixture := &visibilityFixture{}
	a, skills, ids, servers, err := loadAgentVisibility(fixture, "fixture")
	if err != nil || a == nil || !reflect.DeepEqual(skills, []string{"fixture"}) || !reflect.DeepEqual(ids, []int64{7}) || len(servers) != 1 {
		t.Fatalf("healthy visibility: %v %v %v %v %v", a, skills, ids, servers, err)
	}
}

func TestVisibleSkillsMustAllLoadBeforeMCPAssembly(t *testing.T) {
	dir := t.TempDir()
	if reg, err := loadVisibleSkills(filepath.Join(dir, "absent"), nil); reg != nil || err != nil {
		t.Fatalf("no skills: %v %v", reg, err)
	}
	if reg, err := loadVisibleSkills(filepath.Join(dir, "absent"), []string{"fixture"}); reg != nil || err == nil {
		t.Fatal("unreadable skill directory was accepted")
	}
	skdir := filepath.Join(dir, "fixture")
	if err := os.Mkdir(skdir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skdir, "SKILL.md"), []byte("---\nname: fixture\ndescription: synthetic\nmcps: [browser]\n---\nfixture"), 0600); err != nil {
		t.Fatal(err)
	}
	reg, err := loadVisibleSkills(dir, []string{"fixture"})
	if err != nil || reg == nil {
		t.Fatalf("healthy skill: %v", err)
	}
	sk, ok := reg.Get("fixture")
	if !ok || !reflect.DeepEqual(sk.MCPs, []string{"browser"}) {
		t.Fatalf("skill metadata=%+v", sk)
	}
	if reg, err := loadVisibleSkills(dir, []string{"fixture", "missing"}); reg != nil || err == nil {
		t.Fatal("partially missing visible skills were accepted")
	}
}
