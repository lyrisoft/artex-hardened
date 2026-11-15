package server

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

func writeVisibleSkill(t *testing.T, root, dir, body string) {
	t.Helper()
	path := filepath.Join(root, dir)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVisibleSkillLoaderPreservesValidCustomFormats(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"scalar", "---\nname: custom\ndescription: fixture\nmcps: 'alpha, beta'\nwhen_to_use: later\n---\nbody\n"},
		{"list", "---\nname: custom\ndescription: fixture\nmcps: [alpha, beta]\nwhenToUse: later\n---\nbody\n"},
		{"legacy_mcp", "---\nname: custom\ndescription: fixture\nmcp: alpha\n---\nbody\n"},
		{"plain", "custom instructions without frontmatter\n"},
		{"empty_mcps_fallback", "---\nname: custom\nmcps: []\nmcp: alpha\n---\nbody\n"},
		{"crlf", "---\r\nname: custom\r\ndescription: fixture\r\nmcps: [alpha]\r\n---\r\nbody\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeVisibleSkill(t, root, "fixture", tc.body)
			legacy, err := skill.LoadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			got, err := loadVisibleSkills(root, []string{"fixture"})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.List(), legacy.List()) {
				t.Fatalf("custom format changed: got=%+v want=%+v", got.List(), legacy.List())
			}
		})
	}
}

func TestVisibleSkillLoaderRejectsMalformedMetadata(t *testing.T) {
	cases := map[string]string{
		"invalid_yaml":  "---\nname: fixture\ndescription: broken: value\nmcps: browser\n---\nbody\n",
		"unterminated":  "---\nname: fixture\nmcps: browser\nbody\n",
		"invalid_open":  "--- invalid\nname: fixture\n---\nbody\n",
		"mapping_mcp":   "---\nname: fixture\nmcps: {browser: true}\n---\nbody\n",
		"nested_list":   "---\nname: fixture\nmcps: [browser, {bad: value}]\n---\nbody\n",
		"duplicate_mcp": "---\nname: fixture\nmcps: browser\nmcps: other\n---\nbody\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeVisibleSkill(t, root, "fixture", body)
			reg, err := loadVisibleSkills(root, []string{"fixture"})
			if err == nil || reg != nil {
				t.Fatalf("malformed skill admitted: reg=%v err=%v", reg, err)
			}
		})
	}
	root := t.TempDir()
	writeVisibleSkill(t, root, "good", "---\nname: same\nmcps: [browser]\n---\nbody")
	writeVisibleSkill(t, root, "duplicate", "---\nname: same\nmcps: [other]\n---\nbody")
	if reg, err := loadVisibleSkills(root, []string{"good", "duplicate"}); err == nil || reg != nil {
		t.Fatal("duplicate display name admitted")
	}
	writeVisibleSkill(t, root, "unrelated", "---\nmcps: {broken\n---\nbody")
	if _, err := loadVisibleSkills(root, []string{"good"}); err != nil {
		t.Fatalf("unrelated skill affected visible catalog: %v", err)
	}
	for _, bad := range []string{"../escape", "/absolute", ".", "nested/name", `nested\name`} {
		if _, err := loadVisibleSkills(root, []string{bad}); err == nil {
			t.Fatalf("unsafe name admitted: %q", bad)
		}
	}
}
