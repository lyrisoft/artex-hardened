package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/skill"
	"gopkg.in/yaml.v3"
)

// strictMCPNames preserves the SDK's scalar/comma-list and YAML string-list
// forms while rejecting malformed values instead of silently discarding them.
type strictMCPNames []string

func (s *strictMCPNames) UnmarshalYAML(node *yaml.Node) error {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode; depth++ {
		if depth >= 16 {
			return fmt.Errorf("MCP alias nesting too deep")
		}
		node = node.Alias
	}
	if node == nil {
		return fmt.Errorf("invalid MCP value")
	}
	if node.Tag == "!!null" {
		*s = nil
		return nil
	}
	var parts []string
	switch node.Kind {
	case yaml.ScalarNode:
		var v string
		if err := node.Decode(&v); err != nil {
			return fmt.Errorf("invalid MCP name: %w", err)
		}
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "[")
		v = strings.TrimSuffix(v, "]")
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(strings.Trim(part, `"' `)); p != "" {
				parts = append(parts, p)
			}
		}
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return fmt.Errorf("invalid MCP list: %w", err)
		}
		for _, v := range list {
			if p := strings.TrimSpace(v); p != "" {
				parts = append(parts, p)
			}
		}
	default:
		return fmt.Errorf("MCP declaration must be a string or list of strings")
	}
	*s = parts
	return nil
}

type strictSkillFrontmatter struct {
	Name            string         `yaml:"name"`
	Description     string         `yaml:"description"`
	License         string         `yaml:"license"`
	Compatibility   string         `yaml:"compatibility"`
	WhenToUse       string         `yaml:"whenToUse"`
	WhenToUseLegacy string         `yaml:"when_to_use"`
	MCPs            strictMCPNames `yaml:"mcps"`
	MCP             strictMCPNames `yaml:"mcp"`
}

// parseVisibleSkill consumes the same bytes for policy metadata and the skill
// snapshot. It accepts custom skills without frontmatter and the SDK's legacy
// metadata aliases, but refuses malformed or unterminated YAML. Skill files and
// their executable content still require an independent integrity boundary.
func parseVisibleSkill(raw []byte, directory string) (skill.Skill, error) {
	text := string(raw)
	candidate := strings.TrimLeft(text, "\ufeff \t\r\n")
	out := skill.Skill{Dir: directory}
	body := text
	if strings.HasPrefix(candidate, "---") {
		lines := strings.Split(candidate, "\n")
		if strings.TrimSpace(lines[0]) != "---" {
			return out, fmt.Errorf("invalid skill frontmatter opening")
		}
		end := -1
		for i := 1; i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "---" {
				end = i
				break
			}
		}
		if end < 0 {
			return out, fmt.Errorf("unclosed skill frontmatter")
		}
		var fm strictSkillFrontmatter
		if err := yaml.Unmarshal([]byte(strings.Join(lines[1:end], "\n")), &fm); err != nil {
			return out, fmt.Errorf("invalid skill frontmatter: %w", err)
		}
		out.Name = fm.Name
		out.Description = fm.Description
		out.License = fm.License
		out.Compatibility = fm.Compatibility
		out.WhenToUse = fm.WhenToUse
		if out.WhenToUse == "" {
			out.WhenToUse = fm.WhenToUseLegacy
		}
		out.MCPs = []string(fm.MCPs)
		if out.MCPs == nil {
			out.MCPs = []string(fm.MCP)
		}
		body = strings.Join(lines[end+1:], "\n")
	}
	if out.Name == "" {
		out.Name = filepath.Base(directory)
	}
	out.Instructions = strings.TrimSpace(body)
	return out, nil
}

// loadVisibleSkills reads only assigned directories, once each. Duplicate
// display names are rejected rather than silently replacing a skill that might
// own an MCP gate. An unrelated malformed skill cannot break another agent.
func loadVisibleSkills(dir string, names []string) (*skill.Registry, error) {
	if len(names) == 0 {
		return nil, nil
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	seen := map[string]bool{}
	reg := skill.NewRegistry()
	for _, name := range sorted {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			return nil, fmt.Errorf("invalid visible skill name")
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("visible skill %q could not be loaded", name)
		}
		raw, err := os.ReadFile(filepath.Join(path, "SKILL.md"))
		if err != nil {
			return nil, fmt.Errorf("visible skill %q could not be loaded: %w", name, err)
		}
		sk, err := parseVisibleSkill(raw, path)
		if err != nil {
			return nil, fmt.Errorf("visible skill %q: %w", name, err)
		}
		if _, ok := reg.Get(sk.Name); ok {
			return nil, fmt.Errorf("duplicate visible skill name %q", sk.Name)
		}
		reg.Add(sk)
	}
	return reg, nil
}
