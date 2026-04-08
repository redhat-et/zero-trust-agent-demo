package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SkillMeta holds the metadata from a SKILL.md frontmatter.
type SkillMeta struct {
	Name        string
	Description string
	Dir         string
}

// Discover scans the skills directory for subdirectories containing
// SKILL.md files and returns their metadata.
func Discover(skillsDir string) ([]SkillMeta, error) {
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read skills directory: %w", err)
	}

	var skills []SkillMeta
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillFile := filepath.Join(skillsDir, entry.Name(), "SKILL.md")
		if _, err := os.Stat(skillFile); os.IsNotExist(err) {
			continue
		}

		meta, err := parseFrontmatter(skillFile)
		if err != nil {
			continue
		}
		meta.Dir = filepath.Join(skillsDir, entry.Name())
		skills = append(skills, meta)
	}

	return skills, nil
}

// LoadContent reads the full content of a skill's SKILL.md file.
func LoadContent(skillsDir, name string) (string, error) {
	// Validate skill name to prevent path traversal
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("invalid skill name: %q", name)
	}

	path := filepath.Join(skillsDir, name, "SKILL.md")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("skill '%s' not found: %w", name, err)
	}
	return fmt.Sprintf("=== SKILL: %s ===\n%s", name, string(data)), nil
}

// BuildSummary creates a text block listing all available skills.
func BuildSummary(skills []SkillMeta) string {
	if len(skills) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\nAvailable skills (call load_skill to get full instructions):\n")
	for _, s := range skills {
		fmt.Fprintf(&sb, "  - %s: %s\n", s.Name, s.Description)
	}
	return sb.String()
}

// parseFrontmatter extracts name and description from YAML
// frontmatter in a SKILL.md file.
func parseFrontmatter(path string) (SkillMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SkillMeta{}, err
	}

	content := string(data)
	if !strings.HasPrefix(content, "---") {
		return SkillMeta{}, fmt.Errorf("no frontmatter found")
	}

	end := strings.Index(content[3:], "---")
	if end == -1 {
		return SkillMeta{}, fmt.Errorf("unclosed frontmatter")
	}

	frontmatter := content[3 : end+3]
	meta := SkillMeta{}

	for _, line := range strings.Split(frontmatter, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			meta.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		}
		if strings.HasPrefix(line, "description:") {
			meta.Description = strings.TrimSpace(strings.TrimPrefix(line, "description:"))
		}
	}

	if meta.Name == "" {
		return SkillMeta{}, fmt.Errorf("skill has no name")
	}

	return meta, nil
}
