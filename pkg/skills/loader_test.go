package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverSkills(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "test-skill")
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: test-skill\ndescription: A test skill for unit testing\n---\n\n# Test skill\n\nDo something useful.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	skills, err := Discover(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(skills) != 1 {
		t.Fatalf("expected 1 skill, got %d", len(skills))
	}
	if skills[0].Name != "test-skill" {
		t.Fatalf("expected name test-skill, got %q", skills[0].Name)
	}
	if skills[0].Description == "" {
		t.Fatal("expected non-empty description")
	}
}

func TestDiscoverSkillsEmpty(t *testing.T) {
	dir := t.TempDir()
	skills, err := Discover(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(skills) != 0 {
		t.Fatalf("expected 0 skills, got %d", len(skills))
	}
}

func TestDiscoverSkillsNoDir(t *testing.T) {
	skills, err := Discover("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(skills) != 0 {
		t.Fatalf("expected 0 skills, got %d", len(skills))
	}
}

func TestLoadSkillContent(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "my-skill")
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "---\nname: my-skill\ndescription: My test skill\n---\n\n# My skill\n\nStep 1: Do this\nStep 2: Do that\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := LoadContent(dir, "my-skill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty content")
	}
	if len(result) < 20 {
		t.Fatalf("content too short: %q", result)
	}
}

func TestLoadSkillContentNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadContent(dir, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent skill")
	}
}

func TestBuildSkillSummary(t *testing.T) {
	skills := []SkillMeta{
		{Name: "code-review", Description: "Review code for bugs"},
		{Name: "pdf-summary", Description: "Convert and summarize PDFs"},
	}

	summary := BuildSummary(skills)
	if summary == "" {
		t.Fatal("expected non-empty summary")
	}
	if !strings.Contains(summary, "code-review") {
		t.Fatal("expected code-review in summary")
	}
	if !strings.Contains(summary, "pdf-summary") {
		t.Fatal("expected pdf-summary in summary")
	}
}
