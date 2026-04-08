package tools

import (
	"path/filepath"
	"strings"
)

// isInsideWorkspace checks if path is inside workspace, resolving
// symlinks to prevent traversal bypasses.
func isInsideWorkspace(path, workspace string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		return false
	}

	// Resolve symlinks. For new files EvalSymlinks fails, so
	// resolve the parent directory instead.
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	} else if resolved, err := filepath.EvalSymlinks(filepath.Dir(absPath)); err == nil {
		absPath = filepath.Join(resolved, filepath.Base(absPath))
	}
	if resolved, err := filepath.EvalSymlinks(absWorkspace); err == nil {
		absWorkspace = resolved
	}

	// Ensure trailing separator to prevent /tmp/agent matching
	// /tmp/agent-evil
	return strings.HasPrefix(absPath, absWorkspace+string(filepath.Separator)) ||
		absPath == absWorkspace
}
