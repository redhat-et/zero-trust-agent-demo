# zt-agent phase 2 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add agentic tool-use loop, built-in tools, and SKILL.md
loading to zt-agent so the LLM can iteratively call tools driven
by skill instructions.

**Architecture:** New `pkg/tools` (registry, loop, built-in tools)
and `pkg/skills` (SKILL.md loader) packages. Extend `pkg/llm`
with `CompleteWithTools` for both Anthropic and OpenAI providers.
Wire into `serve.go` via `agent-config.yaml`. Backward compatible
— no config means phase 1 single-shot mode.

**Tech Stack:** Go 1.25, Anthropic SDK (tool_use), OpenAI-compatible
API (function calling), existing shared packages.

---

## File structure

| Action | Path | Responsibility |
| ------ | ---- | -------------- |
| Create | `pkg/llm/tools.go` | Message, ToolDefinition, Response, ToolCall types |
| Modify | `pkg/llm/provider.go` | Add CompleteWithTools to Provider interface |
| Modify | `pkg/llm/anthropic.go` | Implement CompleteWithTools for Anthropic |
| Modify | `pkg/llm/openai_compat.go` | Implement CompleteWithTools for OpenAI |
| Create | `pkg/llm/tools_test.go` | Tests for type marshaling |
| Create | `pkg/tools/tool.go` | Tool interface, ToolResult type |
| Create | `pkg/tools/registry.go` | Tool registry with allowed filter |
| Create | `pkg/tools/hooks.go` | Hook interface (defined, nil default) |
| Create | `pkg/tools/loop.go` | RunToolLoop agentic loop |
| Create | `pkg/tools/loop_test.go` | Tests for the loop |
| Create | `pkg/tools/exec.go` | exec tool with deny patterns |
| Create | `pkg/tools/exec_test.go` | Tests for exec deny patterns |
| Create | `pkg/tools/webfetch.go` | web_fetch tool |
| Create | `pkg/tools/readfile.go` | read_file tool |
| Create | `pkg/tools/writefile.go` | write_file tool |
| Create | `pkg/tools/fetchdoc.go` | fetch_document tool |
| Create | `pkg/skills/loader.go` | SKILL.md discovery and loading |
| Create | `pkg/skills/loader_test.go` | Tests for skill loader |
| Create | `zt-agent/cmd/agentconfig.go` | agent-config.yaml loading |
| Modify | `zt-agent/cmd/serve.go` | Wire tools, skills, loop into processLLM |
| Create | `zt-agent/testdata/research-agent/agent-config.yaml` | Test fixture |
| Create | `zt-agent/testdata/research-agent/system-prompt.txt` | Test fixture |
| Create | `zt-agent/testdata/research-agent/agent-card.json` | Test fixture |
| Create | `zt-agent/testdata/research-agent/skills/pdf-summary/SKILL.md` | Test skill |

---

### Task 1: LLM tool-use types

**Files:**

- Create: `pkg/llm/tools.go`
- Create: `pkg/llm/tools_test.go`
- Modify: `pkg/llm/provider.go`

- [ ] **Step 1: Write failing test for Message type**

`pkg/llm/tools_test.go`:

```go
package llm

import (
	"encoding/json"
	"testing"
)

func TestToolDefinitionJSON(t *testing.T) {
	td := ToolDefinition{
		Name:        "read_file",
		Description: "Read a file and return its contents",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
			"required": []string{"path"},
		},
	}

	data, err := json.Marshal(td)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundtrip ToolDefinition
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if roundtrip.Name != "read_file" {
		t.Fatalf("expected read_file, got %q", roundtrip.Name)
	}
}

func TestResponseWithToolCalls(t *testing.T) {
	resp := &Response{
		StopReason: StopReasonToolUse,
		Content:    "I'll read the file.",
		ToolCalls: []ToolCall{
			{
				ID:   "tc_001",
				Name: "read_file",
				Args: map[string]any{"path": "main.go"},
			},
		},
	}

	if !resp.HasToolCalls() {
		t.Fatal("expected HasToolCalls to be true")
	}
}

func TestResponseWithoutToolCalls(t *testing.T) {
	resp := &Response{
		StopReason: StopReasonEndTurn,
		Content:    "Here is the summary.",
	}

	if resp.HasToolCalls() {
		t.Fatal("expected HasToolCalls to be false")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/llm/ -run TestToolDefinition -v`
Expected: FAIL — types not defined.

- [ ] **Step 3: Create the types**

`pkg/llm/tools.go`:

```go
package llm

// StopReason indicates why the LLM stopped generating.
type StopReason string

const (
	StopReasonEndTurn StopReason = "end_turn"
	StopReasonToolUse StopReason = "tool_use"
)

// ToolDefinition describes a tool available to the LLM.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ToolCall represents the LLM's request to invoke a tool.
type ToolCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// ToolResultContent carries the result of a tool execution
// back to the LLM.
type ToolResultContent struct {
	ToolUseID string `json:"tool_use_id"`
	Output    string `json:"output"`
	IsError   bool   `json:"is_error,omitempty"`
}

// Message represents a conversation message for multi-turn
// tool-use interactions.
type Message struct {
	Role        string              // "user", "assistant", "tool"
	Content     string              // text content (for user/assistant)
	ToolCalls   []ToolCall          // tool calls (assistant only)
	ToolResults []ToolResultContent // tool results (tool role only)
}

// Response is the LLM's reply from CompleteWithTools.
type Response struct {
	StopReason StopReason
	Content    string     // text content (may be empty if only tool calls)
	ToolCalls  []ToolCall // tool calls (empty if end_turn)
}

// HasToolCalls returns true if the response contains tool call
// requests.
func (r *Response) HasToolCalls() bool {
	return len(r.ToolCalls) > 0
}
```

- [ ] **Step 4: Add CompleteWithTools to Provider interface**

Modify `pkg/llm/provider.go`:

```go
package llm

import "context"

// Provider defines the interface for LLM providers
type Provider interface {
	// Complete sends a message to the LLM and returns the response
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)

	// CompleteWithTools sends a multi-turn conversation with tool
	// definitions and returns a response that may contain tool calls.
	CompleteWithTools(ctx context.Context, messages []Message,
		tools []ToolDefinition) (*Response, error)

	// Model returns the configured model name
	Model() string

	// ProviderName returns the name of the LLM provider
	ProviderName() string
}
```

Note: This will break the build because `AnthropicProvider` and
`OpenAICompatProvider` don't implement `CompleteWithTools` yet.
Add stub implementations to both providers to keep compiling:

Add to `pkg/llm/anthropic.go`:

```go
// CompleteWithTools implements tool-use conversations.
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	return nil, fmt.Errorf("CompleteWithTools not yet implemented for Anthropic")
}
```

Add to `pkg/llm/openai_compat.go`:

```go
// CompleteWithTools implements tool-use conversations.
func (p *OpenAICompatProvider) CompleteWithTools(ctx context.Context, messages []Message, tools []ToolDefinition) (*Response, error) {
	return nil, fmt.Errorf("CompleteWithTools not yet implemented for OpenAI")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/llm/ -v`
Expected: All tests PASS (including existing tests).

- [ ] **Step 6: Verify full build**

Run: `go build ./...`
Expected: Compiles successfully (stubs satisfy interface).

- [ ] **Step 7: Commit**

```bash
git add pkg/llm/tools.go pkg/llm/tools_test.go pkg/llm/provider.go \
       pkg/llm/anthropic.go pkg/llm/openai_compat.go
git commit -s -m "feat(llm): add tool-use types and CompleteWithTools interface"
```

---

### Task 2: Tool interface and registry

**Files:**

- Create: `pkg/tools/tool.go`
- Create: `pkg/tools/registry.go`
- Create: `pkg/tools/hooks.go`
- Create: `pkg/tools/registry_test.go`

- [ ] **Step 1: Write failing tests for registry**

`pkg/tools/registry_test.go`:

```go
package tools

import (
	"context"
	"testing"
)

// mockTool implements Tool for testing.
type mockTool struct {
	name   string
	output string
}

func (m *mockTool) Name() string                { return m.name }
func (m *mockTool) Description() string         { return "mock tool" }
func (m *mockTool) Parameters() map[string]any  { return map[string]any{"type": "object"} }
func (m *mockTool) Execute(_ context.Context, _ map[string]any) *ToolResult {
	return &ToolResult{Output: m.output}
}

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&mockTool{name: "test_tool", output: "ok"})

	tool, ok := r.Get("test_tool")
	if !ok {
		t.Fatal("expected tool to be registered")
	}
	if tool.Name() != "test_tool" {
		t.Fatalf("expected test_tool, got %q", tool.Name())
	}
}

func TestRegistryAllowedFilter(t *testing.T) {
	r := NewRegistry([]string{"allowed_tool"})
	r.Register(&mockTool{name: "allowed_tool"})
	r.Register(&mockTool{name: "blocked_tool"})

	if _, ok := r.Get("allowed_tool"); !ok {
		t.Fatal("allowed_tool should be accessible")
	}
	if _, ok := r.Get("blocked_tool"); ok {
		t.Fatal("blocked_tool should be filtered out")
	}
}

func TestRegistryDefinitions(t *testing.T) {
	r := NewRegistry(nil)
	r.Register(&mockTool{name: "tool_a"})
	r.Register(&mockTool{name: "tool_b"})

	defs := r.Definitions()
	if len(defs) != 2 {
		t.Fatalf("expected 2 definitions, got %d", len(defs))
	}
}

func TestRegistryAlwaysAllowed(t *testing.T) {
	r := NewRegistry([]string{"only_this"})
	r.RegisterAlwaysAllowed(&mockTool{name: "load_skill"})

	if _, ok := r.Get("load_skill"); !ok {
		t.Fatal("load_skill should bypass allowed filter")
	}
	if _, ok := r.Get("only_this"); !ok {
		t.Fatal("only_this should be accessible")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/tools/ -v`
Expected: FAIL — package doesn't exist.

- [ ] **Step 3: Implement Tool interface**

`pkg/tools/tool.go`:

```go
package tools

import "context"

// Tool defines the interface for an executable tool.
type Tool interface {
	// Name returns the tool's identifier (snake_case).
	Name() string
	// Description returns a human-readable description that
	// guides the LLM on when to use this tool.
	Description() string
	// Parameters returns the JSON Schema for the tool's input.
	Parameters() map[string]any
	// Execute runs the tool and returns the result. Errors are
	// returned in ToolResult, never as Go errors.
	Execute(ctx context.Context, args map[string]any) *ToolResult
}

// ToolResult holds the output of a tool execution.
type ToolResult struct {
	Output string
	Error  bool
}

// OK creates a successful tool result.
func OK(output string) *ToolResult {
	return &ToolResult{Output: output}
}

// Errorf creates an error tool result.
func Errorf(format string, args ...any) *ToolResult {
	return &ToolResult{
		Output: fmt.Sprintf(format, args...),
		Error:  true,
	}
}
```

Add `"fmt"` to the imports in `tool.go`.

- [ ] **Step 4: Implement Registry**

`pkg/tools/registry.go`:

```go
package tools

import (
	"sort"
	"sync"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
)

// Registry maps tool names to handlers with an optional allowed
// filter. Thread-safe for concurrent access.
type Registry struct {
	mu             sync.RWMutex
	tools          map[string]Tool
	alwaysAllowed  map[string]bool
	allowedFilter  map[string]bool // nil means all allowed
}

// NewRegistry creates a new tool registry. If allowedTools is nil
// or empty, all registered tools are available. If non-empty, only
// tools in the list (plus always-allowed tools) are accessible.
func NewRegistry(allowedTools []string) *Registry {
	r := &Registry{
		tools:         make(map[string]Tool),
		alwaysAllowed: make(map[string]bool),
	}
	if len(allowedTools) > 0 {
		r.allowedFilter = make(map[string]bool, len(allowedTools))
		for _, name := range allowedTools {
			r.allowedFilter[name] = true
		}
	}
	return r
}

// Register adds a tool to the registry. Subject to allowed filter.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// RegisterAlwaysAllowed adds a tool that bypasses the allowed filter
// (e.g., load_skill).
func (r *Registry) RegisterAlwaysAllowed(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
	r.alwaysAllowed[t.Name()] = true
}

// Get returns a tool by name, respecting the allowed filter.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, exists := r.tools[name]
	if !exists {
		return nil, false
	}
	if r.allowedFilter != nil && !r.allowedFilter[name] && !r.alwaysAllowed[name] {
		return nil, false
	}
	return t, true
}

// Definitions returns LLM tool definitions for all accessible tools,
// sorted by name for deterministic ordering.
func (r *Registry) Definitions() []llm.ToolDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var defs []llm.ToolDefinition
	for name, t := range r.tools {
		if r.allowedFilter != nil && !r.allowedFilter[name] && !r.alwaysAllowed[name] {
			continue
		}
		defs = append(defs, llm.ToolDefinition{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  t.Parameters(),
		})
	}
	sort.Slice(defs, func(i, j int) bool {
		return defs[i].Name < defs[j].Name
	})
	return defs
}
```

- [ ] **Step 5: Create Hook interface**

`pkg/tools/hooks.go`:

```go
package tools

import "context"

// Hook allows external systems to intercept tool calls.
// When nil, all tool calls are allowed.
type Hook interface {
	// BeforeToolCall is called before each tool execution.
	// Return allow=false to block the call. The reason is
	// returned to the LLM as an error result.
	BeforeToolCall(ctx context.Context, name string,
		args map[string]any) (allow bool, reason string)
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./pkg/tools/ -v`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/tools/
git commit -s -m "feat(tools): add Tool interface, Registry, and Hook interface"
```

---

### Task 3: The agentic loop

**Files:**

- Create: `pkg/tools/loop.go`
- Create: `pkg/tools/loop_test.go`

- [ ] **Step 1: Write failing tests for RunToolLoop**

`pkg/tools/loop_test.go`:

```go
package tools

import (
	"context"
	"testing"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
)

// mockProvider implements llm.Provider for testing the loop.
type mockProvider struct {
	responses []*llm.Response
	callIdx   int
}

func (m *mockProvider) Complete(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (m *mockProvider) CompleteWithTools(_ context.Context, _ []llm.Message, _ []llm.ToolDefinition) (*llm.Response, error) {
	if m.callIdx >= len(m.responses) {
		return &llm.Response{StopReason: llm.StopReasonEndTurn, Content: "done"}, nil
	}
	resp := m.responses[m.callIdx]
	m.callIdx++
	return resp, nil
}

func (m *mockProvider) Model() string        { return "mock" }
func (m *mockProvider) ProviderName() string  { return "mock" }

func TestRunToolLoopNoTools(t *testing.T) {
	provider := &mockProvider{
		responses: []*llm.Response{
			{StopReason: llm.StopReasonEndTurn, Content: "Hello!"},
		},
	}
	registry := NewRegistry(nil)
	messages := []llm.Message{
		{Role: "user", Content: "Say hello"},
	}

	result, err := RunToolLoop(context.Background(), provider, messages,
		registry, DefaultLoopConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Hello!" {
		t.Fatalf("expected 'Hello!', got %q", result)
	}
}

func TestRunToolLoopWithToolCall(t *testing.T) {
	provider := &mockProvider{
		responses: []*llm.Response{
			{
				StopReason: llm.StopReasonToolUse,
				Content:    "I'll check that.",
				ToolCalls: []llm.ToolCall{
					{ID: "tc1", Name: "test_tool", Args: map[string]any{}},
				},
			},
			{
				StopReason: llm.StopReasonEndTurn,
				Content:    "The result is: ok",
			},
		},
	}

	registry := NewRegistry(nil)
	registry.Register(&mockTool{name: "test_tool", output: "ok"})

	messages := []llm.Message{
		{Role: "user", Content: "Use the tool"},
	}

	result, err := RunToolLoop(context.Background(), provider, messages,
		registry, DefaultLoopConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "The result is: ok" {
		t.Fatalf("expected 'The result is: ok', got %q", result)
	}
}

func TestRunToolLoopMaxIterations(t *testing.T) {
	// Provider always returns tool calls — should hit max iterations
	provider := &mockProvider{
		responses: make([]*llm.Response, 20),
	}
	for i := range provider.responses {
		provider.responses[i] = &llm.Response{
			StopReason: llm.StopReasonToolUse,
			ToolCalls: []llm.ToolCall{
				{ID: "tc", Name: "test_tool", Args: map[string]any{}},
			},
		}
	}

	registry := NewRegistry(nil)
	registry.Register(&mockTool{name: "test_tool", output: "ok"})

	cfg := DefaultLoopConfig()
	cfg.MaxIterations = 3

	messages := []llm.Message{
		{Role: "user", Content: "Loop forever"},
	}

	_, err := RunToolLoop(context.Background(), provider, messages,
		registry, cfg)
	if err == nil {
		t.Fatal("expected error for max iterations")
	}
}

func TestRunToolLoopUnknownTool(t *testing.T) {
	provider := &mockProvider{
		responses: []*llm.Response{
			{
				StopReason: llm.StopReasonToolUse,
				ToolCalls: []llm.ToolCall{
					{ID: "tc1", Name: "nonexistent", Args: map[string]any{}},
				},
			},
			{
				StopReason: llm.StopReasonEndTurn,
				Content:    "Tool not found, sorry.",
			},
		},
	}

	registry := NewRegistry(nil)
	messages := []llm.Message{
		{Role: "user", Content: "Use unknown tool"},
	}

	result, err := RunToolLoop(context.Background(), provider, messages,
		registry, DefaultLoopConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The LLM should have received the error and responded
	if result != "Tool not found, sorry." {
		t.Fatalf("expected error recovery response, got %q", result)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/tools/ -run TestRunToolLoop -v`
Expected: FAIL — `RunToolLoop` not defined.

- [ ] **Step 3: Implement RunToolLoop**

`pkg/tools/loop.go`:

```go
package tools

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
)

// LoopConfig controls the agentic loop behavior.
type LoopConfig struct {
	MaxIterations int
}

// DefaultLoopConfig returns sensible defaults.
func DefaultLoopConfig() LoopConfig {
	return LoopConfig{
		MaxIterations: 10,
	}
}

// RunToolLoop executes the agentic tool-use loop. It calls the LLM
// with tool definitions, dispatches any tool calls, feeds results
// back, and repeats until the LLM produces a final text response
// or max iterations is reached.
func RunToolLoop(ctx context.Context, provider llm.Provider,
	messages []llm.Message, registry *Registry,
	config LoopConfig) (string, error) {

	toolDefs := registry.Definitions()

	for i := 0; i < config.MaxIterations; i++ {
		resp, err := provider.CompleteWithTools(ctx, messages, toolDefs)
		if err != nil {
			return "", fmt.Errorf("LLM call failed: %w", err)
		}

		// If no tool calls, return the text response
		if !resp.HasToolCalls() {
			return resp.Content, nil
		}

		// Append assistant message with tool calls
		messages = append(messages, llm.Message{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		// Execute each tool call sequentially
		var results []llm.ToolResultContent
		for _, tc := range resp.ToolCalls {
			result := executeTool(ctx, registry, tc, nil)
			results = append(results, llm.ToolResultContent{
				ToolUseID: tc.ID,
				Output:    result.Output,
				IsError:   result.Error,
			})
		}

		// Append tool results as a new message
		messages = append(messages, llm.Message{
			Role:        "tool",
			ToolResults: results,
		})
	}

	return "", fmt.Errorf("max iterations (%d) reached without final response", config.MaxIterations)
}

// executeTool runs a single tool call through the registry,
// checking the hook if one is provided.
func executeTool(ctx context.Context, registry *Registry,
	tc llm.ToolCall, hook Hook) *ToolResult {

	// Check hook before execution
	if hook != nil {
		allow, reason := hook.BeforeToolCall(ctx, tc.Name, tc.Args)
		if !allow {
			slog.Warn("tool call denied by hook",
				"tool", tc.Name, "reason", reason)
			return Errorf("Tool call denied: %s", reason)
		}
	}

	// Look up tool in registry
	tool, ok := registry.Get(tc.Name)
	if !ok {
		slog.Warn("unknown tool requested", "tool", tc.Name)
		return Errorf("Unknown tool: %s", tc.Name)
	}

	// Execute
	slog.Info("executing tool", "tool", tc.Name)
	result := tool.Execute(ctx, tc.Args)
	if result.Error {
		slog.Warn("tool returned error",
			"tool", tc.Name, "output", truncateLog(result.Output))
	}

	return result
}

func truncateLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/tools/ -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/tools/loop.go pkg/tools/loop_test.go
git commit -s -m "feat(tools): implement RunToolLoop agentic loop"
```

---

### Task 4: Built-in tools

**Files:**

- Create: `pkg/tools/exec.go`
- Create: `pkg/tools/exec_test.go`
- Create: `pkg/tools/webfetch.go`
- Create: `pkg/tools/readfile.go`
- Create: `pkg/tools/writefile.go`
- Create: `pkg/tools/fetchdoc.go`

- [ ] **Step 1: Write failing tests for exec deny patterns**

`pkg/tools/exec_test.go`:

```go
package tools

import (
	"context"
	"testing"
)

func TestExecToolDenyPatterns(t *testing.T) {
	tool := NewExecTool(ExecConfig{Timeout: 5, MaxOutput: 1000})

	denied := []string{
		"rm -rf /",
		"sudo apt-get install",
		"docker run malicious",
		"git push --force",
		"dd if=/dev/zero of=/dev/sda",
	}

	for _, cmd := range denied {
		t.Run(cmd, func(t *testing.T) {
			result := tool.Execute(context.Background(),
				map[string]any{"command": cmd})
			if !result.Error {
				t.Fatalf("expected deny for %q", cmd)
			}
		})
	}
}

func TestExecToolAllowed(t *testing.T) {
	tool := NewExecTool(ExecConfig{Timeout: 5, MaxOutput: 1000})

	result := tool.Execute(context.Background(),
		map[string]any{"command": "echo hello"})
	if result.Error {
		t.Fatalf("unexpected error: %s", result.Output)
	}
	if result.Output != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", result.Output)
	}
}

func TestExecToolTimeout(t *testing.T) {
	tool := NewExecTool(ExecConfig{Timeout: 1, MaxOutput: 1000})

	result := tool.Execute(context.Background(),
		map[string]any{"command": "sleep 10"})
	if !result.Error {
		t.Fatal("expected timeout error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/tools/ -run TestExecTool -v`
Expected: FAIL — `NewExecTool` not defined.

- [ ] **Step 3: Implement exec tool**

`pkg/tools/exec.go`:

```go
package tools

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// ExecConfig holds configuration for the exec tool.
type ExecConfig struct {
	Timeout   int // seconds
	MaxOutput int // max output length in characters
}

// DefaultExecConfig returns sensible defaults.
func DefaultExecConfig() ExecConfig {
	return ExecConfig{
		Timeout:   30,
		MaxOutput: 50000,
	}
}

// denyPatterns are always applied and cannot be removed via config.
// Based on PicoClaw's production-tested deny list.
var denyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-\w*\s+)*-r`),
	regexp.MustCompile(`\brm\s+(-\w*\s+)*-f`),
	regexp.MustCompile(`\bsudo\b`),
	regexp.MustCompile(`\bdd\b.*\bof=/dev/`),
	regexp.MustCompile(`\bmkfs\b`),
	regexp.MustCompile(`\bgit\s+push\b`),
	regexp.MustCompile(`\bgit\s+reset\s+--hard\b`),
	regexp.MustCompile(`\bdocker\s+run\b`),
	regexp.MustCompile(`\bdocker\s+exec\b`),
	regexp.MustCompile(`\bpodman\s+run\b`),
	regexp.MustCompile(`\bkubectl\s+delete\b`),
	regexp.MustCompile(`\boc\s+delete\b`),
	regexp.MustCompile(`\bcurl\b.*\|\s*(ba)?sh`),
	regexp.MustCompile(`\bwget\b.*\|\s*(ba)?sh`),
	regexp.MustCompile(`\bchmod\s+[0-7]*777\b`),
	regexp.MustCompile(`\bchown\b`),
	regexp.MustCompile(`\beval\b`),
	regexp.MustCompile(`:\(\)\{.*\}:`), // fork bomb
	regexp.MustCompile(`\b/dev/sd[a-z]\b`),
	regexp.MustCompile(`\bshutdown\b`),
	regexp.MustCompile(`\breboot\b`),
	regexp.MustCompile(`\bhalt\b`),
	regexp.MustCompile(`\bpoweroff\b`),
	regexp.MustCompile(`>\s*/etc/`),
	regexp.MustCompile(`\bssh\b`),
	regexp.MustCompile(`\bnc\s+-l`), // netcat listen
}

type execTool struct {
	config ExecConfig
}

// NewExecTool creates an exec tool with the given configuration.
func NewExecTool(cfg ExecConfig) Tool {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30
	}
	if cfg.MaxOutput == 0 {
		cfg.MaxOutput = 50000
	}
	return &execTool{config: cfg}
}

func (t *execTool) Name() string        { return "exec" }
func (t *execTool) Description() string {
	return "Run a shell command and return stdout/stderr. " +
		"Use for file conversion, data processing, and system commands. " +
		"Dangerous commands (rm -rf, sudo, docker, etc.) are blocked."
}
func (t *execTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command": map[string]any{
				"type":        "string",
				"description": "The shell command to execute",
			},
		},
		"required": []string{"command"},
	}
}

func (t *execTool) Execute(ctx context.Context, args map[string]any) *ToolResult {
	command, ok := args["command"].(string)
	if !ok || command == "" {
		return Errorf("command is required")
	}

	// Check deny patterns
	for _, pattern := range denyPatterns {
		if pattern.MatchString(command) {
			return Errorf("Command blocked by security policy: %s", command)
		}
	}

	// Run with timeout
	timeout := time.Duration(t.config.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()

	result := string(output)
	if len(result) > t.config.MaxOutput {
		result = result[:t.config.MaxOutput] + "\n...(truncated)"
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return Errorf("Command timed out after %ds: %s", t.config.Timeout, command)
		}
		return &ToolResult{
			Output: fmt.Sprintf("%s\nExit error: %s", result, err),
			Error:  true,
		}
	}

	return OK(result)
}
```

- [ ] **Step 4: Implement web_fetch, read_file, write_file**

`pkg/tools/webfetch.go`:

```go
package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WebFetchConfig holds configuration for the web_fetch tool.
type WebFetchConfig struct {
	AllowedHosts []string
}

type webFetchTool struct {
	config WebFetchConfig
}

// NewWebFetchTool creates a web_fetch tool.
func NewWebFetchTool(cfg WebFetchConfig) Tool {
	return &webFetchTool{config: cfg}
}

func (t *webFetchTool) Name() string        { return "web_fetch" }
func (t *webFetchTool) Description() string {
	return "Fetch content from a URL via HTTP GET. Returns the response body as text."
}
func (t *webFetchTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "The URL to fetch",
			},
		},
		"required": []string{"url"},
	}
}

func (t *webFetchTool) Execute(ctx context.Context, args map[string]any) *ToolResult {
	rawURL, ok := args["url"].(string)
	if !ok || rawURL == "" {
		return Errorf("url is required")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Errorf("invalid URL: %s", err)
	}

	// SSRF prevention
	if len(t.config.AllowedHosts) > 0 {
		host := parsed.Hostname()
		allowed := false
		for _, suffix := range t.config.AllowedHosts {
			if strings.HasSuffix(host, suffix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Errorf("Host not allowed: %s", host)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Errorf("failed to create request: %s", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Errorf("fetch failed: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 100000))
	if err != nil {
		return Errorf("failed to read response: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return OK(string(body))
}
```

`pkg/tools/readfile.go`:

```go
package tools

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type readFileTool struct {
	workspace string
}

// NewReadFileTool creates a read_file tool restricted to workspace.
func NewReadFileTool(workspace string) Tool {
	return &readFileTool{workspace: workspace}
}

func (t *readFileTool) Name() string        { return "read_file" }
func (t *readFileTool) Description() string {
	return "Read a file and return its contents with numbered lines. " +
		"Use when you need to examine file contents."
}
func (t *readFileTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Path to the file to read",
			},
		},
		"required": []string{"path"},
	}
}

func (t *readFileTool) Execute(_ context.Context, args map[string]any) *ToolResult {
	path, ok := args["path"].(string)
	if !ok || path == "" {
		return Errorf("path is required")
	}

	// Workspace restriction
	if t.workspace != "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return Errorf("invalid path: %s", err)
		}
		absWorkspace, _ := filepath.Abs(t.workspace)
		if !strings.HasPrefix(absPath, absWorkspace) {
			return Errorf("Access denied: path outside workspace")
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Errorf("Error reading file: %s", err)
	}

	lines := strings.Split(string(data), "\n")
	var numbered strings.Builder
	for i, line := range lines {
		fmt.Fprintf(&numbered, "%4d\t%s\n", i+1, line)
	}

	output := numbered.String()
	if len(output) > 50000 {
		output = output[:50000] + "\n...(truncated)"
	}

	return OK(output)
}
```

`pkg/tools/writefile.go`:

```go
package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

type writeFileTool struct {
	workspace string
}

// NewWriteFileTool creates a write_file tool restricted to workspace.
func NewWriteFileTool(workspace string) Tool {
	return &writeFileTool{workspace: workspace}
}

func (t *writeFileTool) Name() string        { return "write_file" }
func (t *writeFileTool) Description() string {
	return "Write content to a file. Creates the file if it doesn't exist, " +
		"overwrites if it does."
}
func (t *writeFileTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Path to the file to write",
			},
			"content": map[string]any{
				"type":        "string",
				"description": "Content to write to the file",
			},
		},
		"required": []string{"path", "content"},
	}
}

func (t *writeFileTool) Execute(_ context.Context, args map[string]any) *ToolResult {
	path, _ := args["path"].(string)
	content, _ := args["content"].(string)
	if path == "" {
		return Errorf("path is required")
	}

	// Workspace restriction
	if t.workspace != "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return Errorf("invalid path: %s", err)
		}
		absWorkspace, _ := filepath.Abs(t.workspace)
		if !strings.HasPrefix(absPath, absWorkspace) {
			return Errorf("Access denied: path outside workspace")
		}
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return Errorf("failed to create directory: %s", err)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return Errorf("failed to write file: %s", err)
	}

	return OK("File written successfully: " + path)
}
```

- [ ] **Step 5: Implement fetch_document tool**

`pkg/tools/fetchdoc.go`:

```go
package tools

import (
	"context"
	"fmt"
)

// DocumentFetcher is a function that fetches a document by ID.
// It is injected by serve.go with the delegation-aware HTTP client.
type DocumentFetcher func(ctx context.Context, documentID, bearerToken string) (map[string]any, error)

type fetchDocTool struct {
	fetcher DocumentFetcher
}

// NewFetchDocTool creates a fetch_document tool that uses the
// provided fetcher (which includes DelegationTransport).
func NewFetchDocTool(fetcher DocumentFetcher) Tool {
	return &fetchDocTool{fetcher: fetcher}
}

func (t *fetchDocTool) Name() string        { return "fetch_document" }
func (t *fetchDocTool) Description() string {
	return "Fetch a document from the document service by ID (e.g., DOC-001). " +
		"Returns the document title and content. " +
		"Subject to the same delegation and OPA authorization as the initial request."
}
func (t *fetchDocTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"document_id": map[string]any{
				"type":        "string",
				"description": "Document ID (e.g., DOC-001)",
			},
		},
		"required": []string{"document_id"},
	}
}

func (t *fetchDocTool) Execute(ctx context.Context, args map[string]any) *ToolResult {
	docID, ok := args["document_id"].(string)
	if !ok || docID == "" {
		return Errorf("document_id is required")
	}

	doc, err := t.fetcher(ctx, docID, "")
	if err != nil {
		return Errorf("Failed to fetch document %s: %s", docID, err)
	}

	title, _ := doc["title"].(string)
	content, _ := doc["content"].(string)

	return OK(fmt.Sprintf("**Document:** %s\n\n%s", title, content))
}
```

- [ ] **Step 6: Run all tests**

Run: `go test ./pkg/tools/ -v`
Expected: All tests PASS.

Run: `go build ./...`
Expected: Compiles successfully.

- [ ] **Step 7: Commit**

```bash
git add pkg/tools/exec.go pkg/tools/exec_test.go \
       pkg/tools/webfetch.go pkg/tools/readfile.go \
       pkg/tools/writefile.go pkg/tools/fetchdoc.go
git commit -s -m "feat(tools): add built-in tools (exec, web_fetch, read_file, write_file, fetch_document)"
```

---

### Task 5: Anthropic CompleteWithTools

**Files:**

- Modify: `pkg/llm/anthropic.go`

- [ ] **Step 1: Implement CompleteWithTools for Anthropic**

Replace the stub in `pkg/llm/anthropic.go` with the full
implementation:

```go
// CompleteWithTools sends a multi-turn conversation with tool
// definitions to the Anthropic API.
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context,
	messages []Message, tools []ToolDefinition) (*Response, error) {

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Convert messages to Anthropic format
	var anthropicMsgs []anthropic.MessageParam
	var systemPrompt string

	for _, msg := range messages {
		switch msg.Role {
		case "system":
			systemPrompt = msg.Content
		case "user":
			anthropicMsgs = append(anthropicMsgs,
				anthropic.NewUserMessage(anthropic.NewTextBlock(msg.Content)))
		case "assistant":
			var blocks []anthropic.ContentBlockParamUnion
			if msg.Content != "" {
				blocks = append(blocks, anthropic.NewTextBlock(msg.Content))
			}
			for _, tc := range msg.ToolCalls {
				blocks = append(blocks, anthropic.ContentBlockParamUnion{
					OfRequestToolUseBlock: &anthropic.ToolUseBlockParam{
						ID:    tc.ID,
						Name:  tc.Name,
						Input: tc.Args,
					},
				})
			}
			anthropicMsgs = append(anthropicMsgs,
				anthropic.MessageParam{Role: "assistant", Content: blocks})
		case "tool":
			var blocks []anthropic.ContentBlockParamUnion
			for _, tr := range msg.ToolResults {
				blocks = append(blocks, anthropic.NewToolResultBlock(
					tr.ToolUseID, tr.Output, tr.IsError))
			}
			anthropicMsgs = append(anthropicMsgs,
				anthropic.MessageParam{Role: "user", Content: blocks})
		}
	}

	// Convert tool definitions
	var anthropicTools []anthropic.ToolUnionParam
	for _, td := range tools {
		anthropicTools = append(anthropicTools, anthropic.ToolUnionParam{
			OfTool: &anthropic.ToolParam{
				Name:        td.Name,
				Description: anthropic.String(td.Description),
				InputSchema: td.Parameters,
			},
		})
	}

	// Build params
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(p.model),
		MaxTokens: int64(p.maxTokens),
		Messages:  anthropicMsgs,
		Tools:     anthropicTools,
	}
	if systemPrompt != "" {
		params.System = []anthropic.TextBlockParam{{Text: systemPrompt}}
	}

	message, err := p.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	// Parse response
	resp := &Response{}
	switch message.StopReason {
	case "tool_use":
		resp.StopReason = StopReasonToolUse
	default:
		resp.StopReason = StopReasonEndTurn
	}

	for _, block := range message.Content {
		switch block.Type {
		case "text":
			resp.Content += block.Text
		case "tool_use":
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{
				ID:   block.ID,
				Name: block.Name,
				Args: block.Input.(map[string]any),
			})
		}
	}

	return resp, nil
}
```

Note: The Anthropic SDK types and method names must match the
version in go.mod. Read the existing `Complete` method for the
exact SDK patterns used. The code above follows the same SDK
conventions (e.g., `anthropic.NewUserMessage`,
`anthropic.NewTextBlock`, `anthropic.MessageNewParams`).

The key Anthropic-specific details:

- Tool results are sent as `user` role messages (Anthropic
  convention)
- `ToolUseBlockParam` requires `ID`, `Name`, and `Input`
- `NewToolResultBlock` takes `tool_use_id`, `content`, `is_error`
- `StopReason` is `"tool_use"` when the model wants to call tools

- [ ] **Step 2: Verify build compiles**

Run: `go build ./pkg/llm/`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add pkg/llm/anthropic.go
git commit -s -m "feat(llm): implement CompleteWithTools for Anthropic provider"
```

---

### Task 6: OpenAI CompleteWithTools

**Files:**

- Modify: `pkg/llm/openai_compat.go`

- [ ] **Step 1: Implement CompleteWithTools for OpenAI**

Replace the stub in `pkg/llm/openai_compat.go` with the full
implementation. The OpenAI API uses `tools` and `tool_choice`
fields, with `function` calling format:

```go
// openAIToolCall represents a tool call in the OpenAI response.
type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON string
	} `json:"function"`
}

// openAIToolDef represents a tool definition for the OpenAI API.
type openAIToolDef struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

// openAIChatRequestWithTools extends the request with tools support.
type openAIChatRequestWithTools struct {
	Model    string            `json:"model"`
	Messages []json.RawMessage `json:"messages"`
	Tools    []openAIToolDef   `json:"tools,omitempty"`
	MaxTokens int             `json:"max_tokens,omitempty"`
}

// openAIChatResponseWithTools extends the response with tool calls.
type openAIChatResponseWithTools struct {
	Choices []struct {
		Message struct {
			Role      string           `json:"role"`
			Content   *string          `json:"content"`
			ToolCalls []openAIToolCall  `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *openAIError `json:"error,omitempty"`
}

// CompleteWithTools sends a multi-turn conversation with tool
// definitions to the OpenAI-compatible API.
func (p *OpenAICompatProvider) CompleteWithTools(ctx context.Context,
	messages []Message, tools []ToolDefinition) (*Response, error) {

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Convert messages to OpenAI format
	var openaiMsgs []json.RawMessage
	for _, msg := range messages {
		var raw []byte
		var err error

		switch msg.Role {
		case "system", "user":
			raw, err = json.Marshal(map[string]string{
				"role":    msg.Role,
				"content": msg.Content,
			})
		case "assistant":
			assistantMsg := map[string]any{
				"role": "assistant",
			}
			if msg.Content != "" {
				assistantMsg["content"] = msg.Content
			}
			if len(msg.ToolCalls) > 0 {
				var tcs []openAIToolCall
				for _, tc := range msg.ToolCalls {
					argsJSON, _ := json.Marshal(tc.Args)
					tcs = append(tcs, openAIToolCall{
						ID:   tc.ID,
						Type: "function",
						Function: struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						}{
							Name:      tc.Name,
							Arguments: string(argsJSON),
						},
					})
				}
				assistantMsg["tool_calls"] = tcs
			}
			raw, err = json.Marshal(assistantMsg)
		case "tool":
			// OpenAI sends each tool result as a separate message
			for _, tr := range msg.ToolResults {
				toolMsg, _ := json.Marshal(map[string]string{
					"role":         "tool",
					"tool_call_id": tr.ToolUseID,
					"content":      tr.Output,
				})
				openaiMsgs = append(openaiMsgs, toolMsg)
			}
			continue // already appended
		}

		if err != nil {
			return nil, fmt.Errorf("failed to marshal message: %w", err)
		}
		openaiMsgs = append(openaiMsgs, raw)
	}

	// Convert tool definitions
	var openaiTools []openAIToolDef
	for _, td := range tools {
		def := openAIToolDef{Type: "function"}
		def.Function.Name = td.Name
		def.Function.Description = td.Description
		def.Function.Parameters = td.Parameters
		openaiTools = append(openaiTools, def)
	}

	reqBody := openAIChatRequestWithTools{
		Model:     p.model,
		Messages:  openaiMsgs,
		Tools:     openaiTools,
		MaxTokens: p.maxTokens,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	httpResp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s",
			httpResp.StatusCode, string(body))
	}

	var chatResp openAIChatResponseWithTools
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("empty response from API")
	}

	choice := chatResp.Choices[0]
	resp := &Response{}

	if choice.FinishReason == "tool_calls" {
		resp.StopReason = StopReasonToolUse
	} else {
		resp.StopReason = StopReasonEndTurn
	}

	if choice.Message.Content != nil {
		resp.Content = *choice.Message.Content
	}

	for _, tc := range choice.Message.ToolCalls {
		var args map[string]any
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
			args = map[string]any{"_raw": tc.Function.Arguments}
		}
		resp.ToolCalls = append(resp.ToolCalls, ToolCall{
			ID:   tc.ID,
			Name: tc.Function.Name,
			Args: args,
		})
	}

	return resp, nil
}
```

- [ ] **Step 2: Verify build compiles**

Run: `go build ./pkg/llm/`
Expected: Compiles successfully.

- [ ] **Step 3: Commit**

```bash
git add pkg/llm/openai_compat.go
git commit -s -m "feat(llm): implement CompleteWithTools for OpenAI-compatible provider"
```

---

### Task 7: Skill loader

**Files:**

- Create: `pkg/skills/loader.go`
- Create: `pkg/skills/loader_test.go`
- Create: `zt-agent/testdata/research-agent/skills/pdf-summary/SKILL.md`

- [ ] **Step 1: Create test skill fixture**

`zt-agent/testdata/research-agent/skills/pdf-summary/SKILL.md`:

```markdown
---
name: pdf-summary
description: Convert PDF documents to text and summarize them
---

# PDF summary skill

When asked to summarize a PDF document:

1. Use the exec tool to convert the PDF to text:
   `pdftotext input.pdf output.txt`
2. Use read_file to read the converted text
3. Summarize the content
```

- [ ] **Step 2: Write failing tests for skill loader**

`pkg/skills/loader_test.go`:

```go
package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverSkills(t *testing.T) {
	// Create temp skill directory
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "test-skill")
	os.MkdirAll(skillDir, 0755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(`---
name: test-skill
description: A test skill for unit testing
---

# Test skill

Do something useful.
`), 0644)

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
	os.MkdirAll(skillDir, 0755)
	content := `---
name: my-skill
description: My test skill
---

# My skill

Step 1: Do this
Step 2: Do that
`
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0644)

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
	if !contains(summary, "code-review") {
		t.Fatal("expected code-review in summary")
	}
	if !contains(summary, "pdf-summary") {
		t.Fatal("expected pdf-summary in summary")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/skills/ -v`
Expected: FAIL — package doesn't exist.

- [ ] **Step 4: Implement skill loader**

`pkg/skills/loader.go`:

```go
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
	Dir         string // directory containing the SKILL.md
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
			continue // skip malformed skills
		}
		meta.Dir = filepath.Join(skillsDir, entry.Name())
		skills = append(skills, meta)
	}

	return skills, nil
}

// LoadContent reads the full content of a skill's SKILL.md file.
func LoadContent(skillsDir, name string) (string, error) {
	path := filepath.Join(skillsDir, name, "SKILL.md")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("skill '%s' not found: %w", name, err)
	}
	return fmt.Sprintf("=== SKILL: %s ===\n%s", name, string(data)), nil
}

// BuildSummary creates a text block listing all available skills,
// suitable for appending to the system prompt.
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

	// Find closing ---
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/skills/ -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/skills/ zt-agent/testdata/research-agent/skills/
git commit -s -m "feat(skills): implement SKILL.md discovery and loading"
```

---

### Task 8: Integration into serve.go

**Files:**

- Create: `zt-agent/cmd/agentconfig.go`
- Modify: `zt-agent/cmd/serve.go`
- Create: `zt-agent/testdata/research-agent/agent-config.yaml`
- Create: `zt-agent/testdata/research-agent/system-prompt.txt`
- Create: `zt-agent/testdata/research-agent/agent-card.json`

- [ ] **Step 1: Create test fixtures**

`zt-agent/testdata/research-agent/system-prompt.txt`:

```text
You are a document research agent. You can fetch documents,
read files, execute commands, and use skills to analyze content.
Use the available tools to complete your tasks.
```

`zt-agent/testdata/research-agent/agent-card.json`:

```json
{
  "name": "research-agent",
  "description": "Document research agent with tool-use capabilities",
  "version": "2.0.0",
  "protocolVersion": "0.3.0",
  "url": "http://localhost:8000",
  "skills": [
    {
      "id": "document-research",
      "name": "Document Research",
      "description": "Research and analyze documents using tools",
      "tags": ["engineering", "finance"],
      "examples": ["Research DOC-001 and compare with DOC-002"]
    }
  ],
  "capabilities": {},
  "defaultInputModes": ["application/json"],
  "defaultOutputModes": ["text/plain"]
}
```

`zt-agent/testdata/research-agent/agent-config.yaml`:

```yaml
tools:
  allowed:
    - exec
    - web_fetch
    - read_file
    - write_file
    - fetch_document
  exec:
    timeout: 30
    max_output: 50000
  web_fetch:
    allowed_hosts:
      - ".s3.amazonaws.com"
      - ".svc.cluster.local"
  workspace: /tmp/agent-workspace

loop:
  max_iterations: 10
```

- [ ] **Step 2: Implement agent-config.yaml loading**

`zt-agent/cmd/agentconfig.go`:

```go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/tools"
)

// AgentConfig holds the agent-config.yaml configuration.
type AgentConfig struct {
	Tools ToolsConfig `yaml:"tools"`
	Loop  LoopConfig  `yaml:"loop"`
}

// ToolsConfig configures tool availability and behavior.
type ToolsConfig struct {
	Allowed   []string        `yaml:"allowed"`
	Exec      ExecToolConfig  `yaml:"exec"`
	WebFetch  WebFetchConfig  `yaml:"web_fetch"`
	Workspace string          `yaml:"workspace"`
}

// ExecToolConfig configures the exec tool.
type ExecToolConfig struct {
	Timeout   int `yaml:"timeout"`
	MaxOutput int `yaml:"max_output"`
}

// WebFetchConfig configures the web_fetch tool.
type WebFetchConfig struct {
	AllowedHosts []string `yaml:"allowed_hosts"`
}

// LoopConfig configures the agentic loop.
type LoopConfig struct {
	MaxIterations int `yaml:"max_iterations"`
}

// loadAgentConfig reads agent-config.yaml from the config directory.
// Returns nil if the file does not exist (phase 1 mode).
func loadAgentConfig(configDir string) (*AgentConfig, error) {
	path := filepath.Join(configDir, "agent-config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Phase 1 mode
		}
		return nil, fmt.Errorf("failed to read agent config: %w", err)
	}

	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse agent config: %w", err)
	}

	return &cfg, nil
}

// toToolsLoopConfig converts AgentConfig to the tools.LoopConfig.
func (c *AgentConfig) toLoopConfig() tools.LoopConfig {
	cfg := tools.DefaultLoopConfig()
	if c.Loop.MaxIterations > 0 {
		cfg.MaxIterations = c.Loop.MaxIterations
	}
	return cfg
}
```

- [ ] **Step 3: Add yaml dependency**

Run: `go get gopkg.in/yaml.v3`

- [ ] **Step 4: Wire tools and skills into serve.go**

Modify the `processLLM` callback in `zt-agent/cmd/serve.go`.
After loading `promptVariants` and before creating the logger,
add the agent config loading and tool/skill setup:

Add these imports to serve.go:

```go
"github.com/redhat-et/zero-trust-agent-demo/pkg/tools"
"github.com/redhat-et/zero-trust-agent-demo/pkg/skills"
```

After the existing prompt loading block (around line 198), add:

```go
	// Load agent config (optional — nil means phase 1 mode)
	agentCfg, err := loadAgentConfig(cfg.ConfigDir)
	if err != nil {
		return err
	}

	// Set up tool registry and skill loading if agent config exists
	var toolRegistry *tools.Registry
	var loopCfg tools.LoopConfig

	if agentCfg != nil {
		// Create tool registry with allowed filter
		toolRegistry = tools.NewRegistry(agentCfg.Tools.Allowed)

		// Register built-in tools
		workspace := agentCfg.Tools.Workspace
		if workspace == "" {
			workspace = "/tmp/agent-workspace"
		}
		os.MkdirAll(workspace, 0755)

		toolRegistry.Register(tools.NewExecTool(tools.ExecConfig{
			Timeout:   agentCfg.Tools.Exec.Timeout,
			MaxOutput: agentCfg.Tools.Exec.MaxOutput,
		}))
		toolRegistry.Register(tools.NewWebFetchTool(tools.WebFetchConfig{
			AllowedHosts: agentCfg.Tools.WebFetch.AllowedHosts,
		}))
		toolRegistry.Register(tools.NewReadFileTool(workspace))
		toolRegistry.Register(tools.NewWriteFileTool(workspace))

		loopCfg = agentCfg.toLoopConfig()
	}
```

Then modify the `processLLM` callback to use the tool loop when
available. Replace the existing `processLLM` closure with:

```go
	processLLM := func(ctx context.Context, title, content string) (string, error) {
		selectedPrompt := selectPrompt(systemPrompt, promptVariants, title+" "+content)

		// Phase 1: single-shot mode (no tools)
		if toolRegistry == nil {
			if llmProvider == nil {
				return fmt.Sprintf("## Result\n\n**Document:** %s\n\nMock response. "+
					"Configure LLM_API_KEY to enable AI processing.\n\n"+
					"### Document Preview\n\n%s",
					title, truncate(content, 500)), nil
			}

			userPrompt := "Please process the following document:\n\n" +
				"**Title:** " + title + "\n\n" +
				"**Content:**\n" + content

			log.Info("Processing document with LLM", "document", title)
			result, err := llmProvider.Complete(ctx, selectedPrompt, userPrompt)
			if err != nil {
				return "", fmt.Errorf("LLM request failed: %w", err)
			}
			log.Success("LLM processing completed")
			return result, nil
		}

		// Phase 2: agentic tool-use loop
		if llmProvider == nil {
			return "", fmt.Errorf("LLM provider required for tool-use mode")
		}

		log.Info("Starting agentic loop", "document", title,
			"tools", len(toolRegistry.Definitions()))

		messages := []llm.Message{
			{Role: "system", Content: selectedPrompt},
			{Role: "user", Content: fmt.Sprintf(
				"Process the following document:\n\n"+
					"**Title:** %s\n\n**Content:**\n%s",
				title, content)},
		}

		result, err := tools.RunToolLoop(ctx, llmProvider, messages,
			toolRegistry, loopCfg)
		if err != nil {
			return "", fmt.Errorf("agentic loop failed: %w", err)
		}
		log.Success("Agentic processing completed")
		return result, nil
	}
```

After the tool registry setup and before the HTTP mux, register
`fetch_document` and skills:

```go
	if toolRegistry != nil {
		// Register fetch_document tool (uses delegation transport)
		toolRegistry.Register(tools.NewFetchDocTool(
			func(ctx context.Context, docID, token string) (map[string]any, error) {
				return fetchDocument(ctx, docID, token)
			},
		))

		// Load skills
		skillsDir := filepath.Join(cfg.ConfigDir, "skills")
		discoveredSkills, err := skills.Discover(skillsDir)
		if err != nil {
			log.Warn("Failed to load skills", "error", err)
		} else if len(discoveredSkills) > 0 {
			// Append skill summary to system prompt
			systemPrompt += skills.BuildSummary(discoveredSkills)

			// Register load_skill tool
			toolRegistry.RegisterAlwaysAllowed(&loadSkillTool{
				skillsDir: skillsDir,
			})

			log.Info("Skills loaded",
				"count", len(discoveredSkills),
				"names", skillNames(discoveredSkills))
		}
	}
```

Add the `loadSkillTool` type and `skillNames` helper at the end
of `serve.go`:

```go
// loadSkillTool implements the load_skill tool.
type loadSkillTool struct {
	skillsDir string
}

func (t *loadSkillTool) Name() string        { return "load_skill" }
func (t *loadSkillTool) Description() string {
	return "Load the full instructions for a skill by name. " +
		"Use this when you need specialized guidance for a task."
}
func (t *loadSkillTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "The skill name to load",
			},
		},
		"required": []string{"name"},
	}
}
func (t *loadSkillTool) Execute(_ context.Context, args map[string]any) *tools.ToolResult {
	name, _ := args["name"].(string)
	if name == "" {
		return tools.Errorf("skill name is required")
	}
	content, err := skills.LoadContent(t.skillsDir, name)
	if err != nil {
		return tools.Errorf("%s", err)
	}
	return tools.OK(content)
}

func skillNames(skills []skills.SkillMeta) string {
	names := make([]string, len(skills))
	for i, s := range skills {
		names[i] = s.Name
	}
	return strings.Join(names, ", ")
}
```

Add startup logging for tools:

```go
	if toolRegistry != nil {
		log.Info("Tools enabled",
			"allowed", len(toolRegistry.Definitions()),
			"max_iterations", loopCfg.MaxIterations)
	}
```

- [ ] **Step 5: Run all tests**

Run: `go test ./... -v 2>&1 | tail -30`
Expected: All tests PASS.

- [ ] **Step 6: Build and verify**

Run: `go build -o bin/zt-agent ./zt-agent`
Expected: Compiles successfully.

- [ ] **Step 7: Test phase 1 backward compatibility**

Run:

```bash
./bin/zt-agent serve --config-dir zt-agent/testdata/summarizer-hr --help
```

Expected: Works as before (no agent-config.yaml = phase 1 mode).

- [ ] **Step 8: Test phase 2 mode**

Run:

```bash
./bin/zt-agent serve \
  --config-dir zt-agent/testdata/research-agent \
  --listen-plain-http
```

Expected: Logs show "Tools enabled allowed=6 max_iterations=10"
and "Skills loaded count=1 names=pdf-summary".

- [ ] **Step 9: Run linter**

Run: `golangci-lint run ./zt-agent/... ./pkg/tools/... ./pkg/skills/... ./pkg/llm/...`
Expected: No new lint errors (only pre-existing BindPFlag pattern).

- [ ] **Step 10: Commit**

```bash
git add zt-agent/cmd/agentconfig.go zt-agent/cmd/serve.go \
       zt-agent/testdata/research-agent/ go.mod go.sum
git commit -s -m "feat(zt-agent): wire agentic loop, tools, and skills into serve command"
```
