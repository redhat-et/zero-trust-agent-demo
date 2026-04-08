# zt-agent phase 2: agentic tool-use loop and skill loading

**Date:** 2026-04-08
**Status:** Draft
**Author:** Pavel Anni

## Goal

Add agentic tool-use capabilities to zt-agent so the LLM can
iteratively call tools (shell execution, file I/O, document
fetching) driven by SKILL.md instructions loaded from the
config directory. Maintain full backward compatibility with
phase 1 (single-shot mode when no `agent-config.yaml` is present).

## Background

Phase 1 delivered a unified agent runtime with ConfigMap-driven
prompts. The agent is single-shot: receive A2A request, fetch
document, call `llm.Provider.Complete(prompt, content)`, return.

Phase 2 adds the agentic loop — the LLM can now call tools
iteratively until it produces a final answer. This enables
multi-document research, format conversion, cross-referencing,
and execution of ClawHub-compatible SKILL.md instructions.

## Approach

**Approach C (chosen):** Build the agentic loop, tool dispatch,
and skill loading now. Define hook and MCP interfaces but don't
implement them. The tool registry has a `Hook` field that's nil
initially. MCP tools are a future extension to the same registry.

Alternatives considered:

- **A (minimal):** Tool loop only, no skills, no hook interface.
  Too limited — skills are needed for "OpenClaw compatible" claim.
- **B (full harness):** Loop + tools + skills + hooks + MCP in one
  pass. Over-scoped — MCP needs servers to test against, hooks
  need OPA integration design.

## Package structure

### New packages

```text
pkg/tools/
├── tool.go          # Tool interface, ToolResult type
├── registry.go      # Tool registry (name → handler, allowed filter)
├── loop.go          # RunToolLoop (the agentic loop)
├── exec.go          # exec tool with deny patterns
├── webfetch.go      # web_fetch tool
├── readfile.go      # read_file tool
├── writefile.go     # write_file tool
├── fetchdoc.go      # fetch_document tool (delegation-aware)
├── hooks.go         # Hook interface (defined, not implemented)
└── loop_test.go     # Tests for the agentic loop

pkg/skills/
├── loader.go        # Discover and load SKILL.md files
└── loader_test.go   # Tests
```

### Modified packages

```text
pkg/llm/
├── provider.go      # Add CompleteWithTools method to Provider
├── tools.go         # New: Message, ToolDefinition, Response types
├── anthropic.go     # Implement CompleteWithTools
└── openai_compat.go # Implement CompleteWithTools
```

### Dependency direction

`pkg/tools` depends on `pkg/llm` (for `CompleteWithTools`).
`pkg/llm` does NOT depend on `pkg/tools`. Shared types
(`ToolDefinition`, `Message`, `Response`) live in `pkg/llm/tools.go`.

`pkg/skills` depends on `pkg/tools` (registers `load_skill` tool).
`zt-agent/cmd/serve.go` wires everything together.

## Extending `llm.Provider`

The `Provider` interface gains one new method:

```go
type Provider interface {
    Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
    CompleteWithTools(ctx context.Context, messages []Message,
        tools []ToolDefinition) (*Response, error)
    Model() string
    ProviderName() string
}
```

New types in `pkg/llm/tools.go`:

- `Message` — role (`user`, `assistant`, `tool`) + content
  (text, tool calls, or tool results)
- `ToolDefinition` — name, description, JSON schema for parameters
- `Response` — LLM reply with `StopReason` (`"end_turn"` or
  `"tool_use"`), text content, and/or tool call requests
- `ToolCall` — name, ID, arguments (map)
- `ToolResultContent` — tool use ID, output string, error flag

Both Anthropic and OpenAI providers implement `CompleteWithTools`
using their native tool-use APIs. The existing `Complete()` method
stays unchanged — phase 1 agents keep working.

If a model does not support tool calling, the provider API returns
an error. No capability pre-check — the error message from the
provider is more informative than a maintained model list.

## Tool interface and registry

### Tool interface (`pkg/tools/tool.go`)

```go
type Tool interface {
    Name() string
    Description() string
    Parameters() map[string]any  // JSON Schema
    Execute(ctx context.Context, args map[string]any) *ToolResult
}

type ToolResult struct {
    Output string
    Error  bool
}
```

Errors are returned as strings in `ToolResult`, never thrown to
the loop. The LLM sees the error and decides what to do.

### Registry (`pkg/tools/registry.go`)

Thread-safe `map[string]Tool` with an `AllowedTools` filter from
config. If `allowed_tools` is set, only those tools are visible
to the LLM and executable. If empty/unset, all registered tools
are available.

The `load_skill` tool is always registered regardless of
`allowed_tools` (it only injects text, not a security concern).

### Hook interface (`pkg/tools/hooks.go`)

```go
type Hook interface {
    BeforeToolCall(ctx context.Context, name string,
        args map[string]any) (allow bool, reason string)
}
```

Defined but not implemented in phase 2. The `RunToolLoop`
checks for a hook before each tool call — if nil, all calls
are allowed. OPA integration will implement this interface
in a future phase.

## Built-in tools

| Tool | Description | Security |
| ---- | ----------- | -------- |
| `exec` | Run shell commands | Deny patterns (35+ blocked commands from PicoClaw), configurable timeout (default 30s), output truncation (50K chars) |
| `web_fetch` | HTTP GET a URL | SSRF prevention via `allowed_hosts` config |
| `read_file` | Read file, return numbered lines | Workspace restriction |
| `write_file` | Write content to file | Workspace restriction |
| `fetch_document` | Fetch document from document-service by ID | Uses `DelegationTransport` — OPA authorization enforced |

The `fetch_document` tool is the bridge to zero-trust
infrastructure. When a SKILL.md instructs the LLM to fetch
another document, the tool call goes through the same
delegation/OPA path as the initial document fetch. Permission
intersection is enforced.

## The agentic loop (`pkg/tools/loop.go`)

```go
func RunToolLoop(ctx context.Context, provider llm.Provider,
    messages []llm.Message, registry *Registry,
    config LoopConfig) (string, error)
```

Flow:

1. Build tool definitions from registry (filtered by
   `allowed_tools`)
2. Call `provider.CompleteWithTools(messages, toolDefs)`
3. If response has no tool calls → return text response (done)
4. If response has tool calls:
   a. For each tool call: look up handler in registry
   b. If hook is registered, call `hook.BeforeToolCall` — if
      denied, return error result to the LLM
   c. Execute the tool, collect result
   d. Append tool results as a new message
   e. Loop back to step 2
5. Safety: max iterations (default 10, configurable) — if
   exceeded, return accumulated results with a warning

Design decisions:

- **Sequential tool execution** (not parallel) — simpler, sufficient
  for document tasks. Can add parallel later.
- **Stateless** — each A2A request gets a fresh loop. No persistence
  between requests.
- **Max iterations configurable** via `agent-config.yaml`
  (default 10).

## Skill loading (`pkg/skills/loader.go`)

### Discovery

At startup, the loader scans `{config-dir}/skills/` for
subdirectories containing `SKILL.md` files:

```text
/config/agent/skills/
├── code-review/
│   └── SKILL.md
└── pdf-converter/
    └── SKILL.md
```

Each `SKILL.md` has YAML frontmatter with `name` and `description`,
followed by full instructions in Markdown.

### Progressive disclosure

1. At startup: read only frontmatter, build skill summary
2. Append summary to system prompt (example):

   ```text
   Available skills (call load_skill to get full instructions):
     - code-review: Review code for bugs, security, and quality
     - pdf-converter: Convert PDF documents to text
   ```

3. Register `load_skill` tool in the tool registry
4. When the LLM calls `load_skill("code-review")`, the full
   SKILL.md content is returned as a tool result and injected
   into the conversation

The LLM pays the context cost only when the skill is relevant.

### ConfigMap delivery

Skills are delivered as ConfigMap entries, mounted into the
`skills/` subdirectory. For skills too large for ConfigMaps
(>1MB), a PVC with an init container is the escape hatch.

Future: OCI artifacts for distributing skill bundles via
enterprise registries (Quay, Harbor, GHCR). Init container
pulls with `oras`. Designed but not built in phase 2.

## Configuration (`agent-config.yaml`)

New optional file in the config-dir:

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

**Backward compatibility:** If `agent-config.yaml` is missing,
the agent runs in phase 1 mode — single-shot LLM call, no tools,
no loop. Existing ConfigMaps work unchanged.

**Deny patterns for exec:** PicoClaw-based defaults are always
applied (35+ patterns blocking `rm -rf`, `sudo`, `docker run`,
`git push`, etc.). The config can add more but cannot remove
defaults.

## Integration with `serve.go`

Startup sequence additions (after existing phase 1 loading):

1. Load `agent-config.yaml` (optional — if missing, skip steps
   2-5)
2. Create tool registry with allowed tools from config
3. Load skills from `skills/` directory
4. Append skill summaries to system prompt
5. Register `load_skill` and `fetch_document` tools

The `processLLM` callback changes:

- **If tool registry exists:** pre-fetch the requested document,
  inject content into the initial messages, then call
  `RunToolLoop`. The LLM can respond immediately (if the content
  is sufficient) or call tools for additional work.
- **If no tool registry:** single-shot `Complete()` as today.

The `a2abridge.AgentExecutor` does not change. The `processLLM`
signature stays `func(ctx, title, content string) (string, error)`.

## Container images

The tool set affects what binaries must be available in the image:

```text
zt-agent:base      — exec, curl, jq, common CLI tools
zt-agent:docs      — base + pdftotext, pandoc
zt-agent:research  — base + python3, pip packages
```

Each image can run any agent personality via ConfigMap. The
Dockerfile determines available capabilities, the ConfigMap
determines behavior. 2-4 specialized images is fine — the
Go binary is always the same.

## Out of scope (phase 2)

- Hook implementation (OPA tool approval) — interface defined only
- MCP client — interface designed, implementation deferred
- Parallel tool execution — sequential only
- Web search tool — deferred
- Session persistence — stateless
- Context compression — not needed for document tasks
- Subagent spawning within zt-agent — separate agents via Kagenti
- Streaming — A2A protocol doesn't require it
- OCI-based skill distribution — designed, not built

## Success criteria

1. A zt-agent with `agent-config.yaml` listing tools can execute
   multi-step tasks (e.g., "fetch DOC-001, convert to plain text,
   summarize, then fetch DOC-002 and compare")
2. A SKILL.md loaded from `skills/` directory is discoverable via
   `load_skill` and the LLM follows its instructions
3. The same zt-agent without `agent-config.yaml` behaves
   identically to phase 1 (backward compatible)
4. `exec` tool blocks denied commands (PicoClaw deny patterns)
5. `fetch_document` tool enforces delegation/OPA authorization
6. All existing demo scenarios still pass
