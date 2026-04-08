# Docsclaw extraction plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract zt-agent into a standalone repo
(`redhat-et/docsclaw`) with proper `pkg/` vs `internal/` package
structure, clean go.mod, and working CI.

**Architecture:** Create new repo with public interfaces in `pkg/`
(tools, llm, skills) and built-in implementations in `internal/`.
The cmd binary is `docsclaw`. The demo repo consumes docsclaw as a
container image — no Go import dependency.

**Tech Stack:** Go 1.25, Anthropic SDK v1.20.0, a2a-go v0.3.6,
Cobra/Viper, Prometheus.

---

## File structure

Source (zero-trust-agent-demo) → Target (docsclaw):

| Source | Target | Notes |
|--------|--------|-------|
| `pkg/llm/provider.go` | `pkg/llm/provider.go` | Public: Provider interface |
| `pkg/llm/tools.go` | `pkg/llm/types.go` | Public: Message, ToolCall, Response types |
| `pkg/llm/config.go` | `pkg/llm/config.go` | Public: Config, constants |
| `pkg/llm/factory.go` | `pkg/llm/factory.go` | Public: NewProvider |
| `pkg/llm/prompts.go` | `pkg/llm/prompts.go` | Public: prompt constants |
| `pkg/llm/anthropic.go` | `internal/anthropic/anthropic.go` | Internal: Anthropic impl |
| `pkg/llm/openai_compat.go` | `internal/openai/openai.go` | Internal: OpenAI impl |
| `pkg/llm/tools_test.go` | `pkg/llm/types_test.go` | Tests |
| `pkg/tools/tool.go` | `pkg/tools/tool.go` | Public: Tool, ToolResult |
| `pkg/tools/registry.go` | `pkg/tools/registry.go` | Public: Registry |
| `pkg/tools/hooks.go` | `pkg/tools/hooks.go` | Public: Hook interface |
| `pkg/tools/loop.go` | `pkg/tools/loop.go` | Public: RunToolLoop |
| `pkg/tools/loop_test.go` | `pkg/tools/loop_test.go` | Tests |
| `pkg/tools/registry_test.go` | `pkg/tools/registry_test.go` | Tests |
| `pkg/tools/exec.go` | `internal/exec/exec.go` | Internal: exec tool |
| `pkg/tools/exec_test.go` | `internal/exec/exec_test.go` | Tests |
| `pkg/tools/webfetch.go` | `internal/webfetch/webfetch.go` | Internal: web_fetch |
| `pkg/tools/readfile.go` | `internal/readfile/readfile.go` | Internal: read_file |
| `pkg/tools/writefile.go` | `internal/writefile/writefile.go` | Internal: write_file |
| `pkg/tools/fetchdoc.go` | `internal/fetchdoc/fetchdoc.go` | Internal: fetch_document |
| `pkg/tools/workspace.go` | `internal/workspace/workspace.go` | Internal: path validation |
| `pkg/skills/loader.go` | `pkg/skills/loader.go` | Public: Discover, Load |
| `pkg/skills/loader_test.go` | `pkg/skills/loader_test.go` | Tests |
| `pkg/a2abridge/executor.go` | `internal/bridge/executor.go` | Internal: A2A executor |
| `pkg/a2abridge/message.go` | `internal/bridge/message.go` | Internal: message parsing |
| `pkg/a2abridge/delegation.go` | `internal/bridge/delegation.go` | Internal: delegation ctx |
| `pkg/a2abridge/signedcard.go` | `internal/bridge/signedcard.go` | Internal: signed cards |
| `pkg/a2abridge/client.go` | `internal/bridge/client.go` | Internal: A2A client |
| `pkg/a2abridge/agentcard.go` | `internal/bridge/agentcard.go` | Internal: agent card helper |
| `pkg/config/config.go` | `internal/config/config.go` | Internal: Viper config |
| `pkg/logger/logger.go` | `internal/logger/logger.go` | Internal: colored slog |
| `pkg/metrics/metrics.go` | `internal/metrics/metrics.go` | Internal: Prometheus |
| `zt-agent/cmd/root.go` | `cmd/docsclaw/root.go` | Renamed binary |
| `zt-agent/cmd/serve.go` | `cmd/docsclaw/serve.go` | Main wiring |
| `zt-agent/cmd/agentconfig.go` | `cmd/docsclaw/agentconfig.go` | Config loading |
| `zt-agent/cmd/serve_test.go` | `cmd/docsclaw/serve_test.go` | Tests |
| `zt-agent/testdata/` | `testdata/` | Test fixtures |

**Not extracted** (demo-specific):
- `pkg/a2abridge/discovery.go` — K8s AgentCard CRD discovery
- `pkg/spiffe/` — SPIFFE workload client
- `pkg/auth/` — OIDC/Keycloak auth
- `pkg/storage/` — S3 storage
- `pkg/telemetry/` — OpenTelemetry

---

### Task 1: Create repo and scaffold

- [ ] **Step 1: Create the GitHub repo**

```bash
gh repo create redhat-et/docsclaw \
  --public \
  --description "ConfigMap-driven agentic runtime with A2A protocol support" \
  --clone
```

- [ ] **Step 2: Initialize Go module**

```bash
cd docsclaw
go mod init github.com/redhat-et/docsclaw
```

- [ ] **Step 3: Create directory structure**

```bash
mkdir -p cmd/docsclaw
mkdir -p pkg/llm pkg/tools pkg/skills
mkdir -p internal/anthropic internal/openai
mkdir -p internal/exec internal/webfetch internal/readfile
mkdir -p internal/writefile internal/fetchdoc internal/workspace
mkdir -p internal/bridge internal/config internal/logger internal/metrics
mkdir -p testdata/standalone testdata/research-agent/skills/pdf-summary
```

- [ ] **Step 4: Create CLAUDE.md**

```markdown
# CLAUDE.md - Docsclaw Project Guide

## Overview

Docsclaw is a ConfigMap-driven agentic runtime that turns any LLM
into a tool-using A2A-compatible agent. Deploy with a system prompt,
agent card, and tool config — no code changes needed.

## Quick Start

    make build
    ANTHROPIC_API_KEY=sk-... ./bin/docsclaw serve \
      --config-dir testdata/standalone --listen-plain-http

## Project Structure

    docsclaw/
    ├── cmd/docsclaw/      # CLI (serve command)
    ├── pkg/               # Public API
    │   ├── llm/           # Provider interface, types
    │   ├── tools/         # Tool interface, Registry, RunToolLoop
    │   └── skills/        # SKILL.md discovery and loading
    ├── internal/          # Implementation details
    │   ├── anthropic/     # Anthropic provider
    │   ├── openai/        # OpenAI-compatible provider
    │   ├── exec/          # exec tool
    │   ├── webfetch/      # web_fetch tool
    │   ├── readfile/      # read_file tool
    │   ├── writefile/     # write_file tool
    │   ├── fetchdoc/      # fetch_document tool
    │   ├── workspace/     # Path validation
    │   ├── bridge/        # A2A executor wiring
    │   ├── config/        # Viper configuration
    │   ├── logger/        # Colored slog wrapper
    │   └── metrics/       # Prometheus metrics
    └── testdata/          # Test fixtures

## Build and Test

| Target | Description |
| ------ | ----------- |
| `make build` | Build to `bin/docsclaw` |
| `make test` | Run all tests |
| `make lint` | Run golangci-lint |
| `make fmt` | Format code |

## Key Technologies

- **Go 1.25** with log/slog
- **Anthropic SDK** for Claude models
- **OpenAI-compatible API** for other providers
- **A2A protocol** (a2a-go) for agent communication
- **Cobra/Viper** for CLI and config
```

- [ ] **Step 5: Create Makefile**

```makefile
BINARY := docsclaw
BINDIR := bin

.PHONY: build test lint fmt clean

build:
	go build -o $(BINDIR)/$(BINARY) ./cmd/docsclaw

test:
	go test ./... -v

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

clean:
	rm -rf $(BINDIR)
```

- [ ] **Step 6: Commit scaffold**

```bash
git add -A
git commit -s -m "chore: scaffold docsclaw repo structure"
```

---

### Task 2: Copy public packages (pkg/)

Copy the public-API packages with updated module paths.

- [ ] **Step 1: Copy pkg/llm public files**

Copy from demo repo to docsclaw, updating the module path in all
imports from `github.com/redhat-et/zero-trust-agent-demo/pkg/llm`
to `github.com/redhat-et/docsclaw/pkg/llm`:

- `pkg/llm/provider.go` — Provider interface (add CompleteWithTools)
- `pkg/llm/tools.go` → `pkg/llm/types.go` — rename for clarity
- `pkg/llm/config.go` — Config struct, constants
- `pkg/llm/factory.go` — NewProvider (will need update for
  internal imports later)
- `pkg/llm/prompts.go` — prompt constants
- `pkg/llm/tools_test.go` → `pkg/llm/types_test.go`

For factory.go, temporarily stub the provider constructors since
the implementations move to internal/:

```go
package llm

import "fmt"

// NewProvider creates a Provider based on the config.
// Provider implementations are registered at init time.
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case ProviderAnthropic:
		return newAnthropicProvider(cfg)
	case ProviderOpenAI, ProviderLiteLLM, "":
		return newOpenAICompatProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown provider: %s", cfg.Provider)
	}
}

// Provider constructors — set by internal packages via init().
var (
	newAnthropicProvider   func(Config) (Provider, error)
	newOpenAICompatProvider func(Config) (Provider, error)
)

// RegisterAnthropicProvider is called by internal/anthropic init().
func RegisterAnthropicProvider(fn func(Config) (Provider, error)) {
	newAnthropicProvider = fn
}

// RegisterOpenAICompatProvider is called by internal/openai init().
func RegisterOpenAICompatProvider(fn func(Config) (Provider, error)) {
	newOpenAICompatProvider = fn
}
```

- [ ] **Step 2: Copy pkg/tools public files**

Copy these files, updating module path to
`github.com/redhat-et/docsclaw/pkg/llm` in imports:

- `pkg/tools/tool.go`
- `pkg/tools/registry.go`
- `pkg/tools/hooks.go`
- `pkg/tools/loop.go`
- `pkg/tools/loop_test.go`
- `pkg/tools/registry_test.go`

- [ ] **Step 3: Copy pkg/skills**

Copy these files (no module-path imports to update — stdlib only):

- `pkg/skills/loader.go`
- `pkg/skills/loader_test.go`

- [ ] **Step 4: Verify public packages parse**

```bash
# Won't fully build yet (missing internal packages) but should parse
go vet ./pkg/...
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "feat: add public API packages (llm, tools, skills)"
```

---

### Task 3: Copy internal packages

- [ ] **Step 1: Copy internal/anthropic**

Copy `pkg/llm/anthropic.go` to `internal/anthropic/anthropic.go`.
Change package to `anthropic`. Update imports to use
`github.com/redhat-et/docsclaw/pkg/llm`. Add init() registration:

```go
func init() {
	llm.RegisterAnthropicProvider(func(cfg llm.Config) (llm.Provider, error) {
		return NewAnthropicProvider(cfg)
	})
}
```

Export the constructor: `NewAnthropicProvider`.
The type `AnthropicProvider` stays unexported or exported — keep
it exported for testability. All methods reference `llm.Message`,
`llm.ToolDefinition`, `llm.Response`, etc.

- [ ] **Step 2: Copy internal/openai**

Same pattern as anthropic. Copy `pkg/llm/openai_compat.go` to
`internal/openai/openai.go`. Change package to `openai`.
Add init() registration for `llm.RegisterOpenAICompatProvider`.

- [ ] **Step 3: Copy internal/exec**

Copy `pkg/tools/exec.go` to `internal/exec/exec.go`. Change
package to `exec`. Update imports. Export `NewExecTool` and
`ExecConfig`. Copy `exec_test.go` too.

- [ ] **Step 4: Copy internal/webfetch**

Copy `pkg/tools/webfetch.go` to `internal/webfetch/webfetch.go`.
Change package to `webfetch`. Export `NewWebFetchTool`,
`WebFetchConfig`.

- [ ] **Step 5: Copy internal/readfile, writefile, fetchdoc, workspace**

Copy each tool to its own internal package. Each exports its
constructor (`NewReadFileTool`, etc.). The workspace package
exports `IsInsideWorkspace`.

readfile and writefile import
`github.com/redhat-et/docsclaw/internal/workspace` instead of
calling `isInsideWorkspace` from the same package.

- [ ] **Step 6: Copy internal/bridge**

Copy from `pkg/a2abridge/` all files EXCEPT `discovery.go` to
`internal/bridge/`. Change package to `bridge`. Update imports.

- [ ] **Step 7: Copy internal/config, logger, metrics**

Copy `pkg/config/config.go` → `internal/config/config.go`
Copy `pkg/logger/logger.go` → `internal/logger/logger.go`
Copy `pkg/metrics/metrics.go` → `internal/metrics/metrics.go`

Update all imports to new module path.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -s -m "feat: add internal packages (providers, tools, bridge)"
```

---

### Task 4: Copy cmd and test fixtures

- [ ] **Step 1: Copy cmd/docsclaw**

Copy `zt-agent/cmd/*.go` to `cmd/docsclaw/`. Update:
- Package stays `cmd` (or change to `main` with `package main`)
- Actually, Cobra pattern uses `package cmd` with a separate
  `main.go`. Copy the pattern from zt-agent.
- Update all imports to docsclaw module path.
- Rename binary references from "zt-agent" to "docsclaw".
- In root.go, change `rootCmd.Use` to `"docsclaw"`.

Create `cmd/docsclaw/main.go`:

```go
package main

import (
	"github.com/redhat-et/docsclaw/cmd/docsclaw/cmd"

	// Register provider implementations
	_ "github.com/redhat-et/docsclaw/internal/anthropic"
	_ "github.com/redhat-et/docsclaw/internal/openai"
)

func main() {
	cmd.Execute()
}
```

Wait — this won't work with Cobra's typical `cmd` package layout.
Let me reconsider. The standard Cobra pattern is:

```
cmd/docsclaw/main.go     → package main, calls cmd.Execute()
internal/cmd/root.go     → package cmd
internal/cmd/serve.go    → package cmd
internal/cmd/agentconfig.go → package cmd
```

This keeps the cmd wiring internal (users run the binary, not
import the package). Update the file structure:

- `zt-agent/cmd/root.go` → `internal/cmd/root.go`
- `zt-agent/cmd/serve.go` → `internal/cmd/serve.go`
- `zt-agent/cmd/agentconfig.go` → `internal/cmd/agentconfig.go`
- `zt-agent/cmd/serve_test.go` → `internal/cmd/serve_test.go`
- Create `cmd/docsclaw/main.go`

- [ ] **Step 2: Copy test fixtures**

```bash
cp -r zt-agent/testdata/* testdata/
```

- [ ] **Step 3: Update serve.go imports**

In `internal/cmd/serve.go`, update all imports:

```go
import (
	"github.com/redhat-et/docsclaw/internal/bridge"
	"github.com/redhat-et/docsclaw/internal/config"
	"github.com/redhat-et/docsclaw/internal/exec"
	"github.com/redhat-et/docsclaw/internal/fetchdoc"
	"github.com/redhat-et/docsclaw/internal/readfile"
	"github.com/redhat-et/docsclaw/internal/webfetch"
	"github.com/redhat-et/docsclaw/internal/writefile"
	"github.com/redhat-et/docsclaw/internal/logger"
	_ "github.com/redhat-et/docsclaw/internal/metrics"
	"github.com/redhat-et/docsclaw/pkg/llm"
	"github.com/redhat-et/docsclaw/pkg/skills"
	"github.com/redhat-et/docsclaw/pkg/tools"
)
```

Update tool registration calls:
- `tools.NewExecTool(...)` → `exec.New(...)`
- `tools.NewWebFetchTool(...)` → `webfetch.New(...)`
- etc.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -s -m "feat: add cmd/docsclaw and test fixtures"
```

---

### Task 5: Add dependencies and build

- [ ] **Step 1: Add Go dependencies**

```bash
go get github.com/anthropics/anthropic-sdk-go@v1.20.0
go get github.com/a2aproject/a2a-go@v0.3.6
go get github.com/spf13/cobra@v1.10.1
go get github.com/spf13/viper@v1.21.0
go get github.com/prometheus/client_golang@v1.23.2
go get gopkg.in/yaml.v3@v3.0.1
go mod tidy
```

- [ ] **Step 2: Build**

```bash
make build
```

Fix any remaining import path issues until it compiles.

- [ ] **Step 3: Run tests**

```bash
make test
```

- [ ] **Step 4: Run linter**

```bash
make lint
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -s -m "chore: add dependencies and verify build"
```

---

### Task 6: Verify standalone operation

- [ ] **Step 1: Test help output**

```bash
./bin/docsclaw --help
./bin/docsclaw serve --help
```

Expected: Shows "docsclaw" in usage, not "zt-agent".

- [ ] **Step 2: Test phase 1 mode (no agent-config.yaml)**

```bash
./bin/docsclaw serve \
  --config-dir testdata/research-agent \
  --listen-plain-http --help
```

- [ ] **Step 3: Test phase 2 mode with mock**

```bash
./bin/docsclaw serve \
  --config-dir testdata/standalone \
  --listen-plain-http &
sleep 2
curl -s http://localhost:8000/health | jq .
curl -s http://localhost:8000/.well-known/agent-card.json | jq .name
kill %1
```

Expected: Health OK, agent name is "standalone-agent".

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -s -m "fix: resolve issues found during verification"
```

---

### Task 7: Tag demo repo and push docsclaw

- [ ] **Step 1: Tag the demo repo**

In the demo repo directory:

```bash
cd /Users/panni/work/zero-trust-agent-demo
git tag -a v0.9-with-legacy-agents \
  -m "Last version with all agent code in-tree (zt-agent, legacy Python/Go agents)"
git push origin v0.9-with-legacy-agents
```

- [ ] **Step 2: Push docsclaw**

```bash
cd /path/to/docsclaw
git push -u origin main
```

- [ ] **Step 3: Verify on GitHub**

Check that https://github.com/redhat-et/docsclaw shows the repo
with correct structure and README.
