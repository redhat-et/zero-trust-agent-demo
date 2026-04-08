package tools

import (
	"sort"
	"sync"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/llm"
)

type Registry struct {
	mu            sync.RWMutex
	tools         map[string]Tool
	alwaysAllowed map[string]bool
	allowedFilter map[string]bool // nil means all allowed
}

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

func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

func (r *Registry) RegisterAlwaysAllowed(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
	r.alwaysAllowed[t.Name()] = true
}

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
