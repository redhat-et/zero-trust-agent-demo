package store

import (
	"sync"

	"github.com/a2aproject/a2a-go/a2a"
)

// AgentSource indicates how an agent was registered.
type AgentSource string

const (
	// SourceStatic indicates a hardcoded demo agent.
	SourceStatic AgentSource = "static"
	// SourceDiscovered indicates an agent discovered via Kubernetes.
	SourceDiscovered AgentSource = "discovered"
)

// Agent represents an AI agent in the system
type Agent struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Capabilities []string        `json:"capabilities"`
	SPIFFEID     string          `json:"spiffe_id"`
	Description  string          `json:"description"`
	Source       AgentSource     `json:"source"`
	A2AURL       string          `json:"a2a_url,omitempty"`
	AgentCard    *a2a.AgentCard  `json:"-"`
}

// AgentStore is an in-memory agent store with thread-safe access.
type AgentStore struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

// NewAgentStore creates a new agent store with sample agents
func NewAgentStore(trustDomain string) *AgentStore {
	store := &AgentStore{
		agents: make(map[string]*Agent),
	}
	store.loadSampleAgents(trustDomain)
	return store
}

func (s *AgentStore) loadSampleAgents(trustDomain string) {
	// Agents as defined in the design document
	s.agents["gpt4"] = &Agent{
		ID:           "gpt4",
		Name:         "GPT-4 Agent",
		Capabilities: []string{"engineering", "finance"},
		SPIFFEID:     "spiffe://" + trustDomain + "/agent/gpt4",
		Description:  "General-purpose AI assistant with engineering and finance access",
		Source:       SourceStatic,
	}

	s.agents["claude"] = &Agent{
		ID:           "claude",
		Name:         "Claude Agent",
		Capabilities: []string{"engineering", "finance", "admin", "hr"},
		SPIFFEID:     "spiffe://" + trustDomain + "/agent/claude",
		Description:  "Unrestricted AI assistant with access to all departments",
		Source:       SourceStatic,
	}

	s.agents["summarizer"] = &Agent{
		ID:           "summarizer",
		Name:         "Summarizer Agent",
		Capabilities: []string{"finance"},
		SPIFFEID:     "spiffe://" + trustDomain + "/agent/summarizer",
		Description:  "Specialized agent for summarizing financial documents only",
		Source:       SourceStatic,
	}

	s.agents["reviewer"] = &Agent{
		ID:           "reviewer",
		Name:         "Reviewer Agent",
		Capabilities: []string{"engineering", "finance", "admin", "hr"},
		SPIFFEID:     "spiffe://" + trustDomain + "/agent/reviewer",
		Description:  "Reviews documents for compliance, security, and general issues",
		Source:       SourceStatic,
	}
}

// Register adds or updates an agent in the store.
func (s *AgentStore) Register(agent *Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID] = agent
}

// Remove deletes an agent from the store by ID.
func (s *AgentStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, id)
}

// Get retrieves an agent by ID
func (s *AgentStore) Get(id string) (*Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agent, ok := s.agents[id]
	return agent, ok
}

// List returns all agents
func (s *AgentStore) List() []*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	return agents
}

// GetIDs returns all agent IDs
func (s *AgentStore) GetIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}

// DiscoveredIDs returns the IDs of all discovered agents.
func (s *AgentStore) DiscoveredIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []string
	for id, agent := range s.agents {
		if agent.Source == SourceDiscovered {
			ids = append(ids, id)
		}
	}
	return ids
}
