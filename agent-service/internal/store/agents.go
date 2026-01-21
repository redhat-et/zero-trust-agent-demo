package store

// Agent represents an AI agent in the system
type Agent struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	SPIFFEID     string   `json:"spiffe_id"`
	Description  string   `json:"description"`
}

// AgentStore is an in-memory agent store
type AgentStore struct {
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
	}

	s.agents["claude"] = &Agent{
		ID:           "claude",
		Name:         "Claude Agent",
		Capabilities: []string{"engineering", "finance", "admin", "hr"},
		SPIFFEID:     "spiffe://" + trustDomain + "/agent/claude",
		Description:  "Unrestricted AI assistant with access to all departments",
	}

	s.agents["summarizer"] = &Agent{
		ID:           "summarizer",
		Name:         "Summarizer Agent",
		Capabilities: []string{"finance"},
		SPIFFEID:     "spiffe://" + trustDomain + "/agent/summarizer",
		Description:  "Specialized agent for summarizing financial documents only",
	}
}

// Get retrieves an agent by ID
func (s *AgentStore) Get(id string) (*Agent, bool) {
	agent, ok := s.agents[id]
	return agent, ok
}

// List returns all agents
func (s *AgentStore) List() []*Agent {
	agents := make([]*Agent, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	return agents
}

// GetIDs returns all agent IDs
func (s *AgentStore) GetIDs() []string {
	ids := make([]string, 0, len(s.agents))
	for id := range s.agents {
		ids = append(ids, id)
	}
	return ids
}
