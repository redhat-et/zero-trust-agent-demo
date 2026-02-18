package a2abridge

import (
	"github.com/a2aproject/a2a-go/a2a"
)

// AgentCardParams holds the parameters for building an A2A AgentCard.
type AgentCardParams struct {
	Name        string
	Description string
	Version     string
	URL         string
	Skills      []a2a.AgentSkill
}

// BuildAgentCard creates an a2a.AgentCard from the given parameters.
func BuildAgentCard(p AgentCardParams) *a2a.AgentCard {
	return &a2a.AgentCard{
		Name:            p.Name,
		Description:     p.Description,
		Version:         p.Version,
		URL:             p.URL,
		ProtocolVersion: "0.3.0",
		Skills:          p.Skills,
		Capabilities:    a2a.AgentCapabilities{},
		DefaultInputModes: []string{
			"application/json",
		},
		DefaultOutputModes: []string{
			"text/plain",
		},
	}
}
