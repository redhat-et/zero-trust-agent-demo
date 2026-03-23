package a2abridge

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var agentCardGVR = schema.GroupVersionResource{
	Group:    "agent.kagenti.dev",
	Version:  "v1alpha1",
	Resource: "agentcards",
}

var spiffeIDRegex = regexp.MustCompile(`spiffe://\S+`)

// DiscoveredAgent holds the result of discovering a single A2A agent.
type DiscoveredAgent struct {
	ID          string
	Name        string
	Description string
	SPIFFEID    string
	A2AURL      string
	Version     string
}

// AgentDiscovery discovers A2A agents from Kagenti AgentCard CRs.
type AgentDiscovery struct {
	client    dynamic.Interface
	namespace string
	log       *slog.Logger
}

// DiscoveryConfig holds configuration for agent discovery.
type DiscoveryConfig struct {
	Namespace string
}

// NewAgentDiscovery creates a new discovery instance using in-cluster config.
func NewAgentDiscovery(cfg DiscoveryConfig, log *slog.Logger) (*AgentDiscovery, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &AgentDiscovery{
		client:    client,
		namespace: cfg.Namespace,
		log:       log,
	}, nil
}

// Discover lists AgentCard CRs and extracts agent metadata.
func (d *AgentDiscovery) Discover(ctx context.Context) ([]DiscoveredAgent, error) {
	list, err := d.client.Resource(agentCardGVR).Namespace(d.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list AgentCards: %w", err)
	}

	var agents []DiscoveredAgent
	for _, item := range list.Items {
		labels := item.GetLabels()
		agentID := labels["app.kubernetes.io/name"]
		if agentID == "" {
			agentID = item.GetName()
		}

		status, ok := item.Object["status"].(map[string]any)
		if !ok {
			d.log.Warn("AgentCard has no status", "name", item.GetName())
			continue
		}

		card, ok := status["card"].(map[string]any)
		if !ok {
			d.log.Warn("AgentCard has no card in status", "name", item.GetName())
			continue
		}

		name, _ := card["name"].(string)
		description, _ := card["description"].(string)
		url, _ := card["url"].(string)
		version, _ := card["version"].(string)

		if url == "" {
			d.log.Warn("AgentCard has no URL", "name", item.GetName())
			continue
		}

		// Extract SPIFFE ID from binding status message
		var spiffeID string
		if binding, ok := status["bindingStatus"].(map[string]any); ok {
			if msg, ok := binding["message"].(string); ok {
				if match := spiffeIDRegex.FindString(msg); match != "" {
					spiffeID = match
				}
			}
		}

		agents = append(agents, DiscoveredAgent{
			ID:          agentID,
			Name:        name,
			Description: description,
			SPIFFEID:    spiffeID,
			A2AURL:      url + "/a2a",
			Version:     version,
		})

		d.log.Info("Discovered AgentCard",
			"id", agentID,
			"name", name,
			"url", url,
			"spiffe_id", spiffeID)
	}

	return agents, nil
}
