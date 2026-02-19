package a2abridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2aclient/agentcard"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// LabelType is the label selector used to discover A2A agents.
	LabelType = "a2a-agent.demo/type"
	// LabelProtocol is the protocol hint label.
	LabelProtocol = "a2a-agent.demo/protocol"
	// AnnotationDescription is an optional annotation for agent description.
	AnnotationDescription = "a2a-agent.demo/description"

	labelSelector = LabelType + "=agent"
)

// DiscoveredAgent holds the result of discovering a single A2A agent.
type DiscoveredAgent struct {
	ID           string
	Name         string
	Description  string
	Capabilities []string
	SPIFFEID     string
	A2AURL       string
	Card         *a2a.AgentCard
}

// AgentDiscovery discovers A2A agents from Kubernetes Deployments.
type AgentDiscovery struct {
	clientset    kubernetes.Interface
	namespace    string
	trustDomain  string
	scheme       string
	httpClient   *http.Client
	cardResolver *agentcard.Resolver
	log          *slog.Logger
}

// DiscoveryConfig holds configuration for agent discovery.
type DiscoveryConfig struct {
	Namespace   string
	TrustDomain string
	// Scheme is the URL scheme for connecting to discovered agents ("http" or "https").
	// Defaults to "https" since in-cluster services typically use mTLS.
	Scheme string
}

// NewAgentDiscovery creates a new discovery instance using in-cluster config.
func NewAgentDiscovery(cfg DiscoveryConfig, httpClient *http.Client, log *slog.Logger) (*AgentDiscovery, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}

	return &AgentDiscovery{
		clientset:    clientset,
		namespace:    cfg.Namespace,
		trustDomain:  cfg.TrustDomain,
		scheme:       scheme,
		httpClient:   httpClient,
		cardResolver: agentcard.NewResolver(httpClient),
		log:          log,
	}, nil
}

// Discover scans for Deployments with the A2A agent label and fetches their agent cards.
func (d *AgentDiscovery) Discover(ctx context.Context) ([]DiscoveredAgent, error) {
	deployments, err := d.clientset.AppsV1().Deployments(d.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	var agents []DiscoveredAgent
	for _, deploy := range deployments.Items {
		name := deploy.Name
		// Derive the agent ID from the deployment name (strip -service suffix)
		agentID := strings.TrimSuffix(name, "-service")

		// Build in-cluster URL: {scheme}://{name}.{namespace}.svc.cluster.local:{port}
		port := resolvePort(&deploy)
		baseURL := fmt.Sprintf("%s://%s.%s.svc.cluster.local:%d", d.scheme, name, d.namespace, port)

		d.log.Info("Discovering A2A agent", "deployment", name, "url", baseURL)

		card, err := d.cardResolver.Resolve(ctx, baseURL)
		if err != nil {
			d.log.Warn("Failed to fetch agent card, skipping", "deployment", name, "error", err)
			continue
		}

		// Extract capabilities from skill tags
		capabilities := extractCapabilities(card)

		// Build description from annotation or card
		description := card.Description
		if ann, ok := deploy.Annotations[AnnotationDescription]; ok && ann != "" {
			description = ann
		}

		agents = append(agents, DiscoveredAgent{
			ID:           agentID,
			Name:         card.Name,
			Description:  description,
			Capabilities: capabilities,
			SPIFFEID:     "spiffe://" + d.trustDomain + "/agent/" + agentID,
			A2AURL:       baseURL + "/a2a",
			Card:         card,
		})

		d.log.Info("Discovered A2A agent",
			"id", agentID,
			"name", card.Name,
			"capabilities", capabilities)
	}

	return agents, nil
}

// resolvePort extracts the first container port from a Deployment spec.
// Falls back to 8080 if no port is found.
func resolvePort(deploy *appsv1.Deployment) int {
	for _, c := range deploy.Spec.Template.Spec.Containers {
		for _, p := range c.Ports {
			if p.ContainerPort > 0 {
				return int(p.ContainerPort)
			}
		}
	}
	return 8080
}

// extractCapabilities collects all unique tags from an agent card's skills.
func extractCapabilities(card *a2a.AgentCard) []string {
	seen := make(map[string]bool)
	var caps []string
	for _, skill := range card.Skills {
		for _, tag := range skill.Tags {
			if !seen[tag] {
				seen[tag] = true
				caps = append(caps, tag)
			}
		}
	}
	return caps
}
