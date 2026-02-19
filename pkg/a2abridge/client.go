package a2abridge

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2aclient"
)

// A2AClient wraps the a2aclient to send delegation requests to A2A agents.
type A2AClient struct {
	httpClient *http.Client
	log        *slog.Logger
}

// NewA2AClient creates a new A2A client wrapper.
func NewA2AClient(httpClient *http.Client, log *slog.Logger) *A2AClient {
	return &A2AClient{
		httpClient: httpClient,
		log:        log,
	}
}

// InvokeRequest holds the parameters for invoking an A2A agent.
type InvokeRequest struct {
	AgentURL        string
	Card            *a2a.AgentCard
	DocumentID      string
	UserSPIFFEID    string
	UserDepartments []string
	ReviewType      string
}

// InvokeResult holds the response from an A2A agent invocation.
type InvokeResult struct {
	Text  string `json:"text"`
	State string `json:"state"`
}

// Invoke sends a message/send request to an A2A agent with delegation context.
func (c *A2AClient) Invoke(ctx context.Context, req *InvokeRequest) (*InvokeResult, error) {
	// Build the delegation context as a DataPart
	data := map[string]any{
		"document_id":    req.DocumentID,
		"user_spiffe_id": req.UserSPIFFEID,
	}
	if len(req.UserDepartments) > 0 {
		data["user_departments"] = req.UserDepartments
	}
	if req.ReviewType != "" {
		data["review_type"] = req.ReviewType
	}

	msg := a2a.NewMessage(a2a.MessageRoleUser, &a2a.DataPart{Data: data})

	params := &a2a.MessageSendParams{
		Message: msg,
	}

	// Create a2a client using the A2A URL with explicit JSONRPC transport.
	// We always use NewFromEndpoints because discovered agent cards may not
	// declare PreferredTransport, causing transport matching to fail.
	opts := []a2aclient.FactoryOption{
		a2aclient.WithDefaultsDisabled(),
		a2aclient.WithJSONRPCTransport(c.httpClient),
	}

	endpoints := []a2a.AgentInterface{
		{URL: req.AgentURL, Transport: a2a.TransportProtocolJSONRPC},
	}
	client, err := a2aclient.NewFromEndpoints(ctx, endpoints, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create A2A client: %w", err)
	}

	c.log.Info("Sending A2A message/send",
		"url", req.AgentURL,
		"document_id", req.DocumentID,
		"user_spiffe_id", req.UserSPIFFEID)

	result, err := client.SendMessage(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("A2A message/send failed: %w", err)
	}

	return c.parseResult(result)
}

// parseResult extracts text from a SendMessageResult (Task or Message).
func (c *A2AClient) parseResult(result a2a.SendMessageResult) (*InvokeResult, error) {
	switch r := result.(type) {
	case *a2a.Task:
		return c.parseTask(r)
	case *a2a.Message:
		return c.parseMessage(r)
	default:
		return nil, fmt.Errorf("unexpected result type: %T", result)
	}
}

func (c *A2AClient) parseTask(task *a2a.Task) (*InvokeResult, error) {
	state := string(task.Status.State)

	// Check for failure or rejection
	if task.Status.State == a2a.TaskStateFailed || task.Status.State == a2a.TaskStateRejected {
		reason := "agent returned " + state
		if task.Status.Message != nil {
			if text := extractTextFromParts(task.Status.Message.Parts); text != "" {
				reason = text
			}
		}
		return &InvokeResult{Text: reason, State: state}, nil
	}

	// Extract text from artifacts
	for _, artifact := range task.Artifacts {
		if text := extractTextFromParts(artifact.Parts); text != "" {
			return &InvokeResult{Text: text, State: state}, nil
		}
	}

	// Fall back to status message
	if task.Status.Message != nil {
		if text := extractTextFromParts(task.Status.Message.Parts); text != "" {
			return &InvokeResult{Text: text, State: state}, nil
		}
	}

	return &InvokeResult{Text: "", State: state}, nil
}

func (c *A2AClient) parseMessage(msg *a2a.Message) (*InvokeResult, error) {
	text := extractTextFromParts(msg.Parts)
	return &InvokeResult{Text: text, State: "completed"}, nil
}

// extractTextFromParts concatenates text from all TextParts in a part list.
func extractTextFromParts(parts []a2a.Part) string {
	var texts []string
	for _, part := range parts {
		if tp, ok := part.(*a2a.TextPart); ok && tp.Text != "" {
			texts = append(texts, tp.Text)
		}
	}
	if len(texts) == 0 {
		return ""
	}
	result := texts[0]
	for _, t := range texts[1:] {
		result += "\n" + t
	}
	return result
}
