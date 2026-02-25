package a2abridge

import (
	"context"
	"fmt"
	"strings"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2asrv"
	"github.com/a2aproject/a2a-go/a2asrv/eventqueue"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
)

// DocumentFetcher fetches a document by ID from the document-service.
// The bearerToken parameter is optional; when non-empty, it is forwarded
// as an Authorization header for JWT-based access control.
// Delegation context (X-Delegation-User/Agent headers) is injected
// automatically by DelegationTransport from the request context.
type DocumentFetcher func(ctx context.Context, documentID, bearerToken string) (map[string]any, error)

// LLMProcessor processes a document with an LLM and returns the result text.
type LLMProcessor func(ctx context.Context, title, content string) (string, error)

// AgentExecutor implements a2asrv.AgentExecutor by bridging A2A messages
// to document fetch and LLM processing.
type AgentExecutor struct {
	Log           *logger.Logger
	FetchDocument DocumentFetcher
	ProcessLLM    LLMProcessor
}

// Execute handles an incoming A2A message: extracts the document ID,
// fetches the document, processes it with the LLM, and writes results.
func (e *AgentExecutor) Execute(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue) error {
	// Transition to working state
	working := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateWorking, nil)
	if err := queue.Write(ctx, working); err != nil {
		return fmt.Errorf("failed to write working status: %w", err)
	}

	// Extract document ID from the incoming message
	documentID, err := ExtractDocumentID(reqCtx.Message)
	if err != nil {
		e.Log.Error("Failed to extract document ID from A2A message", "error", err)
		return e.writeFailed(ctx, reqCtx, queue, "Invalid request: "+err.Error())
	}

	// Extract bearer token and delegation context from the incoming A2A
	// request headers. The agent-service forwards the user's JWT and
	// delegation headers via A2A CallMeta, which the JSONRPC transport
	// maps to HTTP headers.
	var bearerToken string
	var userSPIFFEID, agentSPIFFEID string
	if callCtx, ok := a2asrv.CallContextFrom(ctx); ok {
		if vals, found := callCtx.RequestMeta().Get("authorization"); found && len(vals) > 0 {
			bearerToken = strings.TrimPrefix(vals[0], "Bearer ")
		}
		if vals, found := callCtx.RequestMeta().Get("x-delegation-user"); found && len(vals) > 0 {
			userSPIFFEID = vals[0]
		}
		if vals, found := callCtx.RequestMeta().Get("x-delegation-agent"); found && len(vals) > 0 {
			agentSPIFFEID = vals[0]
		}
	}

	e.Log.Info("A2A request received",
		"document_id", documentID,
		"has_bearer_token", bearerToken != "",
		"delegation_user", userSPIFFEID,
		"delegation_agent", agentSPIFFEID)

	// Store delegation context so DelegationTransport can inject headers
	// on outbound HTTP requests (e.g., to document-service).
	if userSPIFFEID != "" || agentSPIFFEID != "" {
		ctx = WithDelegation(ctx, DelegationContext{
			UserSPIFFEID:  userSPIFFEID,
			AgentSPIFFEID: agentSPIFFEID,
		})
	}

	// Fetch the document
	doc, err := e.FetchDocument(ctx, documentID, bearerToken)
	if err != nil {
		e.Log.Error("Document fetch failed", "error", err)
		return e.writeFailed(ctx, reqCtx, queue, err.Error())
	}
	if doc == nil || doc["content"] == nil {
		e.Log.Deny("Access denied by document service")
		return e.writeRejected(ctx, reqCtx, queue, "Access denied")
	}

	e.Log.Allow("Document access granted via A2A")

	title, _ := doc["title"].(string)
	content, _ := doc["content"].(string)

	// Process with LLM
	result, err := e.ProcessLLM(ctx, title, content)
	if err != nil {
		e.Log.Error("LLM processing failed", "error", err)
		return e.writeFailed(ctx, reqCtx, queue, "LLM processing failed: "+err.Error())
	}

	// Write the result as an artifact
	artifact := a2a.NewArtifactEvent(reqCtx, &a2a.TextPart{Text: result})
	if err := queue.Write(ctx, artifact); err != nil {
		return fmt.Errorf("failed to write artifact: %w", err)
	}

	// Mark completed
	completed := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateCompleted, nil)
	completed.Final = true
	if err := queue.Write(ctx, completed); err != nil {
		return fmt.Errorf("failed to write completed status: %w", err)
	}

	return nil
}

// Cancel handles task cancellation.
func (e *AgentExecutor) Cancel(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue) error {
	event := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateCanceled, nil)
	event.Final = true
	return queue.Write(ctx, event)
}

func (e *AgentExecutor) writeFailed(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue, reason string) error {
	msg := a2a.NewMessage(a2a.MessageRoleAgent, &a2a.TextPart{Text: reason})
	event := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateFailed, msg)
	event.Final = true
	if err := queue.Write(ctx, event); err != nil {
		return fmt.Errorf("failed to write failed status: %w", err)
	}
	return nil
}

func (e *AgentExecutor) writeRejected(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue, reason string) error {
	msg := a2a.NewMessage(a2a.MessageRoleAgent, &a2a.TextPart{Text: reason})
	event := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateRejected, msg)
	event.Final = true
	if err := queue.Write(ctx, event); err != nil {
		return fmt.Errorf("failed to write rejected status: %w", err)
	}
	return nil
}
