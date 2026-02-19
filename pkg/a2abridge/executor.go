package a2abridge

import (
	"context"
	"fmt"

	"github.com/a2aproject/a2a-go/a2a"
	"github.com/a2aproject/a2a-go/a2asrv"
	"github.com/a2aproject/a2a-go/a2asrv/eventqueue"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
)

// DocumentFetcher fetches a document via the document-service with delegation context.
// Returns the document map (with "title", "content", etc.) or an error.
type DocumentFetcher func(ctx context.Context, dc *DelegationContext) (map[string]any, error)

// LLMProcessor processes a document with an LLM and returns the result text.
type LLMProcessor func(ctx context.Context, dc *DelegationContext, title, content string) (string, error)

// DelegatedExecutor implements a2asrv.AgentExecutor by bridging A2A messages
// to our SPIFFE/delegation model.
type DelegatedExecutor struct {
	Log           *logger.Logger
	FetchDocument DocumentFetcher
	ProcessLLM    LLMProcessor
}

// Execute handles an incoming A2A message: extracts delegation context,
// fetches the document, processes it with the LLM, and writes results.
func (e *DelegatedExecutor) Execute(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue) error {
	// Transition to working state
	working := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateWorking, nil)
	if err := queue.Write(ctx, working); err != nil {
		return fmt.Errorf("failed to write working status: %w", err)
	}

	// Extract delegation context from the incoming message
	dc, err := ExtractDelegationContext(reqCtx.Message)
	if err != nil {
		e.Log.Error("Failed to extract delegation context from A2A message", "error", err)
		return e.writeFailed(ctx, reqCtx, queue, "Invalid request: "+err.Error())
	}

	e.Log.Info("A2A request received",
		"document_id", dc.DocumentID,
		"user_spiffe_id", dc.UserSPIFFEID,
		"user_departments", dc.UserDepartments)

	// Fetch the document via delegation
	doc, err := e.FetchDocument(ctx, dc)
	if err != nil {
		e.Log.Error("Document fetch failed", "error", err)
		return e.writeFailed(ctx, reqCtx, queue, err.Error())
	}
	if doc == nil || doc["content"] == nil {
		e.Log.Deny("Access denied by document service")
		return e.writeRejected(ctx, reqCtx, queue, "Access denied - permission intersection failed")
	}

	e.Log.Allow("Document access granted via A2A")

	title, _ := doc["title"].(string)
	content, _ := doc["content"].(string)

	// Process with LLM
	result, err := e.ProcessLLM(ctx, dc, title, content)
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
func (e *DelegatedExecutor) Cancel(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue) error {
	event := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateCanceled, nil)
	event.Final = true
	return queue.Write(ctx, event)
}

func (e *DelegatedExecutor) writeFailed(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue, reason string) error {
	msg := a2a.NewMessage(a2a.MessageRoleAgent, &a2a.TextPart{Text: reason})
	event := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateFailed, msg)
	event.Final = true
	if err := queue.Write(ctx, event); err != nil {
		return fmt.Errorf("failed to write failed status: %w", err)
	}
	return nil
}

func (e *DelegatedExecutor) writeRejected(ctx context.Context, reqCtx *a2asrv.RequestContext, queue eventqueue.Queue, reason string) error {
	msg := a2a.NewMessage(a2a.MessageRoleAgent, &a2a.TextPart{Text: reason})
	event := a2a.NewStatusUpdateEvent(reqCtx, a2a.TaskStateRejected, msg)
	event.Final = true
	if err := queue.Write(ctx, event); err != nil {
		return fmt.Errorf("failed to write rejected status: %w", err)
	}
	return nil
}
