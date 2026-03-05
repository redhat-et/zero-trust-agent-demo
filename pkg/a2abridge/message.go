package a2abridge

import (
	"fmt"
	"regexp"

	"github.com/a2aproject/a2a-go/a2a"
)

// documentIDPattern matches document IDs like DOC-001, DOC-002, etc.
var documentIDPattern = regexp.MustCompile(`\b(DOC-\d+)\b`)

// ExtractDocumentID extracts a document ID from an A2A message.
// It first checks for a DataPart with a "document_id" field, then falls back
// to extracting a DOC-NNN pattern from TextPart content.
func ExtractDocumentID(msg *a2a.Message) (string, error) {
	if msg == nil {
		return "", fmt.Errorf("message is nil")
	}

	// First pass: look for structured DataPart with document_id
	for _, part := range msg.Parts {
		dp, ok := part.(a2a.DataPart)
		if !ok {
			continue
		}
		if v, ok := dp.Data["document_id"].(string); ok && v != "" {
			return v, nil
		}
	}

	// Second pass: extract document ID from text (e.g., "Summarize DOC-002")
	for _, part := range msg.Parts {
		tp, ok := part.(a2a.TextPart)
		if !ok {
			continue
		}
		if matches := documentIDPattern.FindStringSubmatch(tp.Text); len(matches) > 1 {
			return matches[1], nil
		}
	}

	return "", fmt.Errorf("no document ID found in message (use DataPart with document_id or include DOC-NNN in text)")
}

// ExtractReviewType extracts an optional review type from an A2A message DataPart.
func ExtractReviewType(msg *a2a.Message) string {
	if msg == nil {
		return ""
	}
	for _, part := range msg.Parts {
		dp, ok := part.(a2a.DataPart)
		if !ok {
			continue
		}
		if v, ok := dp.Data["review_type"].(string); ok {
			return v
		}
	}
	return ""
}
