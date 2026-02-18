package a2abridge

import (
	"fmt"

	"github.com/a2aproject/a2a-go/a2a"
)

// DelegationContext holds the delegation parameters extracted from an A2A message.
type DelegationContext struct {
	DocumentID      string   `json:"document_id"`
	UserSPIFFEID    string   `json:"user_spiffe_id"`
	UserDepartments []string `json:"user_departments,omitempty"`
	ReviewType      string   `json:"review_type,omitempty"`
}

// ExtractDelegationContext extracts delegation context from A2A message parts.
// It looks for a DataPart with document_id and user_spiffe_id fields.
func ExtractDelegationContext(msg *a2a.Message) (*DelegationContext, error) {
	if msg == nil {
		return nil, fmt.Errorf("message is nil")
	}

	for _, part := range msg.Parts {
		dp, ok := part.(*a2a.DataPart)
		if !ok {
			continue
		}

		dc := &DelegationContext{}

		if v, ok := dp.Data["document_id"].(string); ok {
			dc.DocumentID = v
		}
		if v, ok := dp.Data["user_spiffe_id"].(string); ok {
			dc.UserSPIFFEID = v
		}
		if v, ok := dp.Data["review_type"].(string); ok {
			dc.ReviewType = v
		}
		if deps, ok := dp.Data["user_departments"].([]any); ok {
			for _, d := range deps {
				if s, ok := d.(string); ok {
					dc.UserDepartments = append(dc.UserDepartments, s)
				}
			}
		}

		if dc.DocumentID == "" || dc.UserSPIFFEID == "" {
			continue
		}
		return dc, nil
	}

	return nil, fmt.Errorf("no DataPart with document_id and user_spiffe_id found in message")
}
