package storage

import (
	"bytes"
	"context"
	"io"
	"sync"
)

// MockStorage provides an in-memory storage implementation for local development
type MockStorage struct {
	mu       sync.RWMutex
	metadata map[string]*DocumentMetadata
	content  map[string][]byte
}

// NewMockStorage creates a new mock storage with sample documents
func NewMockStorage() *MockStorage {
	m := &MockStorage{
		metadata: make(map[string]*DocumentMetadata),
		content:  make(map[string][]byte),
	}
	m.loadSampleDocuments()
	return m
}

// NewEmptyMockStorage creates an empty mock storage (for testing)
func NewEmptyMockStorage() *MockStorage {
	return &MockStorage{
		metadata: make(map[string]*DocumentMetadata),
		content:  make(map[string][]byte),
	}
}

func (m *MockStorage) loadSampleDocuments() {
	// 7 sample documents as defined in the design
	m.metadata["DOC-001"] = &DocumentMetadata{
		ID:                 "DOC-001",
		Title:              "Engineering Roadmap",
		RequiredDepartment: "engineering",
		Sensitivity:        "medium",
	}
	m.content["DOC-001"] = []byte(`# Engineering Roadmap 2026

## Q1 Goals
- Complete microservices migration
- Implement Zero Trust architecture
- Deploy SPIFFE/SPIRE for workload identity

## Q2 Goals
- Performance optimization
- Security hardening
- AI agent integration

## Key Metrics
- 99.9% uptime target
- <100ms API response time
- Zero security incidents
`)

	m.metadata["DOC-002"] = &DocumentMetadata{
		ID:                 "DOC-002",
		Title:              "Q4 Financial Report",
		RequiredDepartment: "finance",
		Sensitivity:        "high",
	}
	m.content["DOC-002"] = []byte(`# Q4 Financial Report

## Revenue Summary
- Total Revenue: $12.5M
- Growth: 23% YoY
- Recurring Revenue: $8.2M

## Expenses
- Engineering: $4.1M
- Operations: $2.3M
- Marketing: $1.8M

## Projections
- Q1 2026 Target: $14M
- Annual Target: $60M
`)

	m.metadata["DOC-003"] = &DocumentMetadata{
		ID:                 "DOC-003",
		Title:              "Admin Policies",
		RequiredDepartment: "admin",
		Sensitivity:        "critical",
	}
	m.content["DOC-003"] = []byte(`# Administrative Policies

## Access Control
- All access requires MFA
- Admin credentials rotate every 24 hours
- Audit logs retained for 7 years

## System Administration
- Root access restricted to SRE team
- All changes require approval workflow
- Emergency access requires incident ticket

## Compliance
- SOC 2 Type II certified
- GDPR compliant
- HIPAA ready
`)

	m.metadata["DOC-004"] = &DocumentMetadata{
		ID:                 "DOC-004",
		Title:              "HR Guidelines",
		RequiredDepartment: "hr",
		Sensitivity:        "medium",
	}
	m.content["DOC-004"] = []byte(`# HR Guidelines

## Hiring Process
1. Job posting approval
2. Initial screening
3. Technical assessment
4. Team interviews
5. Offer and negotiation

## Benefits
- Health insurance
- 401k matching
- Unlimited PTO
- Remote work options

## Performance Reviews
- Quarterly feedback
- Annual compensation review
- Promotion criteria
`)

	m.metadata["DOC-005"] = &DocumentMetadata{
		ID:                  "DOC-005",
		Title:               "Budget Projections",
		RequiredDepartments: []string{"finance", "engineering"},
		Sensitivity:         "high",
	}
	m.content["DOC-005"] = []byte(`# Budget Projections 2026

## Engineering Budget
- Infrastructure: $2.5M
- Personnel: $8M
- Tools & Software: $500K

## Finance Allocation
- Operating costs: $3M
- Growth investment: $5M
- Reserve: $2M

## Joint Initiatives
- Security platform: $1M
- AI/ML infrastructure: $1.5M
`)

	m.metadata["DOC-006"] = &DocumentMetadata{
		ID:                  "DOC-006",
		Title:               "Compliance Audit",
		RequiredDepartments: []string{"admin", "finance"},
		Sensitivity:         "critical",
	}
	m.content["DOC-006"] = []byte(`# Compliance Audit Report

## SOC 2 Findings
- All controls effective
- No exceptions noted
- Recommendations implemented

## Financial Audit
- Clean opinion issued
- Revenue recognition verified
- Expense controls validated

## Security Assessment
- Penetration testing passed
- Vulnerability scan clean
- Access reviews completed
`)

	m.metadata["DOC-007"] = &DocumentMetadata{
		ID:                 "DOC-007",
		Title:              "All-Hands Summary",
		RequiredDepartment: "", // Public document
		Sensitivity:        "public",
	}
	m.content["DOC-007"] = []byte(`# All-Hands Meeting Summary

## Company Updates
- New product launch successful
- Customer satisfaction at 95%
- Team growing to 150 people

## Announcements
- Office reopening next month
- Summer party planned for July
- New benefits starting Q2

## Q&A Highlights
- Work from home policy continues
- New training programs available
- Promotion cycle in March
`)
}

// GetMetadata retrieves metadata for a single document
func (m *MockStorage) GetMetadata(ctx context.Context, id string) (*DocumentMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	meta, ok := m.metadata[id]
	if !ok {
		return nil, &ErrNotFound{ID: id}
	}
	// Return a copy to prevent external mutation
	copy := *meta
	if meta.RequiredDepartments != nil {
		copy.RequiredDepartments = make([]string, len(meta.RequiredDepartments))
		copy.RequiredDepartments = append([]string{}, meta.RequiredDepartments...)
	}
	return &copy, nil
}

// ListMetadata returns metadata for all documents
func (m *MockStorage) ListMetadata(ctx context.Context) ([]*DocumentMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*DocumentMetadata, 0, len(m.metadata))
	for _, meta := range m.metadata {
		copy := *meta
		if meta.RequiredDepartments != nil {
			copy.RequiredDepartments = append([]string{}, meta.RequiredDepartments...)
		}
		result = append(result, &copy)
	}
	return result, nil
}

// PutMetadata creates or updates document metadata
func (m *MockStorage) PutMetadata(ctx context.Context, meta *DocumentMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copy := *meta
	if meta.RequiredDepartments != nil {
		copy.RequiredDepartments = append([]string{}, meta.RequiredDepartments...)
	}
	m.metadata[meta.ID] = &copy
	return nil
}

// DeleteMetadata removes document metadata
func (m *MockStorage) DeleteMetadata(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.metadata[id]; !ok {
		return &ErrNotFound{ID: id}
	}
	delete(m.metadata, id)
	return nil
}

// GetContent retrieves the content of a document
func (m *MockStorage) GetContent(ctx context.Context, id string) (io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	content, ok := m.content[id]
	if !ok {
		return nil, &ErrNotFound{ID: id}
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

// PutContent creates or updates document content
func (m *MockStorage) PutContent(ctx context.Context, id string, content io.Reader) error {
	data, err := io.ReadAll(content)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.content[id] = data
	return nil
}

// DeleteContent removes document content
func (m *MockStorage) DeleteContent(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.content[id]; !ok {
		return &ErrNotFound{ID: id}
	}
	delete(m.content, id)
	return nil
}

// Ping checks if the storage backend is available
func (m *MockStorage) Ping(ctx context.Context) error {
	return nil
}

// IsEmpty returns true if there are no documents stored
func (m *MockStorage) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.metadata) == 0
}
