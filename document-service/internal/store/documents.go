package store

// Document represents a protected document in the system
type Document struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Content             string   `json:"content"`
	RequiredDepartment  string   `json:"required_department,omitempty"`
	RequiredDepartments []string `json:"required_departments,omitempty"`
	Sensitivity         string   `json:"sensitivity"`
}

// DocumentStore is an in-memory document store
type DocumentStore struct {
	documents map[string]*Document
}

// NewDocumentStore creates a new document store with sample documents
func NewDocumentStore() *DocumentStore {
	store := &DocumentStore{
		documents: make(map[string]*Document),
	}
	store.loadSampleDocuments()
	return store
}

func (s *DocumentStore) loadSampleDocuments() {
	// 7 sample documents as defined in the design
	s.documents["DOC-001"] = &Document{
		ID:                 "DOC-001",
		Title:              "Engineering Roadmap",
		RequiredDepartment: "engineering",
		Sensitivity:        "medium",
		Content: `# Engineering Roadmap 2026

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
`,
	}

	s.documents["DOC-002"] = &Document{
		ID:                 "DOC-002",
		Title:              "Q4 Financial Report",
		RequiredDepartment: "finance",
		Sensitivity:        "high",
		Content: `# Q4 Financial Report

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
`,
	}

	s.documents["DOC-003"] = &Document{
		ID:                 "DOC-003",
		Title:              "Admin Policies",
		RequiredDepartment: "admin",
		Sensitivity:        "critical",
		Content: `# Administrative Policies

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
`,
	}

	s.documents["DOC-004"] = &Document{
		ID:                 "DOC-004",
		Title:              "HR Guidelines",
		RequiredDepartment: "hr",
		Sensitivity:        "medium",
		Content: `# HR Guidelines

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
`,
	}

	s.documents["DOC-005"] = &Document{
		ID:                  "DOC-005",
		Title:               "Budget Projections",
		RequiredDepartments: []string{"finance", "engineering"},
		Sensitivity:         "high",
		Content: `# Budget Projections 2026

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
`,
	}

	s.documents["DOC-006"] = &Document{
		ID:                  "DOC-006",
		Title:               "Compliance Audit",
		RequiredDepartments: []string{"admin", "finance"},
		Sensitivity:         "critical",
		Content: `# Compliance Audit Report

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
`,
	}

	s.documents["DOC-007"] = &Document{
		ID:                 "DOC-007",
		Title:              "All-Hands Summary",
		RequiredDepartment: "", // Public document
		Sensitivity:        "public",
		Content: `# All-Hands Meeting Summary

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
`,
	}
}

// Get retrieves a document by ID
func (s *DocumentStore) Get(id string) (*Document, bool) {
	doc, ok := s.documents[id]
	return doc, ok
}

// List returns all documents (metadata only, not content)
func (s *DocumentStore) List() []*Document {
	docs := make([]*Document, 0, len(s.documents))
	for _, doc := range s.documents {
		// Return without content for list view
		docs = append(docs, &Document{
			ID:                  doc.ID,
			Title:               doc.Title,
			RequiredDepartment:  doc.RequiredDepartment,
			RequiredDepartments: doc.RequiredDepartments,
			Sensitivity:         doc.Sensitivity,
		})
	}
	return docs
}

// GetIDs returns all document IDs
func (s *DocumentStore) GetIDs() []string {
	ids := make([]string, 0, len(s.documents))
	for id := range s.documents {
		ids = append(ids, id)
	}
	return ids
}
