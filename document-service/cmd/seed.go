package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/redhat-et/zero-trust-agent-demo/pkg/config"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/logger"
	"github.com/redhat-et/zero-trust-agent-demo/pkg/storage"
)

var (
	seedIfEmpty bool
)

var seedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Seed the storage with sample documents",
	Long: `Seed the document storage backend with sample documents.

This command populates the S3 bucket with the default set of 7 sample documents
used in the demo. It's typically run as an init container in Kubernetes.`,
	RunE: runSeed,
}

func init() {
	rootCmd.AddCommand(seedCmd)
	seedCmd.Flags().BoolVar(&seedIfEmpty, "if-empty", false, "Only seed if the bucket is empty")
}

// SampleDocument represents a document to seed
type SampleDocument struct {
	Metadata *storage.DocumentMetadata
	Content  string
}

// getSampleDocuments returns the default sample documents
func getSampleDocuments() []SampleDocument {
	return []SampleDocument{
		{
			Metadata: &storage.DocumentMetadata{
				ID:                 "DOC-001",
				Title:              "Engineering Roadmap",
				RequiredDepartment: "engineering",
				Sensitivity:        "medium",
			},
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
		},
		{
			Metadata: &storage.DocumentMetadata{
				ID:                 "DOC-002",
				Title:              "Q4 Financial Report",
				RequiredDepartment: "finance",
				Sensitivity:        "high",
			},
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
		},
		{
			Metadata: &storage.DocumentMetadata{
				ID:                 "DOC-003",
				Title:              "Admin Policies",
				RequiredDepartment: "admin",
				Sensitivity:        "critical",
			},
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
		},
		{
			Metadata: &storage.DocumentMetadata{
				ID:                 "DOC-004",
				Title:              "HR Guidelines",
				RequiredDepartment: "hr",
				Sensitivity:        "medium",
			},
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
		},
		{
			Metadata: &storage.DocumentMetadata{
				ID:                  "DOC-005",
				Title:               "Budget Projections",
				RequiredDepartments: []string{"finance", "engineering"},
				Sensitivity:         "high",
			},
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
		},
		{
			Metadata: &storage.DocumentMetadata{
				ID:                  "DOC-006",
				Title:               "Compliance Audit",
				RequiredDepartments: []string{"admin", "finance"},
				Sensitivity:         "critical",
			},
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
		},
		{
			Metadata: &storage.DocumentMetadata{
				ID:                 "DOC-007",
				Title:              "All-Hands Summary",
				RequiredDepartment: "", // Public document
				Sensitivity:        "public",
			},
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
		},
	}
}

func runSeed(cmd *cobra.Command, args []string) error {
	var cfg Config
	if err := config.Load(v, &cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Load OBC-style environment variables for storage
	config.LoadStorageConfigFromEnv(&cfg.Storage)

	log := logger.New(logger.ComponentDocService)

	ctx := context.Background()

	// Initialize storage backend
	var store storage.DocumentStorage
	if cfg.Storage.Enabled {
		log.Info("Connecting to S3 storage",
			"host", cfg.Storage.BucketHost,
			"port", cfg.Storage.BucketPort,
			"bucket", cfg.Storage.BucketName)

		s3Cfg := storage.S3Config{
			BucketHost:      cfg.Storage.BucketHost,
			BucketPort:      cfg.Storage.BucketPort,
			BucketName:      cfg.Storage.BucketName,
			UseSSL:          cfg.Storage.UseSSL,
			Region:          cfg.Storage.Region,
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		}

		s3Store, err := storage.NewS3Storage(ctx, s3Cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize S3 storage: %w", err)
		}

		// Verify connectivity
		if err := s3Store.Ping(ctx); err != nil {
			return fmt.Errorf("failed to connect to S3 storage: %w", err)
		}
		log.Info("S3 storage connected successfully")

		// Check if empty when --if-empty flag is set
		if seedIfEmpty {
			isEmpty, err := s3Store.IsEmpty(ctx)
			if err != nil {
				return fmt.Errorf("failed to check if storage is empty: %w", err)
			}
			if !isEmpty {
				log.Info("Storage is not empty, skipping seed (--if-empty flag)")
				return nil
			}
		}

		store = s3Store
	} else {
		log.Info("Storage not enabled, nothing to seed")
		log.Info("Set SPIFFE_DEMO_STORAGE_ENABLED=true to enable S3 storage")
		return nil
	}

	// Seed documents
	docs := getSampleDocuments()
	log.Section("SEEDING DOCUMENTS")
	log.Info("Seeding sample documents", "count", len(docs))

	for _, doc := range docs {
		// Save metadata
		if err := store.PutMetadata(ctx, doc.Metadata); err != nil {
			return fmt.Errorf("failed to save metadata for %s: %w", doc.Metadata.ID, err)
		}

		// Save content
		if err := store.PutContent(ctx, doc.Metadata.ID, strings.NewReader(doc.Content)); err != nil {
			return fmt.Errorf("failed to save content for %s: %w", doc.Metadata.ID, err)
		}

		log.Info("Seeded document",
			"id", doc.Metadata.ID,
			"title", doc.Metadata.Title)
	}

	log.Info("Seeding complete", "documents", len(docs))
	return nil
}
