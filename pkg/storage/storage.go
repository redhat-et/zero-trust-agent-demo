package storage

import (
	"context"
	"io"
)

// DocumentMetadata represents metadata for a stored document
type DocumentMetadata struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	RequiredDepartment  string   `json:"required_department,omitempty"`
	RequiredDepartments []string `json:"required_departments,omitempty"`
	Sensitivity         string   `json:"sensitivity"`
}

// DocumentStorage defines the interface for document storage operations
type DocumentStorage interface {
	// GetMetadata retrieves metadata for a single document
	GetMetadata(ctx context.Context, id string) (*DocumentMetadata, error)

	// ListMetadata returns metadata for all documents
	ListMetadata(ctx context.Context) ([]*DocumentMetadata, error)

	// PutMetadata creates or updates document metadata
	PutMetadata(ctx context.Context, meta *DocumentMetadata) error

	// DeleteMetadata removes document metadata
	DeleteMetadata(ctx context.Context, id string) error

	// GetContent retrieves the content of a document
	GetContent(ctx context.Context, id string) (io.ReadCloser, error)

	// PutContent creates or updates document content
	PutContent(ctx context.Context, id string, content io.Reader) error

	// DeleteContent removes document content
	DeleteContent(ctx context.Context, id string) error

	// Ping checks if the storage backend is available
	Ping(ctx context.Context) error
}

// ErrNotFound is returned when a document is not found
type ErrNotFound struct {
	ID string
}

func (e *ErrNotFound) Error() string {
	return "document not found: " + e.ID
}
