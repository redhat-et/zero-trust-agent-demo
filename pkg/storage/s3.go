package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	// ManifestKey is the key for the metadata manifest in the bucket
	ManifestKey = "documents.json"
	// ContentPrefix is the prefix for document content files
	ContentPrefix = "content/"
)

// S3Config holds configuration for S3 storage
type S3Config struct {
	BucketHost      string
	BucketPort      int
	BucketName      string
	UseSSL          bool
	Region          string
	AccessKeyID     string
	SecretAccessKey string
}

// S3Storage implements DocumentStorage using S3-compatible object storage
type S3Storage struct {
	client     *s3.Client
	bucketName string
	mu         sync.RWMutex
}

// NewS3Storage creates a new S3 storage client
func NewS3Storage(ctx context.Context, cfg S3Config) (*S3Storage, error) {
	// Build endpoint URL
	scheme := "http"
	if cfg.UseSSL {
		scheme = "https"
	}
	endpoint := fmt.Sprintf("%s://%s:%d", scheme, cfg.BucketHost, cfg.BucketPort)

	// Configure AWS SDK
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretAccessKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with custom endpoint
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true // Required for MinIO and most S3-compatible stores
	})

	return &S3Storage{
		client:     client,
		bucketName: cfg.BucketName,
	}, nil
}

// manifest holds all document metadata
type manifest struct {
	Documents map[string]*DocumentMetadata `json:"documents"`
}

// loadManifest loads the metadata manifest from S3
func (s *S3Storage) loadManifest(ctx context.Context) (*manifest, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(ManifestKey),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			// No manifest yet, return empty
			return &manifest{Documents: make(map[string]*DocumentMetadata)}, nil
		}
		return nil, fmt.Errorf("failed to get manifest: %w", err)
	}
	defer resp.Body.Close()

	var m manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}
	if m.Documents == nil {
		m.Documents = make(map[string]*DocumentMetadata)
	}
	return &m, nil
}

// saveManifest saves the metadata manifest to S3
func (s *S3Storage) saveManifest(ctx context.Context, m *manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucketName),
		Key:         aws.String(ManifestKey),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("failed to put manifest: %w", err)
	}
	return nil
}

// GetMetadata retrieves metadata for a single document
func (s *S3Storage) GetMetadata(ctx context.Context, id string) (*DocumentMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, err := s.loadManifest(ctx)
	if err != nil {
		return nil, err
	}

	meta, ok := m.Documents[id]
	if !ok {
		return nil, &ErrNotFound{ID: id}
	}
	return meta, nil
}

// ListMetadata returns metadata for all documents
func (s *S3Storage) ListMetadata(ctx context.Context) ([]*DocumentMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, err := s.loadManifest(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*DocumentMetadata, 0, len(m.Documents))
	for _, meta := range m.Documents {
		result = append(result, meta)
	}
	return result, nil
}

// PutMetadata creates or updates document metadata
func (s *S3Storage) PutMetadata(ctx context.Context, meta *DocumentMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.loadManifest(ctx)
	if err != nil {
		return err
	}

	m.Documents[meta.ID] = meta
	return s.saveManifest(ctx, m)
}

// DeleteMetadata removes document metadata
func (s *S3Storage) DeleteMetadata(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.loadManifest(ctx)
	if err != nil {
		return err
	}

	if _, ok := m.Documents[id]; !ok {
		return &ErrNotFound{ID: id}
	}
	delete(m.Documents, id)
	return s.saveManifest(ctx, m)
}

// contentKey returns the S3 key for document content
func contentKey(id string) string {
	return ContentPrefix + id + ".md"
}

// GetContent retrieves the content of a document
func (s *S3Storage) GetContent(ctx context.Context, id string) (io.ReadCloser, error) {
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(contentKey(id)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, &ErrNotFound{ID: id}
		}
		return nil, fmt.Errorf("failed to get content: %w", err)
	}
	return resp.Body, nil
}

// PutContent creates or updates document content
func (s *S3Storage) PutContent(ctx context.Context, id string, content io.Reader) error {
	// Read all content into memory (required for S3 PutObject)
	data, err := io.ReadAll(content)
	if err != nil {
		return fmt.Errorf("failed to read content: %w", err)
	}

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucketName),
		Key:         aws.String(contentKey(id)),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("text/markdown"),
	})
	if err != nil {
		return fmt.Errorf("failed to put content: %w", err)
	}
	return nil
}

// DeleteContent removes document content
func (s *S3Storage) DeleteContent(ctx context.Context, id string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(contentKey(id)),
	})
	if err != nil {
		return fmt.Errorf("failed to delete content: %w", err)
	}
	return nil
}

// Ping checks if the storage backend is available
func (s *S3Storage) Ping(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(s.bucketName),
	})
	if err != nil {
		return fmt.Errorf("failed to ping bucket: %w", err)
	}
	return nil
}

// IsEmpty returns true if there are no documents stored
func (s *S3Storage) IsEmpty(ctx context.Context) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, err := s.loadManifest(ctx)
	if err != nil {
		return false, err
	}
	return len(m.Documents) == 0, nil
}
