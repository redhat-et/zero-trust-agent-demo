# ADR-0006: S3 document storage

## Status

Accepted

## Date

2026-01-27

## Context

The document-service originally used in-memory storage with hardcoded sample documents. This approach has limitations:

1. **No persistence**: Documents are lost on restart
2. **No CRUD operations**: Cannot add, update, or delete documents
3. **Hardcoded metadata**: Document requirements duplicated in OPA policies
4. **Not production-ready**: Doesn't demonstrate real-world storage patterns

For a realistic demo and potential PoC use, we need:

1. Persistent document storage
2. REST API for document management (CRUD)
3. Dynamic document metadata (not hardcoded in policies)
4. Compatibility with OpenShift/Kubernetes object storage (NooBaa via OBC)

## Decision

We will implement S3-compatible object storage for documents using the following design:

### Storage architecture

```text
bucket/
├── documents.json           # Metadata manifest (all document metadata)
└── content/
    ├── DOC-001.md          # Document content files
    ├── DOC-002.md
    └── ...
```

### Storage abstraction layer

Create `pkg/storage/` package with:

- `DocumentStorage` interface for storage operations
- `S3Storage` implementation using AWS SDK v2
- `MockStorage` implementation for local development

```go
type DocumentStorage interface {
    GetMetadata(ctx context.Context, id string) (*DocumentMetadata, error)
    ListMetadata(ctx context.Context) ([]*DocumentMetadata, error)
    PutMetadata(ctx context.Context, meta *DocumentMetadata) error
    DeleteMetadata(ctx context.Context, id string) error
    GetContent(ctx context.Context, id string) (io.ReadCloser, error)
    PutContent(ctx context.Context, id string, content io.Reader) error
    DeleteContent(ctx context.Context, id string) error
    Ping(ctx context.Context) error
}
```

### OPA integration

Document metadata is passed in the OPA request rather than looked up from hardcoded policy data:

```json
{
  "input": {
    "caller_spiffe_id": "spiffe://...",
    "document_id": "DOC-001",
    "document_metadata": {
      "required_departments": ["engineering"],
      "sensitivity": "medium"
    },
    "delegation": { ... }
  }
}
```

This eliminates duplication and allows dynamic document creation.

### CRUD authorization

A new OPA policy (`document_management.rego`) restricts CRUD operations to users with the `admin` department:

```rego
allow_manage if {
    caller := parse_spiffe_id(input.caller_spiffe_id)
    caller.type == "user"
    user_depts := users.get_departments(caller.name)
    "admin" in user_depts
}
```

### Configuration

S3 storage is configured via environment variables from OpenShift OBC:

| Variable | Source | Description |
| -------- | ------ | ----------- |
| `SPIFFE_DEMO_STORAGE_ENABLED` | Deployment | Enable S3 storage |
| `BUCKET_HOST` | OBC ConfigMap | S3 endpoint host |
| `BUCKET_PORT` | OBC ConfigMap | S3 endpoint port |
| `BUCKET_NAME` | OBC ConfigMap | Bucket name |
| `AWS_ACCESS_KEY_ID` | OBC Secret | Access key |
| `AWS_SECRET_ACCESS_KEY` | OBC Secret | Secret key |

## Consequences

### Positive

- **Persistence**: Documents survive restarts
- **CRUD operations**: Full document lifecycle management
- **Dynamic metadata**: No hardcoding in OPA policies
- **OpenShift native**: Uses ObjectBucketClaim for provisioning
- **Backwards compatible**: Mock storage works without S3
- **Testable**: Can test with MinIO locally

### Negative

- **Complexity**: Additional storage layer to maintain
- **Manifest locking**: JSON manifest requires mutex for concurrent writes
- **S3 dependency**: Requires S3-compatible storage in production
- **Network latency**: Additional round-trip for document metadata

### Neutral

- **Seeding**: Init container seeds sample documents on first deploy
- **Migration**: Existing local development works unchanged

## Alternatives considered

### Database (PostgreSQL)

- **Pros**: Better for structured queries, ACID transactions
- **Cons**: Overkill for document storage, requires additional infrastructure

### ConfigMap/Secret storage

- **Pros**: Kubernetes native, no external dependencies
- **Cons**: Size limits (1MB), not designed for file storage, requires restart for updates

### Embedded key-value store (bbolt)

- **Pros**: No external dependencies, persistent
- **Cons**: Single-node only, doesn't match production patterns

### Split metadata/content storage

Store metadata in ConfigMap, content in S3.

- **Pros**: Fast metadata access
- **Cons**: Sync complexity, inconsistency risks

## Implementation details

### New REST API endpoints

| Method | Endpoint | Description | Auth |
| ------ | -------- | ----------- | ---- |
| POST | `/documents` | Create document | Admin only |
| PUT | `/documents/{id}` | Update document | Admin only |
| DELETE | `/documents/{id}` | Delete document | Admin only |
| GET | `/documents/{id}/content` | Get raw content | Standard access |

### Kubernetes deployment

```yaml
initContainers:
  - name: seed-documents
    image: document-service
    args: ["seed", "--if-empty"]
    envFrom:
      - configMapRef:
          name: doc-storage-bucket
      - secretRef:
          name: doc-storage-bucket
```

### Local development with MinIO

```bash
docker run -d -p 9000:9000 minio/minio server /data

export SPIFFE_DEMO_STORAGE_ENABLED=true
export BUCKET_HOST=localhost
export BUCKET_PORT=9000
export BUCKET_NAME=documents
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

./bin/document-service seed
./bin/document-service serve --mock-spiffe
```

## References

- [OpenShift Data Foundation](https://www.redhat.com/en/technologies/cloud-computing/openshift-data-foundation)
- [ObjectBucketClaim API](https://github.com/kube-object-storage/lib-bucket-provisioner)
- [AWS SDK for Go v2](https://aws.github.io/aws-sdk-go-v2/docs/)
- [MinIO](https://min.io/)
