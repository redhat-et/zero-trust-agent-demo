# Contributing

Thanks for your interest in contributing to the Zero Trust Agent Demo!

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/zero-trust-agent-demo.git
   cd zero-trust-agent-demo
   ```
3. Build and run locally:
   ```bash
   make build
   ./scripts/run-local.sh
   ```

## Development

### Project Structure

```text
zero-trust-agent-demo/
├── pkg/                    # Shared packages
├── web-dashboard/          # Dashboard service (:8080)
├── user-service/           # User management (:8082)
├── agent-service/          # Agent management (:8083)
├── document-service/       # Document access (:8084)
├── opa-service/            # Policy evaluation (:8085)
├── deploy/                 # Kubernetes manifests
└── scripts/                # Helper scripts
```

### Building

```bash
make build      # Build all services
make clean      # Clean build artifacts
make test       # Run tests
```

### Running Locally

```bash
./scripts/run-local.sh      # Start all services
tail -f tmp/logs/*.log      # Watch logs (separate terminal)
```

### Testing in Kubernetes (with local images)

```bash
# Create Kind cluster
./scripts/setup-kind.sh

# Build and load local images
make docker-build
make docker-load

# Deploy with local images
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/opa-policies-configmap.yaml
kubectl apply -f deploy/k8s/deployments-local.yaml

# Open dashboard
open http://localhost:8080
```

### Testing in Kubernetes (with pre-built images)

```bash
./scripts/setup-kind.sh
kubectl apply -f deploy/k8s/
```

## Submitting Changes

1. Create a feature branch: `git checkout -b my-feature`
2. Make your changes
3. Test locally with `make build && ./scripts/run-local.sh`
4. Commit with a clear message
5. Push and open a Pull Request

## Code Style

- Go code follows standard `gofmt` formatting
- Keep commits focused and atomic
- Write clear commit messages

## Questions?

Open an issue if you have questions or run into problems.
