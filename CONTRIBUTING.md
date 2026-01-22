# Contributing

Thanks for your interest in contributing to the SPIFFE/SPIRE Zero Trust Demo!

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/spiffe-spire-demo.git
   cd spiffe-spire-demo
   ```
3. Build and run locally:
   ```bash
   make build
   ./scripts/run-local.sh
   ```

## Development

### Project Structure

```
spiffe-spire-demo/
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

### Testing in Kubernetes

```bash
./scripts/setup-kind.sh     # Create Kind cluster
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
