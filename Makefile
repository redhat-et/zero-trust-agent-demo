.PHONY: all build test clean run-local run-kind setup-kind deploy-k8s docker-build docker-load help

# Variables
BINARY_DIR := bin
GO := go
SERVICES := opa-service document-service user-service agent-service web-dashboard

# Container registry settings
REGISTRY ?= ghcr.io/redhat-et/zero-trust-agent-demo
DEV_TAG ?= dev
CONTAINER_ENGINE ?= podman

# Default target
all: build

# Build all services
build:
	@echo "=== Building all services ==="
	@mkdir -p $(BINARY_DIR)
	@for svc in $(SERVICES); do \
		echo "Building $$svc..."; \
		$(GO) build -o $(BINARY_DIR)/$$svc ./$$svc; \
	done
	@echo "Build complete! Binaries in $(BINARY_DIR)/"

# Build individual services
build-%:
	@echo "Building $*..."
	@mkdir -p $(BINARY_DIR)
	$(GO) build -o $(BINARY_DIR)/$* ./$*

# Run tests
test:
	@echo "=== Running tests ==="
	$(GO) test -v ./...

# Run OPA policy tests
test-policies:
	@echo "=== Running OPA policy tests ==="
	@if command -v opa >/dev/null 2>&1; then \
		opa test opa-service/policies/ -v; \
	else \
		echo "OPA CLI not installed. Install with: brew install opa"; \
	fi

# Clean build artifacts
clean:
	@echo "=== Cleaning ==="
	rm -rf $(BINARY_DIR)
	rm -rf tmp/

# Run services locally (development mode)
run-local: build
	@echo "=== Starting services locally ==="
	@./scripts/run-local.sh

# Run individual service locally
run-opa:
	cd opa-service && $(GO) run . serve --policy-dir=policies

run-document:
	cd document-service && $(GO) run . serve

run-user:
	cd user-service && $(GO) run . serve

run-agent:
	cd agent-service && $(GO) run . serve

run-dashboard:
	cd web-dashboard && $(GO) run . serve

# Kind cluster operations
setup-kind:
	@echo "=== Setting up Kind cluster ==="
	./scripts/setup-kind.sh

delete-kind:
	@echo "=== Deleting Kind cluster ==="
	kind delete cluster --name spiffe-demo

# Kubernetes deployment
deploy-k8s:
	@echo "=== Deploying to Kubernetes ==="
	./scripts/deploy-app.sh

undeploy-k8s:
	@echo "=== Removing from Kubernetes ==="
	kubectl delete namespace spiffe-demo --ignore-not-found

port-forward:
	@echo "=== Setting up port forwards ==="
	./scripts/port-forward.sh

# Docker operations
docker-build:
	@echo "=== Building Docker images ==="
	@for svc in $(SERVICES); do \
		echo "Building image for $$svc..."; \
		docker build -t spiffe-demo/$$svc:latest -f $$svc/Dockerfile .; \
	done

docker-load:
	@echo "=== Loading images into Kind ==="
	@for svc in $(SERVICES); do \
		echo "Loading $$svc..."; \
		kind load docker-image spiffe-demo/$$svc:latest --name spiffe-demo; \
	done

# Podman operations for development (cross-platform builds)
# Build x86_64 images for OpenShift testing (from ARM Mac)
podman-build-dev:
	@echo "=== Building x86_64 images for development ==="
	@for svc in $(SERVICES); do \
		echo "Building $$svc for linux/amd64..."; \
		$(CONTAINER_ENGINE) build --platform linux/amd64 \
			-t $(REGISTRY)/$$svc:$(DEV_TAG) \
			-f $$svc/Dockerfile .; \
	done
	@echo "Build complete! Images tagged with :$(DEV_TAG)"

# Build and push specific services (faster iteration)
podman-build-dev-%:
	@echo "Building $* for linux/amd64..."
	$(CONTAINER_ENGINE) build --platform linux/amd64 \
		-t $(REGISTRY)/$*:$(DEV_TAG) \
		-f $*/Dockerfile .

# Push dev images to registry
podman-push-dev:
	@echo "=== Pushing dev images to $(REGISTRY) ==="
	@for svc in $(SERVICES); do \
		echo "Pushing $$svc:$(DEV_TAG)..."; \
		$(CONTAINER_ENGINE) push $(REGISTRY)/$$svc:$(DEV_TAG); \
	done
	@echo "Push complete!"

# Push specific service
podman-push-dev-%:
	@echo "Pushing $*:$(DEV_TAG)..."
	$(CONTAINER_ENGINE) push $(REGISTRY)/$*:$(DEV_TAG)

# Build and push in one step
podman-dev: podman-build-dev podman-push-dev
	@echo "=== Dev images built and pushed ==="

# Build and push specific service
podman-dev-%:
	@$(MAKE) podman-build-dev-$*
	@$(MAKE) podman-push-dev-$*

# Development helpers
fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed"; \
	fi

# Go module operations
tidy:
	$(GO) mod tidy

deps:
	$(GO) mod download

# Help
help:
	@echo "SPIFFE/SPIRE Zero Trust Demo - Makefile"
	@echo ""
	@echo "Build commands:"
	@echo "  make build          - Build all services"
	@echo "  make build-<svc>    - Build specific service"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Local development:"
	@echo "  make run-local      - Run all services locally"
	@echo "  make run-opa        - Run OPA service"
	@echo "  make run-document   - Run Document service"
	@echo "  make run-user       - Run User service"
	@echo "  make run-agent      - Run Agent service"
	@echo "  make run-dashboard  - Run Web Dashboard"
	@echo ""
	@echo "Testing:"
	@echo "  make test           - Run Go tests"
	@echo "  make test-policies  - Run OPA policy tests"
	@echo ""
	@echo "Kubernetes:"
	@echo "  make setup-kind     - Create Kind cluster"
	@echo "  make deploy-k8s     - Deploy to Kubernetes"
	@echo "  make undeploy-k8s   - Remove from Kubernetes"
	@echo "  make port-forward   - Set up port forwards"
	@echo "  make delete-kind    - Delete Kind cluster"
	@echo ""
	@echo "Docker/Podman:"
	@echo "  make docker-build   - Build Docker images (local)"
	@echo "  make docker-load    - Load images into Kind"
	@echo ""
	@echo "Podman (cross-platform for OpenShift):"
	@echo "  make podman-dev               - Build and push all x86_64 images"
	@echo "  make podman-dev-<svc>         - Build and push specific service"
	@echo "  make podman-build-dev         - Build all x86_64 images"
	@echo "  make podman-build-dev-<svc>   - Build specific service"
	@echo "  make podman-push-dev          - Push all dev images"
	@echo "  make podman-push-dev-<svc>    - Push specific service"
	@echo ""
	@echo "  Override variables:"
	@echo "    DEV_TAG=mytag make podman-dev   (default: dev)"
	@echo "    REGISTRY=myrepo make podman-dev"
	@echo ""
	@echo "Development:"
	@echo "  make fmt            - Format code"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run linter"
	@echo "  make tidy           - Run go mod tidy"
