.PHONY: all build test clean run-kind setup-kind deploy-k8s docker-build docker-load help \
	deploy-openshift-authbridge deploy-openshift-authbridge-quick test-openshift-authbridge \
	deploy-authbridge-ai-agents deploy-authbridge-ai-agents-remote-kc test-authbridge-ai-agents

# Variables
BINARY_DIR := bin
GO := go
SERVICES := opa-service document-service user-service agent-service summarizer-service reviewer-service web-dashboard
# Services that come from base (already transformed to ghcr.io names by ghcr overlay)
BASE_SERVICES := opa-service document-service user-service agent-service web-dashboard
# Services that come from ai-agents overlay (still have simple names)
AI_SERVICES := summarizer-service reviewer-service

# Container registry settings
REGISTRY ?= ghcr.io/redhat-et/zero-trust-agent-demo
GIT_SHA := $(shell git rev-parse --short HEAD)
GIT_DIRTY := $(shell git diff --quiet || echo "-dirty")
DEV_TAG ?= $(GIT_SHA)$(GIT_DIRTY)
CONTAINER_ENGINE ?= podman

# Default target
all: build

# Check for required dependencies
check-deps:
	@echo "=== Checking dependencies ==="
	@missing=""; \
	command -v go >/dev/null 2>&1 || missing="$$missing go"; \
	command -v $(CONTAINER_ENGINE) >/dev/null 2>&1 || missing="$$missing $(CONTAINER_ENGINE)"; \
	command -v kubectl >/dev/null 2>&1 || missing="$$missing kubectl"; \
	command -v kustomize >/dev/null 2>&1 || missing="$$missing kustomize"; \
	if [ -n "$$missing" ]; then \
		echo "Missing required tools:$$missing"; \
		echo ""; \
		echo "Install with:"; \
		echo "  go:         https://go.dev/dl/"; \
		echo "  podman:     brew install podman"; \
		echo "  kubectl:    brew install kubectl"; \
		echo "  kustomize:  brew install kustomize"; \
		echo ""; \
		exit 1; \
	fi
	@echo "  go:         $$(go version | cut -d' ' -f3)"
	@echo "  $(CONTAINER_ENGINE):     $$($(CONTAINER_ENGINE) --version | head -1)"
	@echo "  kubectl:    $$(kubectl version --client -o yaml 2>/dev/null | grep gitVersion | cut -d: -f2 | tr -d ' ')"
	@echo "  kustomize:  $$(kustomize version --short 2>/dev/null || kustomize version)"
	@command -v oc >/dev/null 2>&1 && echo "  oc:         $$(oc version --client 2>/dev/null | head -1)" || echo "  oc:         (not installed - optional, for OpenShift)"
	@command -v gh >/dev/null 2>&1 && echo "  gh:         $$(gh --version | head -1)" || echo "  gh:         (not installed - optional, for ghcr-cleanup)"
	@echo ""
	@echo "All required dependencies found!"

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

# Run individual service locally
run-opa:
	cd opa-service && $(GO) run . serve --policy-dir=policies

run-document:
	cd document-service && $(GO) run . serve

run-user:
	cd user-service && $(GO) run . serve

run-agent:
	cd agent-service && $(GO) run . serve

run-summarizer:
	cd summarizer-service && $(GO) run . serve

run-reviewer:
	cd reviewer-service && $(GO) run . serve

run-dashboard:
	cd web-dashboard && $(GO) run . serve

# Kind cluster operations
setup-kind:
	@echo "=== Setting up Kind cluster ==="
	./scripts/setup-kind.sh

delete-kind:
	@echo "=== Deleting Kind cluster ==="
	kind delete cluster --name spiffe-demo

# Kubernetes deployment (uses local overlay by default)
deploy-k8s:
	@echo "=== Deploying to Kubernetes ==="
	kubectl apply -k deploy/k8s/overlays/local

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

# OpenShift deployment with git SHA tags
# Usage: make deploy-openshift
#        make deploy-openshift DEV_TAG=custom-tag
deploy-openshift: check-deps podman-dev
	@echo "=== Deploying to OpenShift with tag $(DEV_TAG) ==="
	@echo "Updating kustomization with new image tags..."
	@cd deploy/k8s/overlays/openshift-ai-agents && \
	for svc in $(BASE_SERVICES); do \
		kustomize edit set image $(REGISTRY)/$$svc:$(DEV_TAG); \
	done && \
	for svc in $(AI_SERVICES); do \
		kustomize edit set image $$svc=$(REGISTRY)/$$svc:$(DEV_TAG); \
	done
	oc apply -k deploy/k8s/overlays/openshift-ai-agents
	@echo ""
	@echo "Deployed with images tagged: $(DEV_TAG)"
	@echo "To rollback: make deploy-openshift DEV_TAG=<previous-sha>"

# Deploy without rebuilding (just update tags and apply)
deploy-openshift-quick:
	@echo "=== Quick deploy to OpenShift with tag $(DEV_TAG) ==="
	@cd deploy/k8s/overlays/openshift-ai-agents && \
	for svc in $(BASE_SERVICES); do \
		kustomize edit set image $(REGISTRY)/$$svc:$(DEV_TAG); \
	done && \
	for svc in $(AI_SERVICES); do \
		kustomize edit set image $$svc=$(REGISTRY)/$$svc:$(DEV_TAG); \
	done
	oc apply -k deploy/k8s/overlays/openshift-ai-agents
	@echo "Deployed with tag: $(DEV_TAG)"

# Restart OpenShift deployments (pick up new images with same tag)
restart-openshift:
	@echo "=== Restarting OpenShift deployments ==="
	oc rollout restart deployment -n spiffe-demo

# Clean up old images from GHCR (keeps last N versions)
# Requires: gh CLI authenticated with delete:packages scope
# Usage: make ghcr-cleanup KEEP_VERSIONS=5
KEEP_VERSIONS ?= 10
ghcr-cleanup:
	@echo "=== Cleaning up old GHCR images (keeping last $(KEEP_VERSIONS)) ==="
	@echo "This requires 'gh' CLI with delete:packages scope"
	@echo ""
	@for svc in $(SERVICES); do \
		echo "Cleaning $$svc..."; \
		gh api --paginate \
			"/users/redhat-et/packages/container/zero-trust-agent-demo%2F$$svc/versions" \
			--jq '.[$(KEEP_VERSIONS):]|.[].id' 2>/dev/null | \
		while read id; do \
			echo "  Deleting version $$id"; \
			gh api --method DELETE \
				"/users/redhat-et/packages/container/zero-trust-agent-demo%2F$$svc/versions/$$id" 2>/dev/null || true; \
		done; \
	done
	@echo "Cleanup complete!"

# List current image tags in GHCR
ghcr-list:
	@echo "=== Current GHCR image tags ==="
	@for svc in $(SERVICES); do \
		echo "$$svc:"; \
		gh api "/users/redhat-et/packages/container/zero-trust-agent-demo%2F$$svc/versions" \
			--jq '.[0:5]|.[]|"  \(.metadata.container.tags|join(", ")) - \(.created_at)"' 2>/dev/null || echo "  (unable to fetch)"; \
	done

# AuthBridge deployment
deploy-authbridge:
	@echo "=== Deploying AuthBridge overlay ==="
	./scripts/setup-authbridge.sh

test-authbridge:
	@echo "=== Running AuthBridge tests ==="
	./scripts/test-authbridge.sh

# AuthBridge with remote Keycloak (Kind + external Keycloak on OpenShift)
deploy-authbridge-remote-kc:
	@echo "=== Deploying AuthBridge with remote Keycloak ==="
	./scripts/setup-authbridge.sh remote-kc

test-authbridge-remote-kc:
	@echo "=== Running AuthBridge tests against remote Keycloak ==="
	KEYCLOAK_URL=https://keycloak.example.com \
		./scripts/test-authbridge.sh

# AuthBridge with AI agents (Kind + Keycloak + summarizer/reviewer)
deploy-authbridge-ai-agents:
	@echo "=== Deploying AuthBridge with AI agents ==="
	./scripts/setup-authbridge.sh ai-agents

deploy-authbridge-ai-agents-remote-kc:
	@echo "=== Deploying AuthBridge with AI agents (remote Keycloak) ==="
	./scripts/setup-authbridge.sh ai-agents-remote-kc

test-authbridge-ai-agents:
	@echo "=== Running AuthBridge AI agents tests ==="
	./scripts/test-authbridge.sh

# AuthBridge on OpenShift (remote Keycloak via OpenShift Route)
deploy-openshift-authbridge: check-deps podman-dev
	@echo "=== Deploying AuthBridge to OpenShift with tag $(DEV_TAG) ==="
	@echo "Updating kustomization with new image tags..."
	@cd deploy/k8s/overlays/openshift-authbridge && \
	for svc in $(BASE_SERVICES); do \
		kustomize edit set image $(REGISTRY)/$$svc:$(DEV_TAG); \
	done
	oc apply -k deploy/k8s/overlays/openshift-authbridge
	@echo ""
	@echo "Deployed with images tagged: $(DEV_TAG)"
	@echo "To rollback: make deploy-openshift-authbridge DEV_TAG=<previous-sha>"

deploy-openshift-authbridge-quick:
	@echo "=== Quick deploy AuthBridge to OpenShift with tag $(DEV_TAG) ==="
	@cd deploy/k8s/overlays/openshift-authbridge && \
	for svc in $(BASE_SERVICES); do \
		kustomize edit set image $(REGISTRY)/$$svc:$(DEV_TAG); \
	done
	oc apply -k deploy/k8s/overlays/openshift-authbridge
	@echo "Deployed with tag: $(DEV_TAG)"

test-openshift-authbridge:
	@echo "=== Running AuthBridge tests on OpenShift ==="
	$(eval KC_ROUTE := $(shell oc get route keycloak -n spiffe-demo -o jsonpath='{.spec.host}' 2>/dev/null))
	@if [ -z "$(KC_ROUTE)" ]; then \
		echo "ERROR: Could not detect Keycloak Route. Is it deployed?"; \
		exit 1; \
	fi
	KEYCLOAK_URL=https://$(KC_ROUTE) \
		./scripts/test-authbridge.sh

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
	@echo "AuthBridge:"
	@echo "  make deploy-authbridge            - Deploy AuthBridge overlay to Kind"
	@echo "  make test-authbridge              - Run AuthBridge token exchange tests"
	@echo "  make deploy-authbridge-remote-kc  - Deploy with remote Keycloak"
	@echo "  make test-authbridge-remote-kc    - Test with remote Keycloak"
	@echo ""
	@echo "AuthBridge with AI agents:"
	@echo "  make deploy-authbridge-ai-agents            - Deploy AuthBridge + AI agents to Kind"
	@echo "  make deploy-authbridge-ai-agents-remote-kc  - Deploy with remote Keycloak"
	@echo "  make test-authbridge-ai-agents              - Run AuthBridge AI agents tests"
	@echo ""
	@echo "AuthBridge on OpenShift:"
	@echo "  make deploy-openshift-authbridge        - Build, push, deploy AuthBridge to OpenShift"
	@echo "  make deploy-openshift-authbridge-quick  - Deploy without rebuild"
	@echo "  make test-openshift-authbridge          - Run AuthBridge tests on OpenShift"
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
	@echo "OpenShift deployment:"
	@echo "  make deploy-openshift         - Build, push, and deploy (uses git SHA tag)"
	@echo "  make deploy-openshift-quick   - Deploy with current SHA (no rebuild)"
	@echo "  make restart-openshift        - Restart all deployments"
	@echo ""
	@echo "GHCR cleanup:"
	@echo "  make ghcr-list                - List recent image tags"
	@echo "  make ghcr-cleanup             - Delete old images (keeps last 10)"
	@echo "  make ghcr-cleanup KEEP_VERSIONS=5"
	@echo ""
	@echo "Variables:"
	@echo "  DEV_TAG    - Image tag (default: git SHA, e.g., abc1234)"
	@echo "  REGISTRY   - Container registry (default: ghcr.io/redhat-et/zero-trust-agent-demo)"
	@echo ""
	@echo "Development:"
	@echo "  make check-deps     - Verify required tools are installed"
	@echo "  make fmt            - Format code"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run linter"
	@echo "  make tidy           - Run go mod tidy"
