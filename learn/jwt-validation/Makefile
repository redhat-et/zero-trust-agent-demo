.PHONY: build run test clean get-token

# Build the CLI
build:
	go build -o jwt-validation .

# Run with a test token
run: build
	./jwt-validation validate \
		--token-file test-token.txt \
		--jwks-url http://localhost:8080/realms/demo/protocol/openid-connect/certs

# Get a test token from Keycloak (requires port-forward and client credentials)
# Usage: make get-token CLIENT_ID=your-client CLIENT_SECRET=your-secret
get-token:
	@if [ -z "$(CLIENT_ID)" ] || [ -z "$(CLIENT_SECRET)" ]; then \
		echo "Usage: make get-token CLIENT_ID=<id> CLIENT_SECRET=<secret>"; \
		exit 1; \
	fi
	@curl -sX POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
		-d 'grant_type=client_credentials' \
		-d "client_id=$(CLIENT_ID)" \
		-d "client_secret=$(CLIENT_SECRET)" \
		| jq -r '.access_token' > test-token.txt
	@echo "Token saved to test-token.txt"
	@echo "Token preview (first 50 chars):"
	@head -c 50 test-token.txt && echo "..."

# Decode token payload (for debugging, no validation)
decode:
	@cat test-token.txt | cut -d. -f2 | base64 -d 2>/dev/null | jq . || \
		(cat test-token.txt | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)

# View JWKS from Keycloak
jwks:
	curl -s http://localhost:8080/realms/demo/protocol/openid-connect/certs | jq .

# Clean build artifacts
clean:
	rm -f jwt-validation test-token.txt

# Run go tests (when you add them)
test:
	go test -v ./...
