# justfile - Command runner for oauth-impl

ldflags := '-s -w -X github.com/bravo68web/oauth-impl/internal/version.Version=dev -X github.com/bravo68web/oauth-impl/internal/version.Commit=$(git rev-parse --short=12 HEAD 2>/dev/null || true) -X github.com/bravo68web/oauth-impl/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)'

# Default recipe - show available commands
default:
    @just --list

# Build all binaries. Rebuild after editing internal/hashalgo/algo.go.
build:
    go build -trimpath -ldflags="{{ldflags}}" -o bin/oauth-server ./cmd/oauth-server
    go build -trimpath -ldflags="{{ldflags}}" -o bin/oauth-cli ./cmd/oauth-cli
    go build -trimpath -ldflags="{{ldflags}}" -o bin/oauth-mobile ./cmd/oauth-mobile

# Build server only
build-server:
    go build -trimpath -ldflags="{{ldflags}}" -o bin/oauth-server ./cmd/oauth-server

# Build CLI only
build-cli:
    go build -trimpath -ldflags="{{ldflags}}" -o bin/oauth-cli ./cmd/oauth-cli

# Build mobile CLI only
build-mobile:
    go build -trimpath -ldflags="{{ldflags}}" -o bin/oauth-mobile ./cmd/oauth-mobile

# Run the server from the project root. Loads config.yaml and recompiles algo.go.
run:
    go run -trimpath -ldflags="{{ldflags}}" cmd/oauth-server/main.go

# Run the server with hot reload (requires air)
dev:
    air

# Run tests
test:
    go test ./... -v

# Run tests with coverage
test-cover:
    go test ./... -coverprofile=coverage.out
    go tool cover -html=coverage.out -o coverage.html

# Playwright + Mocha flows. Install browsers once: cd e2e && npx playwright install chromium
e2e:
    cd e2e && npm test

# Lint code (requires golangci-lint)
lint:
    golangci-lint run ./...

# Format code
fmt:
    go fmt ./...
    goimports -w .

# Vet code
vet:
    go vet ./...

# Tidy dependencies
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -rf bin/
    rm -f oauth.db
    rm -f coverage.out coverage.html

# Show API docs info
docs:
    @echo "OpenAPI spec: openapi/spec.yaml"
    @echo "Docs UI:      http://localhost:8080/docs"
    @echo "Spec JSON:    http://localhost:8080/openapi"
    @echo "Spec YAML:    http://localhost:8080/docs/openapi.yaml"

# Run full check (fmt, vet, lint, test)
check: fmt vet lint test

# Install development tools
install-tools:
    go install github.com/air-verse/air@latest
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    go install golang.org/x/tools/cmd/goimports@latest

# Create database backup
backup-db:
    cp oauth.db oauth.db.bak.$(date +%Y%m%d%H%M%S)

# Show server logs
logs:
    tail -f logs/server.log

# Docker build
docker-build:
    docker build -t oauth-impl .

# Docker run
docker-run:
    docker run -p 8080:8080 oauth-impl

# Start with custom port
run-port port:
    go run cmd/oauth-server/main.go --port {{port}}

# Run with custom config
run-config config:
    go run cmd/oauth-server/main.go --config {{config}}

# Quick test flow
test-flow:
    #!/bin/bash
    set -e
    CFG=$(mktemp)
    trap 'rm -f "$CFG"' EXIT
    # just 1.51 parses << as its own multi-line token, so write the file with printf.
    printf '%s\n' \
      'server:' \
      '  host: "127.0.0.1"' \
      '  port: 8080' \
      '  tls:' \
      '    enabled: false' \
      > "$CFG"
    echo "=== Starting server ==="
    go run cmd/oauth-server/main.go --config "$CFG" &
    SERVER_PID=$!
    sleep 2
    
    echo "=== Register client ==="
    CLIENT=$(curl -s -X POST http://localhost:8080/oauth/register \
      -H "Content-Type: application/json" \
      -d '{"client_name":"Test","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code","client_credentials"],"scope":"openid profile"}')
    CLIENT_ID=$(echo $CLIENT | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
    CLIENT_SECRET=$(echo $CLIENT | grep -o '"client_secret":"[^"]*"' | cut -d'"' -f4)
    echo "Client: $CLIENT_ID"
    
    echo "=== Client credentials token ==="
    curl -s -X POST http://localhost:8080/oauth/token \
      -u "$CLIENT_ID:$CLIENT_SECRET" \
      -d "grant_type=client_credentials&scope=openid" | jq .
    
    echo "=== Cleanup ==="
    kill $SERVER_PID 2>/dev/null || true
    rm -f oauth.db "$CFG"
    echo "Done!"
