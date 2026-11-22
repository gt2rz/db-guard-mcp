BINARY := db-guard-mcp
DATABASE_URL ?= postgres://devuser:devpassword@localhost:55432/ecommerce_demo?sslmode=disable

.PHONY: help build test test-integration smoke demo-up demo-down lint fmt tidy release-snapshot clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

build: ## Build a static binary
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/server

test: ## Run unit tests with the race detector
	go test -race ./...

test-integration: ## Run integration tests against DATABASE_URL
	TEST_DATABASE_URL="$(DATABASE_URL)" go test -tags integration -v ./internal/db/...

smoke: build ## Run the end-to-end MCP smoke test
	DATABASE_URL="$(DATABASE_URL)" python3 scripts/smoke_test.py ./$(BINARY)

demo-up: ## Start the demo PostgreSQL instance
	docker compose up -d

demo-down: ## Stop the demo instance and delete its data
	docker compose down -v

lint: ## Run go vet and check formatting
	go vet ./...
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; \
	fi

fmt: ## Format the code
	gofmt -s -w .

tidy: ## Tidy go.mod / go.sum
	go mod tidy

release-snapshot: ## Build release artifacts locally without publishing
	goreleaser release --snapshot --clean

clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out
	rm -rf dist
