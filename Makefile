BINARY     := registry-cli
MODULE     := github.com/sirosfoundation/registry-cli
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -ldflags "-X $(MODULE)/cmd/registry-cli/cmd.Version=$(VERSION) \
              -X $(MODULE)/cmd/registry-cli/cmd.Commit=$(COMMIT) \
              -X $(MODULE)/cmd/registry-cli/cmd.BuildTime=$(BUILD_TIME)"

.PHONY: build test lint fmt vet tidy clean docker docker-run

build: ## Build registry-cli binary
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/registry-cli

test: ## Run tests
	go test -v -race ./...

test-softhsm: ## Run tests including SoftHSM integration tests
	go test -v -race -tags softhsm ./...

coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

lint: ## Run linter
	golangci-lint run ./...

fmt: ## Format code
	go fmt ./...
	goimports -w .

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy go modules
	go mod tidy

docker: ## Build Docker image
	docker build -t registry-cli:latest \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_TIME) .

docker-run: ## Run Docker container with local sources
	docker compose up --build

clean: ## Remove build artifacts
	rm -rf bin/ coverage.out

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
