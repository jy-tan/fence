GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=fence
BINARY_UNIX=$(BINARY_NAME)_unix

# Tool versions
GOLANGCI_LINT_VERSION=v2.11.4

.PHONY: all build build-ci build-linux build-darwin test test-ci clean deps install-lint-tools setup setup-ci run fmt lint lint-fix release release-minor schema help

all: build

build:
	@echo "🔨 Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) -v ./cmd/fence

build-ci:
	@echo "🏗️  CI: Building $(BINARY_NAME) with version info..."
	$(eval VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev"))
	$(eval BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ'))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))
	$(GOBUILD) -ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)" -o $(BINARY_NAME) -v ./cmd/fence

test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v ./...

test-ci:
	@echo "🧪 CI: Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f coverage.out

deps:
	@echo "📦 Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

build-linux:
	@echo "🐧 Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./cmd/fence

build-darwin:
	@echo "🍎 Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_NAME)_darwin -v ./cmd/fence

install-lint-tools:
	@echo "📦 Installing linting tools..."
	go install mvdan.cc/gofumpt@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "✅ Linting tools installed"

setup: deps install-lint-tools
	@echo "✅ Development environment ready"

setup-ci: deps install-lint-tools
	@echo "✅ CI environment ready"

run: build
	./$(BINARY_NAME)

fmt:
	@echo "📝 Formatting code..."
	gofumpt -w .

lint:
	@echo "🔍 Linting code..."
	golangci-lint run --allow-parallel-runners

lint-fix:
	@echo "🔍 Linting and fixing code..."
	golangci-lint run --allow-parallel-runners --fix


schema:
	@echo "🧾 Generating config JSON schema..."
	go run ./tools/generate-config-schema

release:
	@echo "🚀 Creating patch release..."
	./scripts/release.sh patch

release-minor:
	@echo "🚀 Creating minor release..."
	./scripts/release.sh minor

help:
	@echo "Available targets:"
	@echo "  all                - build (default)"
	@echo "  build              - Build the binary"
	@echo "  build-ci           - Build for CI with version info"
	@echo "  build-linux        - Build for Linux"
	@echo "  build-darwin       - Build for macOS"
	@echo "  test               - Run tests"
	@echo "  test-ci            - Run tests for CI with coverage"
	@echo "  clean              - Clean build artifacts"
	@echo "  deps               - Download dependencies"
	@echo "  install-lint-tools - Install linting tools"
	@echo "  setup              - Setup development environment"
	@echo "  setup-ci           - Setup CI environment"
	@echo "  run                - Build and run"
	@echo "  fmt                - Format code"
	@echo "  lint               - Lint code"
	@echo "  schema             - Regenerate docs/schema/fence.schema.json"
	@echo "  release            - Create patch release (v0.0.X)"
	@echo "  release-minor      - Create minor release (v0.X.0)"
	@echo "  help               - Show this help"
