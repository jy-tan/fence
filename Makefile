GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
BINARY_NAME=fence
BINARY_UNIX=$(BINARY_NAME)_unix

# Tool versions
GOLANGCI_LINT_VERSION=v2.11.4

# Platform matrix for cross-platform operations
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: all build build-ci build-linux build-darwin test test-ci clean deps install-lint-tools setup setup-ci run fmt lint lint-all lint-platform schema help

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

# Base lint command with argument pass-through
LINT_CMD = CGO_ENABLED=0 GOOS=$(word 1,$(subst /, ,$1)) GOARCH=$(word 2,$(subst /, ,$1)) golangci-lint run --allow-parallel-runners $(ARGS)

# Lint for current platform use ARGS="..." for options like --fix
# This is also used in CI for matrix builds
lint:
	@echo "🔍 Linting for current platform..."
	$(call LINT_CMD,$(shell go env GOOS)/$(shell go env GOARCH))

# All platforms
lint-all:
	@$(foreach platform,$(PLATFORMS),echo "Linting $(platform)$(if $(ARGS), with: $(ARGS))..."; $(call LINT_CMD,$(platform));)

# Single platform use PLATFORM=os/arch
lint-platform:
	@$(if $(PLATFORM),,$(error Usage: make lint-platform PLATFORM=os/arch [ARGS="..."]))
	@echo "Linting $(PLATFORM)$(if $(ARGS), with: $(ARGS))..."
	@$(call LINT_CMD,$(PLATFORM))

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
	@echo "  lint               - Lint code for current platform"
	@echo "  lint-all           - Lint all platforms (use ARGS for options)"
	@echo "  lint-platform      - Lint specific platform (PLATFORM=os/arch, ARGS for options)"
	@echo "  schema             - Regenerate docs/schema/fence.schema.json"
	@echo "  release            - Create patch release (v0.0.X)"
	@echo "  release-minor      - Create minor release (v0.X.0)"
	@echo "  help               - Show this help"
	@echo ""
	@echo "Platform matrix: $(PLATFORMS)"
	@echo "Examples:"
	@echo "  make lint-all ARGS=\"--fix\""
	@echo "  make lint-platform PLATFORM=linux/amd64 ARGS=\"--fix --verbose\""
