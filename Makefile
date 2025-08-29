.PHONY: build test lint clean fmt vet security

# Default target
all: build test lint

# Build the plugin
build:
	@echo "Building plugin..."
	@go build -v ./...

# Run tests
test:
	@echo "Running tests..."
	@go test -race -coverprofile=coverage.out ./...

# Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	@go test -race -v -coverprofile=coverage.out ./...

# Show test coverage
coverage: test
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Security scan
security:
	@echo "Running security scan..."
	@gosec ./...

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f coverage.out coverage.html
	@go clean ./...

# Install development dependencies
install-deps:
	@echo "Installing development dependencies..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Download and verify dependencies
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod verify

# Tidy up dependencies
tidy:
	@echo "Tidying up dependencies..."
	@go mod tidy

# Run all checks (CI pipeline)
ci: fmt vet lint test security

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the plugin"
	@echo "  test           - Run tests"
	@echo "  test-verbose   - Run tests with verbose output"
	@echo "  coverage       - Generate test coverage report"
	@echo "  lint           - Run golangci-lint"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  security       - Run security scan"
	@echo "  clean          - Clean build artifacts"
	@echo "  install-deps   - Install development dependencies"
	@echo "  deps           - Download and verify dependencies"
	@echo "  tidy           - Tidy up dependencies"
	@echo "  ci             - Run all checks (CI pipeline)"
	@echo "  help           - Show this help message"
