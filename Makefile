.PHONY: build build-all clean test test-race test-cover test-verbose bench run fmt vet lint help

BINARY_NAME=gih-sorgu
DIST_DIR=dist
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)
VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "local")
BUILD_TIME=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-s -w -X 'main.Version=$(VERSION)' -X 'main.BuildCommit=$(COMMIT)' -X 'main.BuildTime=$(BUILD_TIME)'

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

build-all:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-arm64.exe .
	GOOS=linux GOARCH=amd64   go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64   go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64  go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64  go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 .

clean:
	rm -f $(BINARY_NAME)
	rm -rf $(DIST_DIR)
	go clean

test:
	go test ./...

test-race:
	go test -race ./...

test-cover:
	go test -cover ./...

test-verbose:
	go test -v ./...

bench:
	go test -bench=. -benchmem ./...

run: build
	./$(BINARY_NAME)

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet

help:
	@echo "Available targets:"
	@echo "  build        - Build binary for current platform"
	@echo "  build-all    - Cross-compile for all platforms (dist/)"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run all tests"
	@echo "  test-race    - Run tests with race detector"
	@echo "  test-cover   - Run tests with coverage"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  bench        - Run benchmarks"
	@echo "  run          - Build and run"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  lint         - Run fmt and vet"
