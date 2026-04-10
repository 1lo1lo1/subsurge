BINARY     := subsurge
CMD        := ./cmd/subsurge
VERSION    := 1.0.0
LDFLAGS    := -ldflags="-s -w -X main.version=$(VERSION)"
BUILD_DIR  := ./dist

.PHONY: all build install clean tidy release test lint

all: tidy build

## build: Compile for the current platform
build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)
	@echo "Built: $(BUILD_DIR)/$(BINARY)"

## install: Install to GOPATH/bin (or /usr/local/bin with sudo)
install:
	go install $(LDFLAGS) $(CMD)
	@echo "Installed: $(BINARY)"

## tidy: Download and tidy dependencies
tidy:
	go mod tidy

## test: Run all tests
test:
	go test ./... -v -timeout 30s

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## release: Cross-compile for Linux, macOS, Windows (amd64 + arm64)
release:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   $(CMD)
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64   $(CMD)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  $(CMD)
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  $(CMD)
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(CMD)
	@echo "Release binaries in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
