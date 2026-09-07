BINARY      := network-sniffer
PKG         := ./cmd/network-sniffer
BIN_DIR     := bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -X main.version=$(VERSION)
GO          ?= go

.PHONY: all build run test cover lint vet fmt tidy clean docker

all: lint test build

build: ## Compile the binary into bin/
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

run: build ## Build then run (pass ARGS="-i eth0 ...")
	./$(BIN_DIR)/$(BINARY) $(ARGS)

test: ## Run all tests
	$(GO) test ./... -count=1

cover: ## Run tests with a coverage summary
	$(GO) test ./... -covermode=atomic -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -n 1

vet: ## go vet
	$(GO) vet ./...

fmt: ## Format the tree
	$(GO) fmt ./...

lint: vet ## Static checks (vet + staticcheck if present)
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

tidy: ## Sync go.mod/go.sum
	$(GO) mod tidy

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out

docker: ## Build the container image
	docker build -f deployments/Dockerfile -t $(BINARY):$(VERSION) .
