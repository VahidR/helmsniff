BINARY    := helmsniff
BIN_DIR   := bin
CMD_DIR   := ./cmd
MODULE    := github.com/VahidR/helmsniff

GO        := go
GOFLAGS   :=
LDFLAGS   := -s -w

.PHONY: all build clean tidy lint vet test run

all: build

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)

clean:
	rm -rf $(BIN_DIR)

tidy:
	$(GO) mod tidy

vet:
	$(GO) vet ./...

lint: vet
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

test:
	$(GO) test -race ./...

run: build
	@echo "Usage: $(BIN_DIR)/$(BINARY) --root <rendered_dir|-> --out <path|-> [--format csv|json]"
	@echo "  Pipe mode: helm template mychart | $(BIN_DIR)/$(BINARY) --root - --out - --format json"
