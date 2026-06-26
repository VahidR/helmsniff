BINARY    := helmsniff
BIN_DIR   := bin
CMD_DIR   := ./cmd
MODULE    := github.com/VahidR/helmsniff

GO        := go
GOFLAGS   :=
LDFLAGS   := -s -w

VERSION   ?= dev
DIST_DIR  := dist

.PHONY: all build clean tidy lint vet test run dist dist-linux dist-windows dist-macos

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

# --- Cross-platform release archives (mirrors the GitHub Actions release matrix) ---
dist: dist-linux dist-windows dist-macos

dist-linux:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/$(BINARY) $(CMD_DIR)
	tar czf $(DIST_DIR)/$(BINARY)-linux-amd64.tar.gz -C $(DIST_DIR) $(BINARY) -C $(CURDIR) README.md LICENSE
	rm -f $(DIST_DIR)/$(BINARY)

dist-windows:
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/$(BINARY).exe $(CMD_DIR)
	cd $(DIST_DIR) && zip -j $(BINARY)-windows-amd64.zip $(BINARY).exe $(CURDIR)/README.md $(CURDIR)/LICENSE
	rm -f $(DIST_DIR)/$(BINARY).exe

dist-macos:
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(DIST_DIR)/$(BINARY) $(CMD_DIR)
	cd $(DIST_DIR) && zip -j $(BINARY)-macos-arm64.zip $(BINARY) $(CURDIR)/README.md $(CURDIR)/LICENSE
	rm -f $(DIST_DIR)/$(BINARY)
