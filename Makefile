# crackweb —— traffic-driven web DAST scanner
# Maintained by guaidao2 & coolmoon

BINARY   := crackweb
BIN_DIR  := bin
DIST_DIR := dist

# The toolchain every published binary is built with, so a release can be
# reproduced from the source. Pinned here as well as in the release workflow: a
# build by any other patch release is a different binary from the same source.
TOOLCHAIN := go1.26.4

# Single source of truth: read the version straight out of internal/version.
VERSION := $(shell sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' internal/version/version.go)

# Release matrix (matches the GitHub release workflow).
PLATFORMS := linux/amd64 linux/arm64 linux/386 \
             windows/amd64 windows/arm64 \
             darwin/amd64 darwin/arm64

GOFLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w

.PHONY: all build test test-race vet fmt check clean release dist-list run help

all: build

## build: compile the binary for the current platform into bin/
build:
	@mkdir -p $(BIN_DIR)
	GOTOOLCHAIN=$(TOOLCHAIN) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/crackweb

## test: run the full unit test suite
test:
	go test ./...

## test-race: run the test suite with the race detector
test-race:
	go test -race ./...

## check: gofmt + vet + test
check: fmt vet test

## fmt: format the source tree
fmt:
	gofmt -l -w .

## vet: static analysis
vet:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

## release: cross-compile every platform, package as tar.gz / zip, emit SHA256 sums
##          into dist/ — ready to attach to a GitHub release
release:
	@mkdir -p $(DIST_DIR)
	@set -e; \
	for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		name="$(BINARY)_$(VERSION)_$${os}_$${arch}"; \
		printf '==> building %-8s %-6s\n' "$$os" "$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			GOTOOLCHAIN=$(TOOLCHAIN) \
			go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o "$(DIST_DIR)/$$name/$(BINARY)$$ext" ./cmd/crackweb ; \
		cp README.md "$(DIST_DIR)/$$name/"; \
		cp README.zh-CN.md "$(DIST_DIR)/$$name/"; \
		if [ "$$os" = "windows" ]; then \
			(cd $(DIST_DIR) && zip -qr "$$name.zip" "$$name"); \
		else \
			(cd $(DIST_DIR) && tar -czf "$$name.tar.gz" "$$name"); \
		fi; \
		rm -rf "$(DIST_DIR)/$$name"; \
	done; \
	(cd $(DIST_DIR) && sha256sum *.tar.gz *.zip > sha256sums.txt)
	@echo
	@echo "==> artifacts ($(DIST_DIR)/):"
	@ls -1sh $(DIST_DIR)
	@echo
	@echo "==> checksums ($(DIST_DIR)/sha256sums.txt):"
	@cat $(DIST_DIR)/sha256sums.txt

## dist-list: list the release artifacts already built
dist-list:
	@ls -1 $(DIST_DIR) 2>/dev/null || echo "no artifacts yet — run 'make release' first"

## run: build and print the English help
run: build
	./$(BIN_DIR)/$(BINARY) --help

## help: show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
