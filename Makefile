# Makefile for Deceptifeed

SOURCE := ./cmd/deceptifeed/
BIN_DIRECTORY := ./bin/
BIN_DEFAULT := $(BIN_DIRECTORY)deceptifeed
INSTALL_SCRIPT := ./scripts/install.sh
UNINSTALL_SCRIPT := ./scripts/install.sh --uninstall
VERSION := $(shell git describe --tags --dirty --broken)
BUILD_OPTIONS := -trimpath -ldflags="-s -w -X 'github.com/r-smith/deceptifeed/internal/config.Version=$(VERSION:v%=%)'"
GO := go
CGO_ENABLED := 0

.PHONY: build
build:
	@echo "Building for current operating system..."
	@mkdir -p $(BIN_DIRECTORY)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DEFAULT) $(SOURCE)
	@echo "Build complete: $(BIN_DEFAULT)"
	@echo

.PHONY: all
all: build build-linux build-freebsd build-windows

.PHONY: build-linux
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BIN_DIRECTORY)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DEFAULT)_linux_x64 $(SOURCE)
	@echo "Build complete: $(BIN_DEFAULT)_linux_x64"
	@echo

.PHONY: build-freebsd
build-freebsd:
	@echo "Building for FreeBSD..."
	@mkdir -p $(BIN_DIRECTORY)
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DEFAULT)_freebsd_x64 $(SOURCE)
	@echo "Build complete: $(BIN_DEFAULT)_freebsd_x64"
	@echo

.PHONY: build-windows
build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BIN_DIRECTORY)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DEFAULT)_windows_x64.exe $(SOURCE)
	@echo "Build complete: $(BIN_DEFAULT)_windows_x64.exe"
	@echo

.PHONY: install
install: $(BIN_DEFAULT)
	@bash $(INSTALL_SCRIPT)

.PHONY: uninstall
uninstall:
	@bash $(UNINSTALL_SCRIPT)

.PHONY: clean
clean:
	@echo "Cleaning started."
	-@$(GO) clean
	@rm --recursive --force $(BIN_DIRECTORY)
	@echo "Cleaning complete."
