# Makefile for Deceptifeed

SOURCE = ./cmd/deceptifeed/
BIN_DIRECTORY = ./bin/
BIN_DEFAULT = deceptifeed
BIN_LINUX = $(BIN_DEFAULT)_linux_amd64
BIN_FREEBSD = $(BIN_DEFAULT)_freebsd_amd64
BIN_WINDOWS = $(BIN_DEFAULT)_windows_amd64.exe
INSTALL_SCRIPT = ./scripts/install.sh
UNINSTALL_SCRIPT = ./scripts/install.sh --uninstall
BUILD_OPTIONS = -trimpath -ldflags="-s -w"
GO = go
CGO_ENABLED = 0
GO111MODULE = on

.PHONY: build
build:
	@echo "Building for current operating system to: $(BIN_DIRECTORY)$(BIN_DEFAULT)"
	@mkdir -p $(BIN_DIRECTORY)
	GO111MODULE=$(GO111MODULE) CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DIRECTORY)$(BIN_DEFAULT) $(SOURCE)
	@echo "Build complete."
	@echo

.PHONY: all
all: build build-linux build-freebsd build-windows

.PHONY: build-linux
build-linux:
	@echo "Building for Linux to: $(BIN_DIRECTORY)$(BIN_LINUX)"
	@mkdir -p $(BIN_DIRECTORY)
	GOOS=linux GOARCH=amd64 GO111MODULE=$(GO111MODULE) CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DIRECTORY)$(BIN_LINUX) $(SOURCE)
	@echo "Build complete."
	@echo

.PHONY: build-freebsd
build-freebsd:
	@echo "Building for FreeBSD to: $(BIN_DIRECTORY)$(BIN_FREEBSD)"
	@mkdir -p $(BIN_DIRECTORY)
	GOOS=freebsd GOARCH=amd64 GO111MODULE=$(GO111MODULE) CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DIRECTORY)$(BIN_FREEBSD) $(SOURCE)
	@echo "Build complete."
	@echo

.PHONY: build-windows
build-windows:
	@echo "Building for Windows to: $(BIN_DIRECTORY)$(BIN_WINDOWS)"
	@mkdir -p $(BIN_DIRECTORY)
	GOOS=windows GOARCH=amd64 GO111MODULE=$(GO111MODULE) CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(BUILD_OPTIONS) -o $(BIN_DIRECTORY)$(BIN_WINDOWS) $(SOURCE)
	@echo "Build complete."
	@echo

.PHONY: install
install: $(BIN_DIRECTORY)$(BIN_DEFAULT)
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
