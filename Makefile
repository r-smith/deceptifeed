# Makefile for Deceptifeed

TARGET_BINARY := ./bin/deceptifeed
SOURCE = ./cmd/deceptifeed/
INSTALL_SCRIPT = ./scripts/install.sh
UNINSTALL_SCRIPT = ./scripts/install.sh --uninstall
GO = go
CGO_ENABLED = 0
GO111MODULE = on

.PHONY: build
build:
	@echo "Building to: ./bin/"
	@mkdir -p ./bin/
	GO111MODULE=$(GO111MODULE) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -o $(TARGET_BINARY) $(SOURCE)
	@echo "Build complete."

.PHONY: install
install: $(TARGET_BINARY)
	@bash $(INSTALL_SCRIPT)

.PHONY: uninstall
uninstall:
	@bash $(UNINSTALL_SCRIPT)

.PHONY: clean
clean:
	@echo "Cleaning started."
	-@$(GO) clean
	@rm --recursive --force ./bin/
	@echo "Cleaning complete."
