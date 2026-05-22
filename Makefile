.PHONY: build build-cli clean test serve

BINARY=vault
BUILD_DIR=bin

build: build-cli

build-cli:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/vault
	@echo "✅ Built $(BUILD_DIR)/$(BINARY)"

clean:
	rm -rf $(BUILD_DIR)/
	go clean
	@echo "✅ Cleaned"

test:
	go test ./... -v

serve:
	$(BUILD_DIR)/vault serve
