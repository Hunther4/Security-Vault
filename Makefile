.PHONY: build build-cli clean test test-go test-py serve

BINARY=vault
BUILD_DIR=bin

build: build-cli

build-cli:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/vault
	@echo "✅ Built $(BUILD_DIR)/$(BINARY)"

clean:
	rm -rf $(BUILD_DIR)/ dist/
	go clean
	rm -rf vault.db secure_storage/
	@echo "✅ Cleaned"

test: test-go test-py

test-go:
	go test ./... -v

test-py:
	. venv/bin/activate && python -m pytest portfolio_test.py -v

serve:
	$(BUILD_DIR)/vault serve

release:
	goreleaser release --clean

.PHONY: lint
lint:
	go vet ./...
	. venv/bin/activate && python -m py_compile api.py main.py services.py repositories.py models.py
