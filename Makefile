.PHONY: build test clean install

BINARY := disunity

build:
	go build -o $(BINARY) ./cmd/disunity

test:
	go test ./...

install: build
	install -d ~/.disunity/bin
	install -d ~/.disunity/scripts/ghidra
	install -d ~/.disunity/scripts/ida
	install -m 755 $(BINARY) ~/.disunity/bin/$(BINARY)
	install -m 644 scripts/ghidra/*.py ~/.disunity/scripts/ghidra/
	install -m 644 scripts/ida/*.py ~/.disunity/scripts/ida/
	@echo ""
	@echo "installed: ~/.disunity/bin/$(BINARY)"
	@echo "installed: ~/.disunity/scripts/ghidra/"
	@echo "installed: ~/.disunity/scripts/ida/"
	@echo ""
	@if command -v disunity >/dev/null 2>&1; then \
		echo "disunity is already in PATH"; \
	else \
		RC=~/.zshrc; \
		[ -f ~/.bashrc ] && [ ! -f ~/.zshrc ] && RC=~/.bashrc; \
		echo "Add to PATH:"; \
		echo "  echo 'export PATH=\"$$HOME/.disunity/bin:$$PATH\"' >> $$RC"; \
		echo "  source $$RC"; \
	fi

clean:
	rm -f $(BINARY)
	go clean ./...
