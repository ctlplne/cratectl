SHELL := /bin/sh
GO := $(if $(wildcard .cache/go/bin/go),$(CURDIR)/.cache/go/bin/go,go)
export GOCACHE := $(CURDIR)/.cache/go-build
export GOMODCACHE := $(CURDIR)/.cache/go-mod
export GOTOOLCHAIN := local
.PHONY: build test race lint integration conformance security packaging console console-check
build:
	python3 scripts/check_console_assets.py
	mkdir -p bin
	$(GO) build -trimpath -o bin/cratectld ./cmd/cratectld
	$(GO) build -trimpath -o bin/cratectl ./cmd/cratectl
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
lint:
	$(GO) vet ./...
	python3 scripts/check_architecture.py
	python3 scripts/check_console_assets.py
console:
	python3 scripts/build_console.py
console-check:
	python3 scripts/build_console.py --check
integration: build
	$(GO) test -count=1 -tags=integration ./internal/store ./internal/server ./internal/conformance
conformance: build
	python3 scripts/conformance.py all
security:
	@echo 'Security campaign is not yet complete; see docs/qualification/remaining.json'; exit 1
packaging:
	@echo 'Release packaging is not yet qualified; see docs/qualification/remaining.json'; exit 1
