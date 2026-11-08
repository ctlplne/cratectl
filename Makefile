SHELL := /bin/sh
GO := $(if $(wildcard .cache/go/bin/go),$(CURDIR)/.cache/go/bin/go,go)
BINDIR ?= $(if $(CRATECTL_QUALIFICATION_BIN_DIR),$(CRATECTL_QUALIFICATION_BIN_DIR),bin)
export CRATECTL_QUALIFICATION_BIN_DIR := $(abspath $(BINDIR))
export GOCACHE := $(CURDIR)/.cache/go-build
export GOMODCACHE := $(CURDIR)/.cache/go-mod
export GOTOOLCHAIN := local
.PHONY: build test race lint integration integration-race conformance security packaging console console-check
build:
	python3 scripts/check_console_assets.py
	mkdir -p "$(BINDIR)"
	$(GO) build -trimpath -o "$(BINDIR)/cratectld" ./cmd/cratectld
	$(GO) build -trimpath -o "$(BINDIR)/cratectl" ./cmd/cratectl
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
lint:
	$(GO) vet ./...
	python3 scripts/check_architecture.py
	python3 scripts/test_architecture.py
	python3 scripts/check_console_assets.py
	python3 scripts/check_openapi_descriptions.py
	python3 scripts/test_qualification_contract.py
	python3 scripts/ci/test_historical_baselines.py
	python3 scripts/ci/test_evidence_summary.py
	python3 scripts/ci/test_browser_failure_summary.py
	python3 scripts/ci/test_native_client_diagnostics.py
	python3 scripts/ci/test_postgres_binding.py
	python3 scripts/ci/test_check_schema_plan.py
	python3 scripts/ci/test_campaign_transport.py
	python3 scripts/ci/test_campaign_reports.py
	python3 scripts/ci/test_accept_campaign.py
	python3 scripts/ci/test_prepare_owned_ports.py
	python3 scripts/ci/test_maven_install.py
	python3 scripts/ci/test_fetch_archive.py
	python3 scripts/ci/test_select_changes.py
	python3 scripts/ci/test_maven_evidence.py
	python3 scripts/test_oci_client_contract.py
	python3 scripts/test_nuget_feed_cases.py
	python3 scripts/test_bounded_client.py
	python3 scripts/test_conformance_profile.py
	python3 scripts/test_go_module_profile.py
	python3 scripts/test_go_file_proxy.py
	python3 scripts/test_go_tls_proxy.py
	python3 scripts/test_go_checksum_client_report.py
	python3 scripts/ci/test_gradle_evidence.py
	python3 scripts/test_gradle_publication.py
	python3 scripts/test_ivy_fixture.py
	python3 scripts/ci/test_ivy_evidence.py
	python3 scripts/test_sbt_fixture.py
	python3 scripts/ci/test_sbt_evidence.py
	python3 scripts/ci/test_go_module_evidence.py
	python3 scripts/ci/test_journal_evidence.py
	python3 scripts/ci/test_go_export_portability_evidence.py
	python3 scripts/ci/test_go_common_export_portability_evidence.py
	python3 scripts/ci/test_go_requirement_export_portability_evidence.py
	python3 scripts/ci/test_go_requirement_acknowledgement.py
	python3 scripts/ci/test_owned_child_process.py
	python3 scripts/ci/test_go_export_portable_diagnostics.py
	python3 scripts/test_go_export_portable.py
	python3 scripts/test_go_common_export_fixture.py
	python3 scripts/test_go_common_export_transport.py
	python3 scripts/test_go_requirement_export_fixture.py
	python3 scripts/test_go_requirement_export_transport.py
	python3 scripts/test_ci_native_diagnostics.py
console:
	python3 scripts/build_console.py
console-check:
	python3 scripts/build_console.py --check
integration: build
	# Package suites share the owned loopback ports; never run their listeners concurrently.
	$(GO) test -p=1 -count=1 -tags=integration ./internal/store ./internal/server ./internal/conformance
	python3 scripts/test_sql_timing.py
integration-race:
	$(GO) test -p=1 -race -count=1 -tags=integration ./internal/store ./internal/server ./internal/conformance
conformance: build
	python3 scripts/conformance.py all
security:
	@echo 'Security campaign is not yet complete; see docs/qualification/remaining.json'; exit 1
packaging:
	@echo 'Release packaging is not yet qualified; see docs/qualification/remaining.json'; exit 1
