# ossl — Makefile
#
# Targets:
#   ci          — CI entry point: vet + fmt-check + test-race + cgocheck2 + nocgo + api-parity
#   build       — compile the package
#   nocgo       — build, vet and test the CGO_ENABLED=0 stub configuration
#   api-parity  — fail if the cgo and non-cgo builds export different APIs
#   test        — run all tests (no race detector)
#   test-race   — run all tests with the race detector
#   cgocheck2   — run tests under the deep cgo pointer checker
#   vet         — go vet
#   fmt         — format Go source
#   fmt-check   — fail if any Go source is unformatted
#   clean       — remove build artifacts

.PHONY: help build nocgo api-parity test test-race cgocheck2 vet fmt fmt-check ci clean

.DEFAULT_GOAL := help

# OpenSSL 3.5 prefix this package is built and tested against. pkg-config
# supplies -I/-L; CGO_LDFLAGS' rpath is what makes the dynamic loader agree
# with pkg-config at runtime instead of falling back to a system libcrypto —
# without it CheckVersion() (see ossl/ossl.go) is what catches the mismatch.
OPENSSL_PREFIX ?= /opt/openssl3.5.2

export PKG_CONFIG_PATH := $(OPENSSL_PREFIX)/lib64/pkgconfig
export CGO_LDFLAGS := -Wl,-rpath,$(OPENSSL_PREFIX)/lib64

help: ## Show this help (list all available targets)
	@printf "\n\033[1mUsage:\033[0m make <target>\n\n"
	@printf "\033[1mTargets:\033[0m\n"
	@awk 'BEGIN {FS = ":.*##"} \
	     /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' \
	     $(MAKEFILE_LIST)
	@printf "\n\033[1mTunable variables:\033[0m\n"
	@printf "  \033[33m%-14s\033[0m %s (default: %s)\n" "OPENSSL_PREFIX" "OpenSSL 3.5 install prefix" "$(OPENSSL_PREFIX)"

build: ## Compile the package
	go build ./...

nocgo: ## Build, vet and test the CGO_ENABLED=0 stub configuration
	CGO_ENABLED=0 go build ./...
	CGO_ENABLED=0 go vet ./...
	CGO_ENABLED=0 go test -count=1 ./...

api-parity: ## Fail if the cgo and non-cgo builds export different APIs
	@# Building the stub only proves it compiles against its own tests, which
	@# do not touch most of the surface: a changed signature in ossl/nocgo.go
	@# slips through that entirely. Comparing the two exported APIs is what
	@# actually catches drift. Struct bodies are normalised because the cgo
	@# types carry unexported fields and the stubs are empty, which is a
	@# difference of implementation rather than of API.
	@go doc -all ./ossl 2>/dev/null \
		| grep -E '^(func|type|var|const)|^    func' \
		| sed -e 's/^ *//' -e 's/struct{}$$/struct {/' | sort > /tmp/ossl-api-cgo.txt
	@CGO_ENABLED=0 go doc -all ./ossl 2>/dev/null \
		| grep -E '^(func|type|var|const)|^    func' \
		| sed -e 's/^ *//' -e 's/struct{}$$/struct {/' | sort > /tmp/ossl-api-nocgo.txt
	@if ! diff -u /tmp/ossl-api-cgo.txt /tmp/ossl-api-nocgo.txt; then \
		echo; echo "cgo and non-cgo builds export different APIs (see diff above)"; \
		echo "update ossl/nocgo.go to match"; exit 1; \
	fi
	@echo "api-parity: cgo and non-cgo exports match ($$(wc -l < /tmp/ossl-api-cgo.txt) entries)"

test: ## Run all unit tests (no race detector)
	go test -count=1 ./...

test-race: ## Run all unit tests with the race detector
	go test -race -count=1 ./...

cgocheck2: ## Run tests under the deep cgo pointer checker
	GOEXPERIMENT=cgocheck2 go test -count=1 ./...

vet: ## Run 'go vet'
	go vet ./...

fmt: ## Format Go source (gofmt)
	gofmt -w .

fmt-check: ## Fail if any Go source is unformatted
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi

ci: vet fmt-check test-race cgocheck2 nocgo api-parity ## CI entry point: vet + fmt-check + test-race + cgocheck2 + nocgo + api-parity

clean: ## Remove build artifacts
	go clean ./...
