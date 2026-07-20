GO ?= go
GOCACHE ?= /tmp/codex-go-build
GOMODCACHE ?= /tmp/codex-go-mod
BINARY ?= linux-nixer
VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: test vet fmt fmt-check build clean changelog-check release-check

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

vet:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)"

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/linux-nixer

changelog-check:
	scripts/check-changelog.sh $(VERSION)

release-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) scripts/release-check.sh $(VERSION)

clean:
	rm -rf bin dist
