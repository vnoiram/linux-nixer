GO ?= go
GOCACHE ?= /tmp/codex-go-build
GOMODCACHE ?= /tmp/codex-go-mod
BINARY ?= linux-nixer

.PHONY: test vet fmt fmt-check build clean

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

vet:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) vet ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)"

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -o bin/$(BINARY) ./cmd/linux-nixer

clean:
	rm -rf bin dist
