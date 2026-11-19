APP := reconx
PKG := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-race vet fmt clean run

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP) ./cmd/reconx

test:
	CGO_ENABLED=0 go test $(PKG)

# The race detector needs cgo, so it is a separate target from the static build.
test-race:
	CGO_ENABLED=1 go test -race $(PKG)

vet:
	CGO_ENABLED=0 go vet $(PKG)

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

clean:
	rm -rf bin reconx_workspaces

run: build
	./bin/$(APP) $(ARGS)
