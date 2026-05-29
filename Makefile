BINARY := siovos-audit
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test lint run clean

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/siovos-audit

test:
	go test ./... -v

lint:
	golangci-lint run

run-local:
	go run ./cmd/siovos-audit run --local

clean:
	rm -rf bin/ dist/
