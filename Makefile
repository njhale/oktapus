# Makefile for oktapus

BIN := bin/oktapus

default: build

# Go's build cache makes an unconditional build cheap, so this stays phony rather
# than tracking sources as prerequisites.
build:
	go build -o $(BIN) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

# Everything CI would check, in one target.
ci: fmt tidy vet test build

clean:
	rm -rf bin

.PHONY: default build test vet fmt tidy ci clean
