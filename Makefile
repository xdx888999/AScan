.PHONY: build test vet fmt check

build:
	go build -o bin/ascan ./cmd/ascan

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

check:
	go test ./...
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
